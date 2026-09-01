package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Client ID Metadata Documents, draft-ietf-oauth-client-id-metadata-document.
//
// The client_id is itself an https URL, and the document it points at describes
// the client. That replaces registration: a client with a domain needs no row in
// our clients table and no anonymous /register call.
//
// It is also a better answer than consent alone to the problem /authorize warns
// about at length. An anonymous registration proves nothing about who is asking,
// which is why the consent screen has to exist. A CIMD client_id is at least
// tied to a domain someone controls.

const (
	// cimdMaxBody is the size the draft recommends. A client metadata document
	// is small; anything larger is either broken or hostile.
	cimdMaxBody = 5 << 10

	cimdTimeout   = 5 * time.Second
	cimdCacheTTL  = 15 * time.Minute
	cimdCacheSize = 256

	// cimdFailureTTL remembers a failure briefly. The draft forbids caching an
	// error response as if it were a document; this caches only the refusal to
	// try again, which is what stops one caller turning repeated /authorize
	// calls into repeated outbound requests.
	cimdFailureTTL = 30 * time.Second
)

var errCIMDDisabled = errors.New("client id metadata documents are not enabled")

// NAT64 translation prefixes. An address inside one of these is an IPv4
// destination in disguise, so on a network with a NAT64 gateway it would reach
// exactly the private range the v4 checks exclude.
var (
	// NAT64 translation prefixes.
	_, nat64WellKnown, _ = net.ParseCIDR("64:ff9b::/96")
	_, nat64Local, _     = net.ParseCIDR("64:ff9b:1::/48")
	// 6to4, which carries the v4 address in the second and third groups.
	_, sixToFour, _ = net.ParseCIDR("2002::/16")
	// IPv4-compatible addresses, ::a.b.c.d. Deprecated but still routed by some
	// stacks, and net.IP.To4 does not report them.
	_, ipv4Compatible, _ = net.ParseCIDR("::/96")
)

// embeddedIPv4 extracts the IPv4 destination an IPv6 address stands for, or nil
// when it is an ordinary v6 address.
func embeddedIPv4(ip net.IP) net.IP {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return nil
	}
	switch {
	case nat64WellKnown.Contains(ip), nat64Local.Contains(ip):
		// The v4 address sits in the last four octets of the /96, and for the
		// /48 form in the same position this proxy cares about.
		return net.IPv4(v6[12], v6[13], v6[14], v6[15])
	case sixToFour.Contains(ip):
		return net.IPv4(v6[2], v6[3], v6[4], v6[5])
	case ipv4Compatible.Contains(ip):
		v4 := net.IPv4(v6[12], v6[13], v6[14], v6[15])
		// ::/96 also covers :: and ::1, which the earlier checks already handle.
		if v4.IsUnspecified() {
			return nil
		}
		return v4
	}
	return nil
}

// validateCIMDURL applies the draft's rules for a usable client_id URL.
func validateCIMDURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("must use https")
	}
	if u.Host == "" {
		return nil, errors.New("has no host")
	}
	if u.User != nil {
		return nil, errors.New("must not carry a username or password")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, errors.New("must not have a fragment")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errors.New("must contain a path")
	}
	// Dot segments would let two different client_id strings resolve to the same
	// document, so identity would stop being a simple string comparison.
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return nil, errors.New("must not contain dot path segments")
		}
	}
	return u, nil
}

// looksLikeCIMD is the cheap test used before deciding which lookup to attempt.
// Registered client ids from /register are base64url and never contain a colon.
func looksLikeCIMD(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// cimdClient fetches metadata documents. Its transport refuses to connect to
// anything that is not a public address, which is what keeps a caller-supplied
// URL from turning this into a probe of the private network behind us.
type cimdClient struct {
	http *http.Client

	mu    sync.Mutex
	cache map[string]cimdEntry
	// failures is separate so a flood of bad client_ids cannot evict documents.
	failures map[string]cimdEntry
}

type cimdEntry struct {
	client  Client
	err     error
	expires time.Time
}

func newCIMDClient() *cimdClient { return newCIMD(true) }

// newCIMD builds the fetcher. guardAddresses is false only in tests, where the
// document being fetched is necessarily on loopback. It is a separate
// constructor rather than a field so that nothing outside this file can reach
// the unguarded form, and so the guarded constructor is the one every caller
// sees.
func newCIMD(guardAddresses bool) *cimdClient {
	dialer := &net.Dialer{
		Timeout: cimdTimeout,
		// Control runs after DNS resolution with the address actually about to
		// be dialled, so a name that resolves to a private address is refused
		// even if it resolved to a public one a moment earlier. Checking the
		// hostname instead would be defeated by exactly that.
		Control: func(network, address string, _ syscall.RawConn) error {
			if !guardAddresses {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("cimd: could not parse the address %q", host)
			}
			if !isPublicIP(ip) {
				return fmt.Errorf("cimd: refusing to connect to the non-public address %s", ip)
			}
			return nil
		},
	}

	return &cimdClient{
		http: &http.Client{
			Timeout: cimdTimeout,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
				// Bounded, because the hosts here are chosen by callers and an
				// unbounded pool would keep a connection to each one alive.
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: cimdTimeout,
			},
			// A redirect could land anywhere, including somewhere the checks
			// above were meant to exclude, and the draft requires the document
			// to live at the client_id itself.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("cimd: the document must not redirect")
			},
		},
		cache:    map[string]cimdEntry{},
		failures: map[string]cimdEntry{},
	}
}

// isPublicIP excludes everything that could reach something we host.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10, carrier-grade NAT, which IsPrivate does not cover and
		// which is where a tailnet or similar overlay usually sits.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		// 0.0.0.0/8, "this network". Only 0.0.0.0 itself is IsUnspecified.
		if v4[0] == 0 {
			return false
		}
		return true
	}
	// Several IPv6 forms carry an IPv4 destination inside them, and net.IP only
	// recognises the ::ffff: mapping. Each is resolved to the address it
	// actually reaches and judged on that, rather than being waved through
	// because it does not look like the private ranges.
	if v4 := embeddedIPv4(ip); v4 != nil {
		return isPublicIP(v4)
	}
	return true
}

// Fetch resolves a client_id URL to the client it describes.
func (c *cimdClient) Fetch(ctx context.Context, clientID string) (Client, error) {
	if entry, ok := c.cached(clientID); ok {
		return entry.client, entry.err
	}

	u, err := validateCIMDURL(clientID)
	if err != nil {
		return c.fail(clientID, fmt.Errorf("client_id %q is not a usable metadata document URL: %w", clientID, err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return c.fail(clientID, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return c.fail(clientID, fmt.Errorf("could not fetch the metadata document: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.fail(clientID, fmt.Errorf("the metadata document answered %d", resp.StatusCode))
	}
	// Required, not merely checked when present: a host that returns no content
	// type at all should not slip through a check meant to confirm this is a
	// metadata document rather than someone else's web page.
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return c.fail(clientID, fmt.Errorf("the metadata document is %q, not JSON", ct))
	}

	// One byte over the limit is read deliberately, so a document that is exactly
	// at the cap is accepted and a larger one is detected rather than truncated
	// into something that happens to parse.
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBody+1))
	if err != nil {
		return c.fail(clientID, fmt.Errorf("could not read the metadata document: %w", err))
	}
	if len(body) > cimdMaxBody {
		return c.fail(clientID, fmt.Errorf("the metadata document is larger than %d bytes", cimdMaxBody))
	}

	client, err := parseCIMD(clientID, body)
	if err != nil {
		return c.fail(clientID, err)
	}

	c.store(clientID, client, nil)
	return client, nil
}

// parseCIMD validates the document against the draft's rules.
func parseCIMD(clientID string, body []byte) (Client, error) {
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`

		// Present only so their presence can be rejected. The draft forbids
		// shared symmetric secrets, and a document offering one is either
		// confused about the model or trying to have us treat a public client as
		// a confidential one.
		ClientSecret            string `json:"client_secret"`
		ClientSecretExpiresAt   any    `json:"client_secret_expires_at"`
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Client{}, fmt.Errorf("the metadata document is not valid JSON: %w", err)
	}

	// Simple string comparison, as the draft requires. Anything looser would let
	// one document claim to be a client hosted somewhere else.
	if doc.ClientID != clientID {
		return Client{}, fmt.Errorf("the metadata document claims client_id %q but was fetched from %q", doc.ClientID, clientID)
	}
	if doc.ClientSecret != "" || doc.ClientSecretExpiresAt != nil {
		return Client{}, errors.New("the metadata document carries a client secret, which is not allowed")
	}
	switch doc.TokenEndpointAuthMethod {
	case "", "none":
	default:
		return Client{}, fmt.Errorf("token_endpoint_auth_method %q is not supported; this proxy issues tokens to public clients only", doc.TokenEndpointAuthMethod)
	}

	if len(doc.RedirectURIs) == 0 {
		return Client{}, errors.New("the metadata document lists no redirect_uris")
	}
	if len(doc.RedirectURIs) > maxRedirectURIs {
		return Client{}, errors.New("the metadata document lists too many redirect_uris")
	}
	for _, u := range doc.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return Client{}, fmt.Errorf("redirect_uri %q is not usable: %w", u, err)
		}
	}

	name := strings.TrimSpace(doc.ClientName)
	if len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		name = clientID
	}

	return Client{ID: clientID, Name: name, RedirectURIs: doc.RedirectURIs}, nil
}

func (c *cimdClient) cached(clientID string) (cimdEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.cache[clientID]; ok && time.Now().Before(e.expires) {
		return e, true
	}
	if e, ok := c.failures[clientID]; ok && time.Now().Before(e.expires) {
		return e, true
	}
	return cimdEntry{}, false
}

// store bounds the cache by clearing it wholesale when it grows too large. A
// proper eviction policy would be more code than this is worth: entries are tiny
// and expire on their own, and the cap exists only so a stream of distinct URLs
// cannot grow it without limit.
func (c *cimdClient) store(clientID string, client Client, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Failures are held apart from documents. Sharing one map meant a caller
	// sending distinct bogus client_ids filled it and triggered the wholesale
	// clear, discarding every legitimate client's cached document; the negative
	// cache added to stop repeated outbound fetches became a way to force them.
	if err != nil {
		if len(c.failures) >= cimdCacheSize {
			c.failures = map[string]cimdEntry{}
		}
		c.failures[clientID] = cimdEntry{err: err, expires: time.Now().Add(cimdFailureTTL)}
		return
	}
	if len(c.cache) >= cimdCacheSize {
		c.cache = map[string]cimdEntry{}
	}
	c.cache[clientID] = cimdEntry{client: client, expires: time.Now().Add(cimdCacheTTL)}
}

// fail records a failure and returns it, so every error path memoises without
// each one having to remember to.
func (c *cimdClient) fail(clientID string, err error) (Client, error) {
	c.store(clientID, Client{}, err)
	return Client{}, err
}

// resolveClient finds the client behind a client_id, from a metadata document
// when it is a URL and this is enabled, and from our own registrations
// otherwise.
func (s *Server) resolveClient(ctx context.Context, clientID string) (Client, error) {
	if looksLikeCIMD(clientID) {
		if !s.cfg.CIMDEnabled {
			return Client{}, errCIMDDisabled
		}
		return s.cimd.Fetch(ctx, clientID)
	}
	return s.store.GetClient(ctx, clientID)
}
