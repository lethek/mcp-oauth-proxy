package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// challengeFor sends the RFC 6750 response that starts the whole dance. Without
// the resource_metadata pointer a client has no way to discover who issues
// tokens for this endpoint, so every unauthenticated path must go through here.
//
// It names a specific target's metadata, which is what lets a caller holding a
// token for the wrong one discover the right resource and recover on its own.
func (s *Server) challengeFor(w http.ResponseWriter, t Target, errCode, desc string) {
	v := `Bearer resource_metadata=` + strconv.Quote(s.cfg.PublicURL+t.MetadataPath())
	if errCode != "" {
		v += `, error=` + strconv.Quote(errCode)
		if desc != "" {
			v += `, error_description=` + strconv.Quote(desc)
		}
	}
	w.Header().Set("WWW-Authenticate", v)
	oauthError(w, http.StatusUnauthorized, orDefault(errCode, "unauthorized"), orDefault(desc, "an access token is required"))
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// upstreamTransport is used for config targets. Admin targets use a clone with
// the dial guard (see newAdminTransport).
//
// It bounds connection establishment — dial, TLS handshake, idle pooling —
// which http.DefaultTransport leaves partly open, without bounding the exchange
// itself.
//
// There is deliberately NO ResponseHeaderTimeout. A non-streaming MCP server
// writes response headers only when the tool call returns, so any such timeout
// is a ceiling on how long a tool may run: a 75-second call against a 60-second
// timeout becomes a 502 with the work discarded. An earlier version of this file
// set one and would have done exactly that.
//
// A hung upstream is instead released by the client going away, which
// ReverseProxy propagates through the request context.
var upstreamTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   8,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// newAdminTransport is upstreamTransport for an admin-supplied URL, with the
// destination policy enforced in the dialler. It sets no Proxy: with
// HTTPS_PROXY in effect the guard would see only the egress proxy, which would
// then resolve the real destination itself. A deployment that must use an
// egress proxy has to enforce the equivalent policy there.
//
// requireListed is for plain http, where the dialled address must be in nets
// even if it is public, so a name that later resolves elsewhere cannot carry
// the credential across the internet in cleartext.
func newAdminTransport(nets []netip.Prefix, requireListed bool) *http.Transport {
	t := upstreamTransport.Clone()
	t.Proxy = nil
	t.DialContext = (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialGuard(nets, requireListed),
	}).DialContext
	return t
}

// maxInFlightPerTarget bounds how many requests may be forwarded to one
// upstream at a time.
//
// There is no ResponseHeaderTimeout, so a request to an upstream that accepts
// the connection and never answers is held until the client disconnects.
// Nothing else bounds that: the rate limiter counts arrivals per minute, not
// concurrent work, so a caller who opens requests and keeps them open
// accumulates goroutines and upstream connections without limit. The cap sits
// far above real use; past it callers get a 503 they can retry rather than a
// proxy that has run out of sockets.
const maxInFlightPerTarget = 64

// boundConcurrency refuses a request rather than queueing it once n are already
// in flight. Queueing would convert exhaustion into unbounded latency for
// everyone, which is not an improvement on refusing the caller who caused it.
func boundConcurrency(h http.Handler, n int) http.Handler {
	return &boundHandler{next: h, limit: n, slots: make(chan struct{}, n)}
}

// boundHandler is a named pointer type, rather than a closure, so two proxies
// can be compared for identity when the registry reuses one.
type boundHandler struct {
	next  http.Handler
	limit int
	slots chan struct{}
}

func (b *boundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
		b.next.ServeHTTP(w, r)
	default:
		slog.Warn("mcp: refused a request; the upstream already has the maximum in flight", "limit", b.limit)
		w.Header().Set("Retry-After", "5")
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable",
			"too many requests are already in flight to this server; retry shortly")
	}
}

// newReverseProxyWith targets the upstream MCP server over rt, which is how an
// admin target gets its dial guard. Streamable HTTP keeps a long-lived response
// open, so buffering has to stay off.
//
// enrolURL, when set, turns an upstream 401 into advice. In per_user mode a 401
// from the MCP server means the credential this user stored is no longer
// accepted — revoked at the far end, most likely — and passing that through
// unchanged would reach the client as an unexplained "unauthorized" about a
// credential the client has never seen and cannot fix.
//
// The concurrency bound is applied here rather than by the caller so that no
// construction site can forget it.
func newReverseProxyWith(rt http.RoundTripper, target *url.URL, enrolURL string) http.Handler {
	p := &httputil.ReverseProxy{
		Transport: rt,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			// The upstream sees only our injected credential, never the client's.
			r.Out.Header.Del("Cookie")
		},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			// Every client shares this proxy's origin, so an upstream cookie would
			// be handed to whichever client happened to make the request and then
			// sent back on everyone else's. MCP over streamable HTTP has no use for
			// cookies, so they are dropped rather than scoped.
			resp.Header.Del("Set-Cookie")

			if enrolURL != "" && resp.StatusCode == http.StatusUnauthorized {
				return replaceWithEnrolAdvice(resp, enrolURL)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy to upstream failed", "err", err, "path", r.URL.Path)
			oauthError(w, http.StatusBadGateway, "server_error", "the MCP server could not be reached")
		},
	}
	return boundConcurrency(p, maxInFlightPerTarget)
}

// replaceWithEnrolAdvice rewrites an upstream 401 in place.
//
// The status becomes 403, matching the not-enrolled case: the caller's own
// authentication is fine, and the thing that is wrong is a credential only they
// can replace. A 401 here would invite the client to re-run OAuth, which would
// succeed and change nothing.
func replaceWithEnrolAdvice(resp *http.Response, enrolURL string) error {
	body, err := json.Marshal(map[string]string{
		"error": "access_denied",
		"error_description": "the MCP server rejected your stored credential; " +
			"replace it at " + enrolURL,
	})
	if err != nil {
		return err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.StatusCode = http.StatusForbidden
	resp.Status = http.StatusText(http.StatusForbidden)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	// The upstream's own challenge would point at a realm the client cannot use.
	resp.Header.Del("WWW-Authenticate")
	// The replacement body is plain JSON. Leaving the upstream's encoding behind
	// hands a client that asked for gzip an uncompressed body labelled gzip, and
	// it fails to decode exactly the advice this function exists to deliver.
	resp.Header.Del("Content-Encoding")
	resp.Uncompressed = true
	return nil
}

// errBehind means this replica's snapshot is older than the database's
// definition of a target.
var errBehind = errors.New("this replica has not seen the latest change to the target")

// refuseBehind answers a request this replica cannot judge yet, and starts the
// rebuild that will let it. The client keeps whatever it holds and retries.
func (s *Server) refuseBehind(w http.ResponseWriter) {
	s.reg.RequestRebuild()
	w.Header().Set("Retry-After", "2")
	oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable",
		"this server's targets are being updated; retry shortly")
}

// notEnrolled tells the caller what to do about it. An MCP client surfaces
// errors poorly, so the message has to carry the address of the page that fixes
// the problem rather than merely reporting that something is wrong.
func (s *Server) notEnrolled(w http.ResponseWriter, t Target) {
	oauthError(w, http.StatusForbidden, "access_denied",
		"no credential is stored for you for "+t.DisplayName+"; set one at "+s.cfg.PublicURL+"/settings")
}

// hasDotSegments reports whether a path contains "." or ".." segments.
//
// ServeMux normalises a literal "/../" and redirects, but it does NOT decode
// percent-encoding first, so "%2e%2e" reaches the handler intact and arrives at
// the upstream as "..". Whether that escapes the target's base path depends on
// the upstream's own normalisation, and the request carries an injected
// credential the caller never held, so it is refused here rather than forwarded
// and hoped about.
//
// r.URL.Path is already percent-decoded by net/http, so checking it catches both
// spellings at once.
func hasDotSegments(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// stripTargetPrefix removes the "/<target>" segment before the request is
// forwarded.
//
// ReverseProxy joins the upstream's path with the INCOMING path, so without this
// a request to /plane/mcp against an upstream of /http/api-key would be sent to
// /http/api-key/plane/mcp. The target name is how this proxy addresses its own
// routes and means nothing to the server behind it.
func stripTargetPrefix(r *http.Request, t Target) {
	if t.Name == "" {
		return
	}
	prefix := "/" + t.Name
	r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	if r.URL.RawPath != "" {
		r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, prefix)
	}
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
}

// upstreamAllowedHeaders is what a caller may send through to the MCP server.
//
// An allowlist rather than a denylist, because the interesting failure is a
// header nobody thought to remove. The credential injected here is often not the
// caller's own — an operator's static token, or another user's stored one — so
// any second authentication header the upstream happens to honour would let a
// caller override or sidestep it. Enumerating the two we knew about would only
// have covered the ones we knew about.
//
// The set is what MCP over streamable HTTP actually needs. Accept-Encoding is
// excluded on purpose: Go's transport negotiates its own and decompresses
// transparently, which keeps response rewriting honest.
var upstreamAllowedHeaders = map[string]bool{
	"Accept":               true,
	"Accept-Language":      true,
	"Content-Type":         true,
	"Content-Length":       true,
	"Last-Event-Id":        true,
	"Mcp-Method":           true,
	"Mcp-Name":             true,
	"Mcp-Protocol-Version": true,
	"Mcp-Session-Id":       true,
	"User-Agent":           true,
}

// prepareUpstreamHeaders reduces the request to what the upstream should see and
// then applies the given headers. Which credential applies is the caller's
// decision, made from the target's mode.
//
// Everything the caller sent that is not on the allowlist is dropped before any
// decision about what replaces it. Relying on the injection to overwrite the
// caller's Authorization would leak that token upstream whenever the configured
// headers happen not to include one.
func prepareUpstreamHeaders(r *http.Request, headers map[string]string) {
	for name := range r.Header {
		if !upstreamAllowedHeaders[http.CanonicalHeaderKey(name)] {
			r.Header.Del(name)
		}
	}
	for name, value := range headers {
		r.Header.Set(name, value)
	}
}

// refreshLocks serialises refreshes per session, so a burst of concurrent
// requests on an expired token produces one upstream refresh rather than a
// stampede that would invalidate its own rotated refresh token.
//
// The locks are striped over a fixed set rather than kept one per session in a
// map. A map would grow for the life of the process, and pruning it is not
// safe: removing a mutex that another goroutine is already blocked on lets the
// next caller create a second mutex for the same session and run concurrently,
// which is the exact stampede this exists to prevent. Two unrelated sessions
// occasionally sharing a stripe just makes one wait, which costs nothing here.
const refreshStripes = 256

var refreshLocks [refreshStripes]sync.Mutex

func refreshLock(sessionID string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sessionID))
	return &refreshLocks[h.Sum32()%refreshStripes]
}

// handleMCP authenticates the caller against a token we issued, checks that the
// token was issued for THIS target, swaps in the upstream credential, and
// forwards.
//
// The target is resolved per request from the snapshot, which is loaded once so
// the audience check, the stamp check and the credential all describe the same
// definition.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	// Before authentication, because a traversal is malformed whoever sent it
	// and there is no reason to spend a database lookup deciding that. It also
	// precedes the lookup, so a wildcard route cannot be steered by a name
	// containing dot segments.
	if hasDotSegments(r.URL.Path) {
		slog.Warn("mcp: refused a path containing dot segments", "path", r.URL.Path)
		oauthError(w, http.StatusBadRequest, "invalid_request", "the request path may not contain dot segments")
		return
	}

	// Empty in a single-target deployment, whose routes have no {target}.
	snap := s.reg.Load()
	e := snap.byName[r.PathValue("target")]
	if e == nil {
		http.NotFound(w, r)
		return
	}
	t, stamp, proxy := e.Target, e.Stamp, e.Proxy
	multi := snap.MultiTarget()

	token := bearerFrom(r)
	if token == "" {
		s.challengeFor(w, t, "", "")
		return
	}

	ref, err := s.store.LookupAccessToken(r.Context(), token)
	sessionID := ref.ID
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("mcp: token lookup failed", "err", err)
		}
		s.challengeFor(w, t, "invalid_token", "the access token is unknown or expired")
		return
	}

	// Freshness comes first. If this replica is behind about the target, every
	// other answer it could give, including "invalid token", is a statement about
	// a definition that may no longer exist. A session for another target is left
	// to the checks below, which refuse it.
	if s.reg.enabled() && ref.Target == t.Name && e.behind(ref.CurrentStamp) {
		s.refuseBehind(w)
		return
	}

	// The session's stamp comes second, as the spec orders it: a session issued
	// under another definition of this name is unknown, whatever resource it
	// names, and would otherwise reach whatever this one points at now.
	if ref.Stamp != stamp {
		slog.Warn("mcp: session was issued under a different definition of this target",
			"session", sessionID, "target", t.Name)
		s.challengeFor(w, t, "invalid_token", "the access token is unknown or expired")
		return
	}

	// The audience check. Without it a token minted for one target would work
	// against every other, which would turn separate upstreams into one
	// permission. A challenge naming THIS target's metadata is returned rather
	// than a flat refusal, so a client holding the wrong token can discover the
	// right resource and fetch a usable one by itself.
	//
	// An empty resource means a session from a single-target deployment that
	// never asked for one. That is only acceptable while there is exactly one
	// target to mean; with several it fails shut.
	if ref.Resource != t.Resource && (ref.Resource != "" || multi) {
		slog.Warn("mcp: token presented at the wrong resource",
			"session", sessionID, "token_resource", ref.Resource, "target", t.Resource)
		s.challengeFor(w, t, "invalid_token", "this token was not issued for "+t.Resource)
		return
	}

	switch t.Mode {
	case CredPerUser:
		// In per_user mode the credential is the caller's own, found through the
		// subject behind this session. Not being enrolled answers 403 rather than a
		// 401 challenge: the caller authenticated correctly and re-authenticating
		// will not help, so a challenge would only put a well-behaved client into a
		// retry loop. The upstream is never contacted.
		headers, err := s.userHeadersFor(r, sessionID, e)
		switch {
		case err == nil:
		case errors.Is(err, errBehind):
			s.refuseBehind(w)
			return
		case errors.Is(err, ErrNotFound):
			s.notEnrolled(w, t)
			return
		default:
			// A database outage, a rotated encryption key or a corrupt row is
			// not the user's problem to fix. Telling them to go and set a
			// credential sends them to do something that will not help and
			// hides a server fault behind a 403.
			slog.Error("mcp: could not read the stored credential",
				"err", err, "session", sessionID, "target", t.Name)
			oauthError(w, http.StatusInternalServerError, "server_error",
				"your stored credential could not be read")
			return
		}
		stripTargetPrefix(r, t)
		prepareUpstreamHeaders(r, headers)
		proxy.ServeHTTP(w, r)
		return

	case CredStatic:
		// The upstream authenticates with a fixed credential, so this session's
		// provider token is irrelevant. It is deliberately not loaded: it may have
		// expired with no refresh token available, and failing a request over a
		// credential we were never going to send would be wrong.
		//
		// A static target with nothing to send is a configuration fault. Falling
		// through to the provider token would hand it to a server that was never
		// meant to receive it, so this fails closed.
		if len(t.StaticHeaders) == 0 {
			slog.Error("mcp: static target has no headers to send", "target", t.Name)
			oauthError(w, http.StatusInternalServerError, "server_error", "this server is misconfigured")
			return
		}
		stripTargetPrefix(r, t)
		prepareUpstreamHeaders(r, t.StaticHeaders)
		proxy.ServeHTTP(w, r)
		return

	case CredProviderToken:
		stripTargetPrefix(r, t)
		prepareUpstreamHeaders(r, nil)

		upstreamTok, err := s.currentUpstreamToken(r, sessionID, stamp)
		if err != nil {
			// A session that is gone or whose target was replaced is expected, not a fault.
			level := slog.LevelError
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrStaleTarget) {
				level = slog.LevelWarn
			}
			slog.Log(r.Context(), level, "mcp: could not resolve the upstream token", "err", err, "session", sessionID)
			s.challengeFor(w, t, "invalid_token", "the upstream credential for this session is no longer usable")
			return
		}

		r.Header.Set("Authorization", "Bearer "+upstreamTok.AccessToken)
		proxy.ServeHTTP(w, r)

	default:
		// Only provider_token may forward the provider's token, so a mode this
		// code does not know fails closed rather than receiving it.
		slog.Error("mcp: target has an unknown credential mode", "target", t.Name, "mode", t.Mode)
		oauthError(w, http.StatusInternalServerError, "server_error", "this server is misconfigured")
	}
}

// currentUpstreamToken returns a usable upstream token, refreshing it first if
// the provider gave us an expiry and we have passed it.
func (s *Server) currentUpstreamToken(r *http.Request, sessionID, stamp string) (UpstreamToken, error) {
	tok, err := s.loadToken(r.Context(), sessionID, stamp)
	if err != nil {
		return tok, err
	}
	if !tok.expired() {
		return tok, nil
	}
	if tok.RefreshToken == "" {
		return tok, errors.New("upstream token expired and no refresh token was issued")
	}

	mu := refreshLock(sessionID)
	mu.Lock()
	defer mu.Unlock()

	// Re-read under the lock. Two things can have happened while we waited:
	// another request may have refreshed the token, or the session may have been
	// revoked out from under us. The error is not ignorable, because treating a
	// revoked session as "no fresher token available" would send us on to
	// refresh with a credential the session no longer has any claim to.
	fresh, err := s.loadToken(r.Context(), sessionID, stamp)
	if err != nil {
		return tok, err
	}
	if !fresh.expired() {
		return fresh, nil
	}
	if fresh.RefreshToken == "" {
		return fresh, errors.New("upstream token expired and no refresh token was issued")
	}

	refreshed, err := s.upstream.Refresh(r.Context(), fresh.RefreshToken)
	if err != nil {
		return tok, err
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = fresh.RefreshToken
	}
	if err := s.persistRefreshed(r.Context(), sessionID, stamp, refreshed); err != nil {
		// The rotated pair could not be recorded, so the session now holds a
		// refresh token the provider will not honour again and is finished.
		// Serving this request anyway would hide that until some later refresh
		// failed for a reason nobody could trace back to here.
		slog.Error("could not persist the refreshed upstream token; the session is now unusable",
			"err", err, "session", sessionID)
		return tok, err
	}
	slog.Info("refreshed the upstream token", "session", sessionID)
	return refreshed, nil
}

// persistRefreshed writes a rotated upstream token back to its session.
//
// The provider invalidates the old refresh token the moment it issues a new
// one, so what comes back from a refresh is the only copy of the pair. A write
// that fails here costs the user their session, and a store that fails one
// statement is often serving again a moment later, so a failure is retried
// briefly rather than taken as final.
//
// A revoked session is the exception. There is no row to write back to and
// nothing of the session may be served, so ErrNotFound returns immediately. So
// does ErrStaleTarget: the target was replaced mid-refresh, the session is no
// longer valid, and the write was refused.
func (s *Server) persistRefreshed(ctx context.Context, sessionID, stamp string, tok UpstreamToken) error {
	const attempts = 3
	var err error
	for i := range attempts {
		if i > 0 {
			select {
			case <-time.After(time.Duration(i) * 100 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err = s.updateSessionToken(ctx, sessionID, stamp, tok)
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrStaleTarget) {
			return err
		}
		slog.Warn("could not persist the refreshed upstream token; retrying",
			"err", err, "session", sessionID, "attempt", i+1)
	}
	return err
}
