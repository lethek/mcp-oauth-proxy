package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
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

// upstreamTransport is used for every target.
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
	slots := make(chan struct{}, n)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			h.ServeHTTP(w, r)
		default:
			slog.Warn("mcp: refused a request; the upstream already has the maximum in flight", "limit", n)
			w.Header().Set("Retry-After", "5")
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable",
				"too many requests are already in flight to this server; retry shortly")
		}
	})
}

// newReverseProxy targets the upstream MCP server. Streamable HTTP keeps a
// long-lived response open, so buffering has to stay off.
//
// enrolURL, when set, turns an upstream 401 into advice. In per_user mode a 401
// from the MCP server means the credential this user stored is no longer
// accepted — revoked at the far end, most likely — and passing that through
// unchanged would reach the client as an unexplained "unauthorized" about a
// credential the client has never seen and cannot fix.
//
// The concurrency bound is applied here rather than by the caller so that no
// construction site can forget it.
func newReverseProxy(target *url.URL, enrolURL string) http.Handler {
	p := &httputil.ReverseProxy{
		Transport: upstreamTransport,
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
	"Mcp-Protocol-Version": true,
	"Mcp-Session-Id":       true,
	"User-Agent":           true,
}

// prepareUpstreamHeaders reduces the request to what the upstream should see and
// then, when static headers are configured, applies those. It reports whether
// the upstream credential is now settled.
//
// Everything the caller sent that is not on the allowlist is dropped before any
// decision about what replaces it. Relying on the injection to overwrite the
// caller's Authorization would leak that token upstream whenever the configured
// headers happen not to include one.
func prepareUpstreamHeaders(r *http.Request, static map[string]string) bool {
	for name := range r.Header {
		if !upstreamAllowedHeaders[http.CanonicalHeaderKey(name)] {
			r.Header.Del(name)
		}
	}
	if len(static) == 0 {
		return false
	}
	for name, value := range static {
		r.Header.Set(name, value)
	}
	return true
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
func (s *Server) handleMCP(t Target) http.HandlerFunc {
	proxy := s.proxies[t.Name]

	return func(w http.ResponseWriter, r *http.Request) {
		// Before authentication, because a traversal is malformed whoever sent it
		// and there is no reason to spend a database lookup deciding that.
		if hasDotSegments(r.URL.Path) {
			slog.Warn("mcp: refused a path containing dot segments", "path", r.URL.Path, "target", t.Name)
			oauthError(w, http.StatusBadRequest, "invalid_request", "the request path may not contain dot segments")
			return
		}

		token := bearerFrom(r)
		if token == "" {
			s.challengeFor(w, t, "", "")
			return
		}

		sessionID, resource, err := s.store.LookupAccessToken(r.Context(), token)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				slog.Error("mcp: token lookup failed", "err", err)
			}
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
		if resource != t.Resource && (resource != "" || s.cfg.MultiTarget()) {
			slog.Warn("mcp: token presented at the wrong resource",
				"session", sessionID, "token_resource", resource, "target", t.Resource)
			s.challengeFor(w, t, "invalid_token", "this token was not issued for "+t.Resource)
			return
		}

		// In per_user mode the credential is the caller's own, found through the
		// subject behind this session. Not being enrolled answers 403 rather than a
		// 401 challenge: the caller authenticated correctly and re-authenticating
		// will not help, so a challenge would only put a well-behaved client into a
		// retry loop. The upstream is never contacted.
		if t.Mode == CredPerUser {
			headers, err := s.userHeadersFor(r, sessionID, t.Name)
			switch {
			case err == nil:
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
		}

		stripTargetPrefix(r, t)

		// In static mode the upstream authenticates with a fixed credential, so this
		// session's provider token is irrelevant. It is deliberately not loaded: it
		// may have expired with no refresh token available, and failing a request
		// over a credential we were never going to send would be wrong.
		if prepareUpstreamHeaders(r, t.StaticHeaders) {
			proxy.ServeHTTP(w, r)
			return
		}

		upstreamTok, err := s.currentUpstreamToken(r, sessionID)
		if err != nil {
			slog.Error("mcp: could not resolve the upstream token", "err", err, "session", sessionID)
			s.challengeFor(w, t, "invalid_token", "the upstream credential for this session is no longer usable")
			return
		}

		r.Header.Set("Authorization", "Bearer "+upstreamTok.AccessToken)
		proxy.ServeHTTP(w, r)
	}
}

// currentUpstreamToken returns a usable upstream token, refreshing it first if
// the provider gave us an expiry and we have passed it.
func (s *Server) currentUpstreamToken(r *http.Request, sessionID string) (UpstreamToken, error) {
	tok, err := s.loadToken(r.Context(), sessionID)
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
	fresh, err := s.loadToken(r.Context(), sessionID)
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
	// subject and resource are ignored on an update; both belong to the session
	// as created and a refresh must not be able to change either.
	if err := s.persistToken(r.Context(), sessionID, "", "", refreshed, false); err != nil {
		return refreshed, err
	}
	slog.Info("refreshed the upstream token", "session", sessionID)
	return refreshed, nil
}
