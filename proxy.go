package main

import (
	"errors"
	"hash/fnv"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// challenge sends the RFC 6750 response that starts the whole dance. Without
// the resource_metadata pointer a client has no way to discover who issues
// tokens for this endpoint, so every unauthenticated path must go through here.
func (s *Server) challenge(w http.ResponseWriter, errCode, desc string) {
	s.challengeFor(w, s.cfg.Targets[0], errCode, desc)
}

// challengeFor points the client at the metadata for a specific target, which is
// what lets a caller holding a token for the wrong one recover on its own.
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

// newReverseProxy targets the upstream MCP server. Streamable HTTP keeps a
// long-lived response open, so buffering has to stay off.
func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{
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
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy to upstream failed", "err", err, "path", r.URL.Path)
			oauthError(w, http.StatusBadGateway, "server_error", "the MCP server could not be reached")
		},
	}
	return p
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

// prepareUpstreamHeaders drops the credential the caller sent us and, when
// static headers are configured, applies those in its place. It reports whether
// the upstream credential is now settled.
//
// The caller's token is dropped unconditionally, before any decision about what
// replaces it. Relying on the injection to overwrite it would leak that token
// upstream whenever the configured headers happen not to include Authorization.
func prepareUpstreamHeaders(r *http.Request, static map[string]string) bool {
	r.Header.Del("Authorization")
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
