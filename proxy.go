package main

import (
	"errors"
	"hash/fnv"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
)

// challenge sends the RFC 6750 response that starts the whole dance. Without
// the resource_metadata pointer a client has no way to discover who issues
// tokens for this endpoint, so every unauthenticated path must go through here.
func (s *Server) challenge(w http.ResponseWriter, errCode, desc string) {
	v := `Bearer resource_metadata=` + strconv.Quote(s.cfg.PublicURL+"/.well-known/oauth-protected-resource")
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

// handleMCP authenticates the caller against a token we issued, swaps in the
// upstream credential we are holding for that session, and forwards.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	token := bearerFrom(r)
	if token == "" {
		s.challenge(w, "", "")
		return
	}

	sessionID, err := s.store.LookupAccessToken(r.Context(), token)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("mcp: token lookup failed", "err", err)
		}
		s.challenge(w, "invalid_token", "the access token is unknown or expired")
		return
	}

	upstreamTok, err := s.currentUpstreamToken(r, sessionID)
	if err != nil {
		slog.Error("mcp: could not resolve the upstream token", "err", err, "session", sessionID)
		s.challenge(w, "invalid_token", "the upstream credential for this session is no longer usable")
		return
	}

	r.Header.Set("Authorization", "Bearer "+upstreamTok.AccessToken)
	s.proxy.ServeHTTP(w, r)
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
	if err := s.persistToken(r.Context(), sessionID, "", refreshed, false); err != nil {
		return refreshed, err
	}
	slog.Info("refreshed the upstream token", "session", sessionID)
	return refreshed, nil
}
