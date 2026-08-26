package main

import (
	"errors"
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
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy to upstream failed", "err", err, "path", r.URL.Path)
			oauthError(w, http.StatusBadGateway, "server_error", "the MCP server could not be reached")
		},
	}
	return p
}

// refreshMu serialises refreshes per session, so a burst of concurrent requests
// on an expired token produces one upstream refresh rather than a stampede that
// would invalidate its own rotated refresh token.
var refreshMu sync.Map

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

	gate, _ := refreshMu.LoadOrStore(sessionID, &sync.Mutex{})
	mu := gate.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Re-read under the lock: another request may have refreshed it while we
	// waited, in which case the token we loaded above is already stale.
	if fresh, err := s.loadToken(r.Context(), sessionID); err == nil && !fresh.expired() {
		return fresh, nil
	}

	refreshed, err := s.upstream.Refresh(r.Context(), tok.RefreshToken)
	if err != nil {
		return tok, err
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = tok.RefreshToken
	}
	if err := s.persistToken(r.Context(), sessionID, refreshed, false); err != nil {
		return refreshed, err
	}
	slog.Info("refreshed the upstream token", "session", sessionID)
	return refreshed, nil
}
