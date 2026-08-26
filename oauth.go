package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const accessTokenTTL = 12 * time.Hour

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// ---------- discovery ----------

// handleProtectedResourceMetadata implements RFC 9728. This is the document a
// client fetches first; it names us as our own authorization server, which is
// what lets us present dynamic registration over a provider that has none.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.cfg.ResourceURI(),
		"authorization_servers":    []string{s.cfg.PublicURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
	})
}

// handleAuthorizationServerMetadata implements RFC 8414. We advertise only what
// we actually accept: authorization code with S256, refresh, and public clients.
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.PublicURL,
		"authorization_endpoint":                s.cfg.PublicURL + "/authorize",
		"token_endpoint":                        s.cfg.PublicURL + "/token",
		"registration_endpoint":                 s.cfg.PublicURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

// ---------- dynamic client registration ----------

// handleRegister implements RFC 7591 loosely: we accept any client, record the
// redirect URIs it asks for, and hand back an identifier. Every client ends up
// sharing the one upstream application, so registration here is bookkeeping
// rather than provisioning.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body was not valid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if _, err := url.Parse(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "unparseable redirect_uri: "+u)
			return
		}
	}

	c := Client{ID: newSecret(), Name: req.ClientName, RedirectURIs: req.RedirectURIs}
	if err := s.store.CreateClient(r.Context(), c); err != nil {
		slog.Error("register: could not store client", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not store the registration")
		return
	}
	slog.Info("registered client", "client_id", c.ID, "name", c.Name)

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"client_name":                c.Name,
	})
}

// ---------- authorization ----------

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")

	client, err := s.store.GetClient(r.Context(), clientID)
	if err != nil {
		// Nothing here is safe to redirect: an unknown client means we cannot
		// trust the redirect_uri either, so the error is rendered directly.
		oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri was not registered by this client")
		return
	}
	if q.Get("response_type") != "code" {
		s.redirectErr(w, r, redirectURI, q.Get("state"), "unsupported_response_type", "only the code flow is supported")
		return
	}
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		s.redirectErr(w, r, redirectURI, q.Get("state"), "invalid_request", "PKCE with S256 is required")
		return
	}

	flow := Flow{
		ID:               newSecret(),
		ClientID:         clientID,
		RedirectURI:      redirectURI,
		ClientState:      q.Get("state"),
		CodeChallenge:    challenge,
		UpstreamVerifier: newSecret(),
		Resource:         q.Get("resource"),
	}
	if err := s.store.CreateFlow(r.Context(), flow); err != nil {
		slog.Error("authorize: could not store flow", "err", err)
		s.redirectErr(w, r, redirectURI, flow.ClientState, "server_error", "could not start the authorization")
		return
	}

	dest, err := s.upstream.AuthorizeURL(r.Context(), flow.ID, flow.UpstreamVerifier)
	if err != nil {
		slog.Error("authorize: upstream discovery failed", "err", err)
		s.redirectErr(w, r, redirectURI, flow.ClientState, "temporarily_unavailable", "the upstream provider could not be reached")
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleCallback receives the upstream redirect, trades the code for a real
// token, and then mints our own code for the waiting client.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	flow, err := s.store.TakeFlow(r.Context(), q.Get("state"))
	if err != nil {
		// Without a flow we have no registered redirect_uri to send the user back
		// to, so this has to terminate here.
		http.Error(w, "This authorization request has expired or was already used. Start again from your client.", http.StatusBadRequest)
		return
	}

	if e := q.Get("error"); e != "" {
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, e, q.Get("error_description"))
		return
	}
	code := q.Get("code")
	if code == "" {
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "invalid_request", "the provider returned no authorization code")
		return
	}

	tok, err := s.upstream.Exchange(r.Context(), code, flow.UpstreamVerifier)
	if err != nil {
		slog.Error("callback: upstream exchange failed", "err", err)
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "invalid_grant", "the provider rejected the authorization code")
		return
	}

	sessionID := newSecret()
	if err := s.persistToken(r.Context(), sessionID, tok, true); err != nil {
		slog.Error("callback: could not store session", "err", err)
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "server_error", "could not store the session")
		return
	}

	ourCode := newSecret()
	if err := s.store.CreateAuthCode(r.Context(), ourCode, AuthCode{
		SessionID:     sessionID,
		ClientID:      flow.ClientID,
		RedirectURI:   flow.RedirectURI,
		CodeChallenge: flow.CodeChallenge,
		Resource:      flow.Resource,
	}); err != nil {
		slog.Error("callback: could not store authorization code", "err", err)
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "server_error", "could not issue an authorization code")
		return
	}

	dest, _ := url.Parse(flow.RedirectURI)
	rq := dest.Query()
	rq.Set("code", ourCode)
	if flow.ClientState != "" {
		rq.Set("state", flow.ClientState)
	}
	// RFC 9207: let the client confirm which authorization server answered.
	rq.Set("iss", s.cfg.PublicURL)
	dest.RawQuery = rq.Encode()

	slog.Info("authorized a client", "client_id", flow.ClientID, "session", sessionID)
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		oauthError(w, http.StatusBadRequest, code, desc)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.cfg.PublicURL)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---------- token ----------

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "could not parse the form body")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r)
	case "refresh_token":
		s.tokenFromRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
	}
}

func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	rec, err := s.store.TakeAuthCode(r.Context(), f.Get("code"))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is unknown, expired or already used")
		return
	}
	if rec.ClientID != f.Get("client_id") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "this code was issued to a different client")
		return
	}
	if rec.RedirectURI != f.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if verifier := f.Get("code_verifier"); verifier == "" || s256(verifier) != rec.CodeChallenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	s.issue(w, r, rec.SessionID, rec.ClientID)
}

func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	sessionID, clientID, err := s.store.TakeRefreshToken(r.Context(), r.PostForm.Get("refresh_token"))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is unknown or already used")
		return
	}
	if given := r.PostForm.Get("client_id"); given != "" && given != clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "this refresh token was issued to a different client")
		return
	}
	s.issue(w, r, sessionID, clientID)
}

// issue mints the pair of credentials the client will actually use. These are
// ours, not the provider's — the upstream token never leaves this process.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, sessionID, clientID string) {
	access, refresh := newSecret(), newSecret()
	if err := s.store.CreateAccessToken(r.Context(), access, sessionID, clientID, accessTokenTTL); err != nil {
		slog.Error("token: could not store access token", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue an access token")
		return
	}
	if err := s.store.CreateRefreshToken(r.Context(), refresh, sessionID, clientID); err != nil {
		slog.Error("token: could not store refresh token", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue a refresh token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         "mcp",
	})
}

// ---------- shared helpers ----------

func (s *Server) persistToken(ctx context.Context, sessionID string, tok UpstreamToken, create bool) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	sealed, err := s.sealer.seal(raw)
	if err != nil {
		return err
	}
	if create {
		return s.store.CreateSession(ctx, sessionID, "", sealed)
	}
	return s.store.UpdateSessionToken(ctx, sessionID, sealed)
}

func (s *Server) loadToken(ctx context.Context, sessionID string) (UpstreamToken, error) {
	var tok UpstreamToken
	sealed, err := s.store.SessionToken(ctx, sessionID)
	if err != nil {
		return tok, err
	}
	raw, err := s.sealer.open(sealed)
	if err != nil {
		return tok, errors.New("stored token could not be decrypted; the encryption key may have changed")
	}
	err = json.Unmarshal(raw, &tok)
	return tok, err
}

func bearerFrom(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
