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

// maxRedirectURIs caps a single registration. The body limit alone would allow
// tens of thousands of them in one client row.
const maxRedirectURIs = 16

// consentCookie carries the secret that ties a consent decision to the browser
// that was actually shown the question.
const consentCookie = "mcp_proxy_consent"

// browserSecret returns this browser's binding secret, minting one if it has
// none. The value is reused across concurrent authorizations so that opening
// two clients at once does not invalidate the first one's consent page.
//
// SameSite is the point of the whole thing: the browser will not attach this
// cookie to a POST initiated from anyone else's page, so a cross-site consent
// submission arrives with nothing to prove itself with.
//
// Lax rather than Strict, deliberately. Both refuse a cross-site POST, which is
// the attack, but Strict also withholds the cookie on the ordinary cross-site
// navigation that reaches /authorize. That would mint a fresh secret every time
// and overwrite the previous one, so a second client started mid-flow would
// silently invalidate the first client's consent page. Lax keeps the defence
// and lets the reuse above actually happen.
func (s *Server) browserSecret(w http.ResponseWriter, r *http.Request) string {
	secret := readBrowserSecret(r)
	if secret == "" {
		secret = newSecret()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     consentCookie,
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.PublicScheme == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(flowTTL.Seconds()),
	})
	return secret
}

// readBrowserSecret returns this browser's binding secret, or "" when it has
// none. It never mints one: the consent handler must not manufacture a
// valid-looking binding for a browser that was never shown the page.
func readBrowserSecret(r *http.Request) string {
	c, err := r.Cookie(consentCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// sameOrigin backs the cookie up for anything that does not honour SameSite.
//
// Two headers are consulted, because either can be absent. Sec-Fetch-Site is
// the more dependable: unlike Origin it is not affected by the page's referrer
// policy. Origin is checked whenever it names a real origin.
//
// Neither is required. A missing or opaque signal falls through to the browser
// binding in ApproveFlow, which is the actual gate. Refusing here on a missing
// header would lock out anyone whose browser or privacy extension suppresses
// it, and would buy nothing: a cross-site POST cannot carry the SameSite=Lax
// binding cookie in the first place, so it fails the check that matters.
func (s *Server) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}

	origin := r.Header.Get("Origin")
	// "null" is what a browser sends when a referrer policy withholds the
	// origin, so it says nothing about who sent this.
	if origin == "" || origin == "null" {
		return true
	}
	got, err := url.Parse(origin)
	if err != nil || got.Host == "" {
		return false
	}
	// Both sides are canonicalised, because a browser omits the default port and
	// a PUBLIC_URL may spell it out.
	return canonicalOrigin(got) == s.cfg.PublicOrigin
}

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
		"issuer":                                     s.cfg.PublicURL,
		"authorization_endpoint":                     s.cfg.PublicURL + "/authorize",
		"token_endpoint":                             s.cfg.PublicURL + "/token",
		"registration_endpoint":                      s.cfg.PublicURL + "/register",
		"revocation_endpoint":                        s.cfg.PublicURL + "/revoke",
		"response_types_supported":                   []string{"code"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      []string{"none"},
		"revocation_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                           []string{"mcp"},
		"resource_parameter_supported":               true,
	})
}

// ---------- dynamic client registration ----------

// handleRegister implements RFC 7591 loosely: we accept any client, record the
// redirect URIs it asks for, and hand back an identifier. Every client ends up
// sharing the one upstream application, so registration here is bookkeeping
// rather than provisioning.
//
// Because it is anonymous, nothing about a registration is trustworthy. The
// consent screen at /authorize is what stops a registration made by one party
// being used to collect another party's credentials.
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
	if len(req.RedirectURIs) > maxRedirectURIs {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "too many redirect_uris")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	// The name is shown on the consent screen, so keep it to something a person
	// can read rather than a wall of text chosen by the registrant.
	name := strings.TrimSpace(req.ClientName)
	if len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		name = "an unnamed application"
	}

	c := Client{ID: newSecret(), Name: name, RedirectURIs: req.RedirectURIs}
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

// handleAuthorize validates the request and then stops, showing the user who is
// asking. It does not contact the provider.
//
// Stopping here is the whole point. Registration is anonymous, so anyone can
// obtain a client_id pointing at a redirect URI they control. If this endpoint
// forwarded straight to the provider, a crafted link would send a victim
// through a provider that has already approved this proxy's application, and
// the resulting code would land on the attacker's redirect. The provider's
// consent, where it appears at all, names this proxy and says nothing about the
// client. Only the proxy can ask the question that matters.
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
	if redirectURI == "" || !slices.Contains(client.RedirectURIs, redirectURI) {
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
	// RFC 8707. We serve exactly one resource, so a request naming a different
	// one is either confused or trying to have us mint a token for somewhere
	// else. Absent is still allowed, for clients predating the requirement.
	if res := q.Get("resource"); res != "" && strings.TrimRight(res, "/") != s.cfg.ResourceURI() {
		s.redirectErr(w, r, redirectURI, q.Get("state"), "invalid_target", "this proxy only issues tokens for "+s.cfg.ResourceURI())
		return
	}

	flow := Flow{
		ID:               newSecret(),
		ClientID:         clientID,
		RedirectURI:      redirectURI,
		ClientState:      q.Get("state"),
		CodeChallenge:    challenge,
		UpstreamVerifier: newSecret(),
		BrowserSecret:    s.browserSecret(w, r),
	}
	if err := s.store.CreateFlow(r.Context(), flow); err != nil {
		slog.Error("authorize: could not store flow", "err", err)
		s.redirectErr(w, r, redirectURI, flow.ClientState, "server_error", "could not start the authorization")
		return
	}

	renderConsent(w, consentView{
		ClientName:  client.Name,
		ClientID:    client.ID,
		RedirectURI: redirectURI,
		FlowID:      flow.ID,
		ConsentPath: "/consent",
	})
}

// handleConsent receives the user's decision.
//
// The flow id in the form is NOT the CSRF defence, and reading it as one is how
// this was got wrong the first time. Anyone may call /authorize and read a
// valid flow id straight out of the page they get back, then have a victim's
// browser submit it from a page they control; a plain HTML form POST is not
// blocked by CORS. What binds the decision is the browser secret, checked
// inside ApproveFlow, plus the Origin check above. Do not remove either on the
// grounds that the flow id already proves something.
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		slog.Warn("consent: cross-origin submission refused", "origin", r.Header.Get("Origin"))
		http.Error(w, "This request did not come from the authorization page.", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Malformed form submission.", http.StatusBadRequest)
		return
	}
	flowID := r.PostForm.Get("flow_id")

	binding := readBrowserSecret(r)

	if r.PostForm.Get("decision") != "approve" {
		// Cancelling is bound the same way as approving. Nothing is granted here,
		// so the stakes are lower, but a flow id is not proof of anything on this
		// path either and there is no reason to have two different rules.
		flow, err := s.store.TakeFlow(r.Context(), flowID, binding)
		if err != nil {
			http.Error(w, "This authorization request has expired. Start again from your client.", http.StatusBadRequest)
			return
		}
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "access_denied", "the user declined the request")
		return
	}

	// ApproveFlow refuses unless this browser is the one that was shown the
	// page. Knowing the flow id is not enough: an attacker can call /authorize
	// themselves and read one straight out of the response.
	flow, err := s.store.ApproveFlow(r.Context(), flowID, binding)
	if err != nil {
		slog.Warn("consent: approval refused", "flow_bound", binding != "")
		http.Error(w, "This authorization request has expired, was already used, or was not the one shown in this browser. Start again from your client.", http.StatusBadRequest)
		return
	}

	dest, err := s.upstream.AuthorizeURL(r.Context(), flow.ID, flow.UpstreamVerifier)
	if err != nil {
		slog.Error("consent: upstream discovery failed", "err", err)
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "temporarily_unavailable", "the upstream provider could not be reached")
		return
	}
	slog.Info("consent granted", "client_id", flow.ClientID)
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleCallback receives the upstream redirect, trades the code for a real
// token, and then mints our own code for the waiting client.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Only an approved flow is redeemable, so this cannot be reached without
	// someone having seen and accepted the consent screen.
	flow, err := s.store.TakeApprovedFlow(r.Context(), q.Get("state"))
	if err != nil {
		// Without a flow we have no registered redirect_uri to send the user back
		// to, so this has to terminate here.
		http.Error(w, "This authorization request has expired or was already used. Start again from your client.", http.StatusBadRequest)
		return
	}

	// RFC 9207. If the provider tells us who answered, make sure it is the one
	// we asked.
	if iss := q.Get("iss"); iss != "" {
		if meta, err := s.upstream.Meta(r.Context()); err == nil && meta.Issuer != "" &&
			strings.TrimRight(iss, "/") != strings.TrimRight(meta.Issuer, "/") {
			slog.Warn("callback: issuer mismatch", "got", iss, "want", meta.Issuer)
			s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "invalid_request", "the response came from an unexpected issuer")
			return
		}
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

	// Who this session belongs to, for the audit trail. A provider that will not
	// say must not block the login.
	subject, err := s.upstream.Subject(r.Context(), tok.AccessToken)
	if err != nil {
		slog.Warn("callback: could not resolve the user", "err", err)
	}

	sessionID := newSecret()
	if err := s.persistToken(r.Context(), sessionID, subject, tok, true); err != nil {
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
	}); err != nil {
		slog.Error("callback: could not store authorization code", "err", err)
		s.redirectErr(w, r, flow.RedirectURI, flow.ClientState, "server_error", "could not issue an authorization code")
		return
	}

	dest, err := url.Parse(flow.RedirectURI)
	if err != nil {
		slog.Error("callback: stored redirect_uri no longer parses", "err", err)
		http.Error(w, "The registered redirect address is unusable.", http.StatusBadRequest)
		return
	}
	rq := dest.Query()
	rq.Set("code", ourCode)
	if flow.ClientState != "" {
		rq.Set("state", flow.ClientState)
	}
	// RFC 9207: let the client confirm which authorization server answered.
	rq.Set("iss", s.cfg.PublicURL)
	dest.RawQuery = rq.Encode()

	slog.Info("authorized a client", "client_id", flow.ClientID, "subject", subject)
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
	if errors.Is(err, ErrTokenReused) {
		// Either the client replayed a token it should have discarded, or someone
		// else is holding a copy. We cannot tell which, and only one of those is
		// survivable, so the session goes.
		slog.Warn("refresh token reuse detected; revoking the session", "session", sessionID)
		if err := s.store.RevokeSession(r.Context(), sessionID); err != nil {
			slog.Error("could not revoke the reused session", "err", err, "session", sessionID)
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "this refresh token was already used; the session has been revoked")
		return
	}
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is unknown or expired")
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

// ---------- revocation ----------

// handleRevoke implements RFC 7009. Presenting either credential ends the whole
// session: the codes, both token families and the provider's own credential go
// with it. That is the logout the proxy previously had no way to perform.
//
// RFC 7009 requires 200 even for an unknown token, so a caller cannot use this
// endpoint to test whether a token exists.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "could not parse the form body")
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	sessionID, err := s.store.SessionForToken(r.Context(), token)
	if err == nil {
		if err := s.store.RevokeSession(r.Context(), sessionID); err != nil {
			slog.Error("revoke: could not delete the session", "err", err, "session", sessionID)
			oauthError(w, http.StatusInternalServerError, "server_error", "could not revoke the session")
			return
		}
		slog.Info("revoked a session", "session", sessionID)
	} else if !errors.Is(err, ErrNotFound) {
		slog.Error("revoke: lookup failed", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not revoke the session")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// ---------- shared helpers ----------

func (s *Server) persistToken(ctx context.Context, sessionID, subject string, tok UpstreamToken, create bool) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	sealed, err := s.sealer.seal(raw)
	if err != nil {
		return err
	}
	if create {
		return s.store.CreateSession(ctx, sessionID, subject, sealed)
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
