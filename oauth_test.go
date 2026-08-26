package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// harness wires a proxy against a stub OAuth provider, both on loopback.
type harness struct {
	t *testing.T

	proxy    *httptest.Server
	provider *httptest.Server

	// providerAuthorizeHits counts arrivals at the provider's authorization
	// endpoint. The consent gate is only real if this stays at zero until
	// someone has actually approved.
	providerAuthorizeHits atomic.Int64

	// client keeps cookies, so it models one browser across a whole flow.
	client *http.Client
	// otherBrowser keeps none, so it models anyone who was not shown the consent
	// page: a different browser, or a victim submitting from an attacker's site.
	otherBrowser *http.Client

	srv *Server

	// providerTokenHits counts upstream token-endpoint calls, so a test can
	// assert that a refresh did not happen.
	providerTokenHits atomic.Int64
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	store := newTestStore(t) // skips the test when there is no database
	h := &harness{t: t}

	// Never follow redirects: each hop is an assertion.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.client = &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	h.otherBrowser = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}

	cfg := &Config{
		UpstreamClientID:     "proxy-app",
		UpstreamClientSecret: "proxy-secret",
		UpstreamScopes:       "openid profile email",
		RefreshTokenTTL:      30 * 24 * time.Hour,
		SessionTTL:           90 * 24 * time.Hour,
	}

	providerMux := http.NewServeMux()
	h.provider = httptest.NewServer(providerMux)
	t.Cleanup(h.provider.Close)

	providerMux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 h.provider.URL,
			"authorization_endpoint": h.provider.URL + "/login/oauth/authorize",
			"token_endpoint":         h.provider.URL + "/login/oauth/access_token",
			"userinfo_endpoint":      h.provider.URL + "/login/oauth/userinfo",
		})
	})

	// The provider behaves as one that has already approved this application:
	// it redirects straight back without asking the user anything. That is
	// precisely the condition the confused-deputy attack relies on.
	providerMux.HandleFunc("GET /login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		h.providerAuthorizeHits.Add(1)
		back, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := back.Query()
		q.Set("code", "upstream-code")
		q.Set("state", r.URL.Query().Get("state"))
		q.Set("iss", h.provider.URL)
		back.RawQuery = q.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})

	providerMux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		h.providerTokenHits.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  "upstream-access-token",
			"refresh_token": "upstream-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	providerMux.HandleFunc("GET /login/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"sub": "user-42", "preferred_username": "alice"})
	})

	// The same test server doubles as the MCP endpoint, so a request that gets
	// past authentication has somewhere real to land. It echoes the credential
	// it was given and sets a cookie, both of which the proxy must handle.
	providerMux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "upstream_session", Value: "leaky"})
		writeJSON(w, http.StatusOK, map[string]any{
			"saw_authorization": r.Header.Get("Authorization"),
			"saw_cookie":        r.Header.Get("Cookie"),
		})
	})

	seal, sealErr := newSealer(bytes.Repeat([]byte{3}, 32))
	if sealErr != nil {
		t.Fatal(sealErr)
	}

	s := &Server{
		cfg: cfg, store: store, sealer: seal,
		registerLimit:   newLimiter(1000, time.Minute),
		flowLimit:       newLimiter(1000, time.Minute),
		credentialLimit: newLimiter(1000, time.Minute),
	}
	h.proxy = httptest.NewServer(s.routes())
	t.Cleanup(h.proxy.Close)

	// Both origins are known only once the servers are listening. Deriving the
	// public scheme and origin through the same path LoadConfig uses keeps the
	// harness honest: if that derivation breaks, these tests break too.
	cfg.PublicURL = h.proxy.URL
	if err := cfg.derivePublic(); err != nil {
		t.Fatal(err)
	}
	cfg.UpstreamIssuer = h.provider.URL
	cfg.UpstreamMCP = h.provider.URL
	s.upstream = NewUpstream(cfg)

	upstreamURL, parseErr := url.Parse(cfg.UpstreamMCP)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	s.proxy = newReverseProxy(upstreamURL)
	h.srv = s

	return h
}

// register performs dynamic client registration and returns the client id.
func (h *harness) register(redirectURI string) string {
	h.t.Helper()

	body, _ := json.Marshal(map[string]any{
		"client_name":   "Test Client",
		"redirect_uris": []string{redirectURI},
	})
	resp, err := h.client.Post(h.proxy.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("register: status %d", resp.StatusCode)
	}

	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	return out.ClientID
}

func (h *harness) authorizeURL(clientID, redirectURI, challenge string) string {
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	return h.proxy.URL + "/authorize?" + q.Encode()
}

func (h *harness) get(u string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(u)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) postForm(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.client.PostForm(h.proxy.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

var flowIDPattern = regexp.MustCompile(`name="flow_id" value="([^"]+)"`)

// consentFlowID reads the hidden field out of the rendered consent page. That
// value is the proof of consent, and it exists nowhere else.
func (h *harness) consentFlowID(resp *http.Response) string {
	h.t.Helper()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("expected the consent page, got status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		h.t.Fatalf("expected HTML, got Content-Type %q", ct)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		h.t.Fatal(err)
	}
	m := flowIDPattern.FindSubmatch(buf.Bytes())
	if m == nil {
		h.t.Fatalf("no flow_id in the consent page:\n%s", buf.String())
	}
	return string(m[1])
}

// TestAuthorizeDoesNotReachProviderWithoutConsent is the regression test for the
// confused-deputy hole. An attacker registers a client pointing at an address
// they control and gets a victim to open the resulting link. Previously that
// silently produced an authorization code on the attacker's redirect, because
// the provider had already approved this proxy's application and never
// mentioned the client. Now the request stops at a page the victim has to act
// on, and the provider is not contacted at all.
func TestAuthorizeDoesNotReachProviderWithoutConsent(t *testing.T) {
	h := newHarness(t)

	attackerRedirect := "http://127.0.0.1:9999/attacker"
	clientID := h.register(attackerRedirect)

	resp := h.get(h.authorizeURL(clientID, attackerRedirect, s256("attacker-verifier")))
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Fatalf("/authorize redirected to %q instead of asking the user", resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/authorize: status %d, want 200 with a consent page", resp.StatusCode)
	}
	if got := h.providerAuthorizeHits.Load(); got != 0 {
		t.Fatalf("the provider was contacted %d times before any consent", got)
	}
}

// TestConsentPageNamesTheClient checks the page carries what a person needs in
// order to answer, and escapes it. The name and address come from an anonymous
// registration.
func TestConsentPageNamesTheClient(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)

	resp := h.get(h.authorizeURL(clientID, redirect, s256("v")))
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	page := buf.String()

	for _, want := range []string{"Test Client", clientID, redirect} {
		if !strings.Contains(page, want) {
			t.Errorf("the consent page does not show %q", want)
		}
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("the consent page can be framed by the site that sent the user here")
	}
}

func TestConsentPageEscapesTheClientName(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	body, _ := json.Marshal(map[string]any{
		"client_name":   `<script>alert(1)</script>`,
		"redirect_uris": []string{redirect},
	})
	resp, err := h.client.Post(h.proxy.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()

	page := h.get(h.authorizeURL(reg.ClientID, redirect, s256("v")))
	defer page.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(page.Body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Error("the client name was rendered unescaped")
	}
}

// TestCallbackRejectsUnapprovedFlow closes the other half of the gate: even
// knowing a flow id, nothing can be redeemed until consent marks it approved.
func TestCallbackRejectsUnapprovedFlow(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	flowID := h.consentFlowID(h.get(h.authorizeURL(clientID, redirect, s256("v"))))

	resp := h.get(h.proxy.URL + "/callback?code=upstream-code&state=" + url.QueryEscape(flowID))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("/callback on an unapproved flow: status %d, want 400", resp.StatusCode)
	}
}

func TestConsentDenialReturnsAccessDenied(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	flowID := h.consentFlowID(h.get(h.authorizeURL(clientID, redirect, s256("v"))))

	resp := h.postForm("/consent", url.Values{"flow_id": {flowID}, "decision": {"deny"}})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("deny: status %d, want a redirect", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("deny: error = %q, want access_denied", got)
	}
	if h.providerAuthorizeHits.Load() != 0 {
		t.Error("the provider was contacted despite the user declining")
	}
}

func TestConsentRejectsAForgedFlowID(t *testing.T) {
	h := newHarness(t)

	resp := h.postForm("/consent", url.Values{"flow_id": {newSecret()}, "decision": {"approve"}})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("consent with an unknown flow id: status %d, want 400", resp.StatusCode)
	}
	if h.providerAuthorizeHits.Load() != 0 {
		t.Error("a forged consent POST reached the provider")
	}
}

// authorizeThroughConsent walks the full flow and returns the proxy's
// authorization code.
func (h *harness) authorizeThroughConsent(clientID, redirect, verifier string) string {
	h.t.Helper()

	flowID := h.consentFlowID(h.get(h.authorizeURL(clientID, redirect, s256(verifier))))

	consent := h.postForm("/consent", url.Values{"flow_id": {flowID}, "decision": {"approve"}})
	consent.Body.Close()
	if consent.StatusCode != http.StatusFound {
		h.t.Fatalf("consent: status %d, want a redirect to the provider", consent.StatusCode)
	}

	// The provider redirects straight back to /callback.
	toProvider := h.get(consent.Header.Get("Location"))
	toProvider.Body.Close()
	if toProvider.StatusCode != http.StatusFound {
		h.t.Fatalf("provider authorize: status %d", toProvider.StatusCode)
	}

	callback := h.get(toProvider.Header.Get("Location"))
	callback.Body.Close()
	if callback.StatusCode != http.StatusFound {
		h.t.Fatalf("callback: status %d, want a redirect to the client", callback.StatusCode)
	}

	back, err := url.Parse(callback.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	code := back.Query().Get("code")
	if code == "" {
		h.t.Fatalf("no code on the redirect back to the client: %s", back)
	}
	return code
}

// tokens walks the whole flow and redeems the code, returning the pair the
// client would actually hold. Four tests need a live token before they can test
// anything else; this keeps the shape of the token response in one place.
func (h *harness) tokens(clientID, redirect string) (access, refresh string) {
	h.t.Helper()

	verifier := newSecret()
	code := h.authorizeThroughConsent(clientID, redirect, verifier)

	resp := h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("/token: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken, tok.RefreshToken
}

func TestFullFlowIssuesTokensAfterConsent(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	verifier := newSecret()

	code := h.authorizeThroughConsent(clientID, redirect, verifier)

	resp := h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatal("/token returned an incomplete pair")
	}
	if tok.AccessToken == "upstream-access-token" {
		t.Fatal("the proxy handed the provider's own token to the client")
	}
}

func TestTokenRejectsWrongPKCEVerifier(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	code := h.authorizeThroughConsent(clientID, redirect, newSecret())

	resp := h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"code_verifier": {newSecret()},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token with the wrong verifier: status %d, want 400", resp.StatusCode)
	}
}

func TestRefreshReuseRevokesTheSession(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	_, refreshToken := h.tokens(clientID, redirect)

	// Rotate once, legitimately.
	rotated := h.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	if rotated.StatusCode != http.StatusOK {
		t.Fatalf("legitimate refresh: status %d", rotated.StatusCode)
	}
	var rotatedTok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(rotated.Body).Decode(&rotatedTok)
	rotated.Body.Close()

	// Now replay the token that was already spent.
	replay := h.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed refresh: status %d, want 400", replay.StatusCode)
	}

	// The whole session should be gone, including the access token that the
	// legitimate rotation had just produced.
	mcp, err := http.NewRequest(http.MethodPost, h.proxy.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	mcp.Header.Set("Authorization", "Bearer "+rotatedTok.AccessToken)
	resp, err := h.client.Do(mcp)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after reuse detection the session still works: status %d, want 401", resp.StatusCode)
	}
}

func TestRevokeEndsTheSession(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	accessToken, refreshToken := h.tokens(clientID, redirect)

	revoke := h.postForm("/revoke", url.Values{"token": {refreshToken}})
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("/revoke: status %d", revoke.StatusCode)
	}

	mcp, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/mcp", nil)
	mcp.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := h.client.Do(mcp)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the access token still works after revocation: status %d", resp.StatusCode)
	}

	// RFC 7009: an unknown token is still a 200, so this cannot be used to probe.
	unknown := h.postForm("/revoke", url.Values{"token": {newSecret()}})
	unknown.Body.Close()
	if unknown.StatusCode != http.StatusOK {
		t.Errorf("/revoke on an unknown token: status %d, want 200", unknown.StatusCode)
	}
}

func TestAuthorizeRejectsUnregisteredRedirectAndMissingPKCE(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)

	// A redirect the client never registered.
	resp := h.get(h.authorizeURL(clientID, "http://127.0.0.1:9999/elsewhere", s256("v")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unregistered redirect_uri: status %d, want 400", resp.StatusCode)
	}

	// No PKCE at all.
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"response_type": {"code"},
	}
	resp = h.get(h.proxy.URL + "/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("missing PKCE: status %d, want a redirect carrying the error", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("missing PKCE: error = %q", loc.Query().Get("error"))
	}
}

func TestAuthorizeRejectsForeignResource(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)

	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"code_challenge":        {s256("v")},
		"code_challenge_method": {"S256"},
		"resource":              {"https://somewhere.else/mcp"},
	}
	resp := h.get(h.proxy.URL + "/authorize?" + q.Encode())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("foreign resource: status %d, want a redirect carrying the error", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if got := loc.Query().Get("error"); got != "invalid_target" {
		t.Errorf("foreign resource: error = %q, want invalid_target", got)
	}
}

func TestRegisterRejectsDangerousRedirectURIs(t *testing.T) {
	h := newHarness(t)

	for _, bad := range []string{"javascript:alert(1)", "http://evil.example/cb", "https://ok.example/cb#frag"} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{bad}})
		resp, err := h.client.Post(h.proxy.URL+"/register", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("register with %q: status %d, want 400", bad, resp.StatusCode)
		}
	}
}

// TestMCPSwapsTheCredentialAndDropsCookies covers the pass-through: the client
// presents our token, the upstream sees the provider's, and no cookie crosses
// in either direction.
func TestMCPSwapsTheCredentialAndDropsCookies(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	accessToken, _ := h.tokens(clientID, redirect)

	req, err := http.NewRequest(http.MethodPost, h.proxy.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Cookie", "client_cookie=snoop")

	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/mcp with a valid token: status %d", resp.StatusCode)
	}

	var seen struct {
		Authorization string `json:"saw_authorization"`
		Cookie        string `json:"saw_cookie"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&seen); err != nil {
		t.Fatal(err)
	}
	if seen.Authorization != "Bearer upstream-access-token" {
		t.Errorf("upstream saw Authorization %q, want the provider's own token", seen.Authorization)
	}
	if strings.Contains(seen.Authorization, accessToken) {
		t.Error("the client's token was forwarded to the upstream")
	}
	if seen.Cookie != "" {
		t.Errorf("the client's cookie reached the upstream: %q", seen.Cookie)
	}
	if sc := resp.Header.Get("Set-Cookie"); sc != "" {
		t.Errorf("an upstream cookie reached the client: %q", sc)
	}
}

func TestMCPRequiresAToken(t *testing.T) {
	h := newHarness(t)

	resp := h.get(h.proxy.URL + "/mcp")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp without a token: status %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Errorf("WWW-Authenticate lacks the metadata pointer: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

// TestConsentCannotBeApprovedCrossOrigin is the regression test for the second
// shape of the confused-deputy attack, the one the flow id alone does not stop.
//
// The attacker does not send the victim a link. They open /authorize
// themselves, so they learn a valid flow id bound to their own client and
// redirect address, and then have the victim's browser submit that id to
// /consent from a page they control. A plain HTML form POST is not blocked by
// CORS, so without a browser binding the approval succeeds, the victim is sent
// to a provider that already trusts this proxy, and the code lands on the
// attacker's address.
//
// The victim's browser never visited /authorize, so it holds no binding cookie
// and does not send one. That is what must be refused.
func TestConsentCannotBeApprovedCrossOrigin(t *testing.T) {
	h := newHarness(t)

	attackerRedirect := "http://127.0.0.1:9999/attacker"
	clientID := h.register(attackerRedirect)

	// The attacker opens the consent page themselves and reads the flow id.
	flowID := h.consentFlowID(h.get(h.authorizeURL(clientID, attackerRedirect, s256("attacker-verifier"))))

	// The victim's browser submits it from the attacker's origin, carrying no
	// cookie for this proxy.
	req, err := http.NewRequest(http.MethodPost, h.proxy.URL+"/consent",
		strings.NewReader(url.Values{"flow_id": {flowID}, "decision": {"approve"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")

	resp, err := h.otherBrowser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Fatalf("a cross-origin consent POST was accepted and redirected to %q", resp.Header.Get("Location"))
	}
	if h.providerAuthorizeHits.Load() != 0 {
		t.Fatal("a cross-origin consent POST reached the provider")
	}
}

// TestConsentRequiresTheBrowserThatWasAsked covers the same gap without relying
// on the Origin header, which not every client sends.
func TestConsentRequiresTheBrowserThatWasAsked(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	flowID := h.consentFlowID(h.get(h.authorizeURL(clientID, redirect, s256("v"))))

	// No Origin header at all, and no cookie: a different browser entirely.
	resp, err := h.otherBrowser.PostForm(h.proxy.URL+"/consent",
		url.Values{"flow_id": {flowID}, "decision": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Fatalf("consent was accepted from a browser that never saw the page, redirecting to %q", resp.Header.Get("Location"))
	}
	if h.providerAuthorizeHits.Load() != 0 {
		t.Fatal("an unbound consent POST reached the provider")
	}
}

// TestRefreshAbortsWhenTheSessionIsRevokedWhileWaiting reproduces the race
// between revocation and an upstream refresh.
//
// A request can load an expired token, then block on the per-session refresh
// lock while another request revokes the session. When it finally gets the
// lock, the world has changed underneath it. Ignoring the error from the
// re-read under that lock meant carrying on with the stale credential,
// refreshing against the provider and forwarding the request, all after
// revocation was supposed to have ended the session.
func TestRefreshAbortsWhenTheSessionIsRevokedWhileWaiting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A session whose provider token has already expired, so the refresh path is
	// the one that runs.
	sessionID := newSecret()
	expired := UpstreamToken{
		AccessToken:  "stale-access-token",
		RefreshToken: "stale-refresh-token",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	if err := h.srv.persistToken(ctx, sessionID, "subject", expired, true); err != nil {
		t.Fatal(err)
	}

	// Hold the refresh lock so the request under test is forced to wait exactly
	// where the race happens.
	mu := refreshLock(sessionID)
	mu.Lock()

	type result struct {
		tok UpstreamToken
		err error
	}
	done := make(chan result, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		tok, err := h.srv.currentUpstreamToken(req, sessionID)
		done <- result{tok, err}
	}()

	// Give the goroutine time to load the expired token and block on the lock.
	// It cannot proceed past this point until the lock is released.
	time.Sleep(100 * time.Millisecond)

	// Revocation lands while the request is parked on the lock.
	if err := h.srv.store.RevokeSession(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	mu.Unlock()

	select {
	case got := <-done:
		if got.err == nil {
			t.Fatalf("refresh succeeded against a revoked session, returning token %q", got.tok.AccessToken)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("currentUpstreamToken did not return")
	}

	if n := h.providerTokenHits.Load(); n != 0 {
		t.Errorf("the provider token endpoint was called %d times for a revoked session", n)
	}
}

func TestConsentDenialAlsoRequiresTheBrowser(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	flowID := h.consentFlowID(h.get(h.authorizeURL(clientID, redirect, s256("v"))))

	// A browser that was never shown the page cannot cancel it either.
	resp, err := h.otherBrowser.PostForm(h.proxy.URL+"/consent",
		url.Values{"flow_id": {flowID}, "decision": {"deny"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatalf("an unbound browser cancelled the request, redirecting to %q", resp.Header.Get("Location"))
	}

	// The real browser still can, so the binding has not broken the feature.
	real := h.postForm("/consent", url.Values{"flow_id": {flowID}, "decision": {"deny"}})
	defer real.Body.Close()
	if real.StatusCode != http.StatusFound {
		t.Fatalf("the browser that was shown the page could not cancel: status %d", real.StatusCode)
	}
	loc, _ := url.Parse(real.Header.Get("Location"))
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("cancel: error = %q, want access_denied", got)
	}
}

// TestUnauthenticatedEndpointsAreRateLimited pins the limits to the routing
// table. They used to be a line inside each handler, which is how /consent and
// /revoke ended up without one; this fails if a route loses its wrapper.
func TestUnauthenticatedEndpointsAreRateLimited(t *testing.T) {
	h := newHarness(t)

	// Shrink every budget to one request, then confirm each endpoint is capped
	// by the limiter it is supposed to be capped by.
	h.srv.registerLimit = newLimiter(1, time.Minute)
	h.srv.flowLimit = newLimiter(1, time.Minute)
	h.srv.credentialLimit = newLimiter(1, time.Minute)
	limitedRoutes := httptest.NewServer(h.srv.routes())
	defer limitedRoutes.Close()

	post := func(path string) int {
		resp, err := h.otherBrowser.PostForm(limitedRoutes.URL+path, url.Values{})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(path string) int {
		resp, err := h.otherBrowser.Get(limitedRoutes.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Each of the three budgets is spent by one request, then every endpoint
	// drawing on it must refuse.
	post("/register")
	if got := post("/register"); got != http.StatusTooManyRequests {
		t.Errorf("second POST /register: status %d, want 429", got)
	}

	get("/authorize")
	if got := get("/authorize"); got != http.StatusTooManyRequests {
		t.Errorf("second GET /authorize: status %d, want 429", got)
	}

	// /consent, /callback, /token and /revoke share the credential backstop, so
	// one request exhausts it for all four.
	post("/consent")
	if got := get("/callback"); got != http.StatusTooManyRequests {
		t.Errorf("GET /callback past the limit: status %d, want 429", got)
	}
	for _, path := range []string{"/consent", "/token", "/revoke"} {
		if got := post(path); got != http.StatusTooManyRequests {
			t.Errorf("POST %s past the limit: status %d, want 429", path, got)
		}
	}

	// Liveness must never be capped: it is what tells the orchestrator this
	// process is alive, and a flood is exactly when that matters.
	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("GET /healthz: status %d, want 200 regardless of load", got)
	}
}

// TestConsentAcceptsOriginWithoutDefaultPort covers a PUBLIC_URL that spells out
// the default port. A browser never includes one in the Origin header, so
// comparing raw hosts refused every consent submission from every user, while
// logging it as a cross-origin attack.
func TestConsentAcceptsOriginWithoutDefaultPort(t *testing.T) {
	h := newHarness(t)

	// Pretend this deployment is https://example.com:443. The browser will say
	// https://example.com.
	h.srv.cfg.PublicURL = "https://example.com:443"
	if err := h.srv.cfg.derivePublic(); err != nil {
		t.Fatal(err)
	}

	for _, origin := range []string{"https://example.com", "https://example.com:443", "https://EXAMPLE.com"} {
		r := httptest.NewRequest(http.MethodPost, "/consent", nil)
		r.Header.Set("Origin", origin)
		if !h.srv.sameOrigin(r) {
			t.Errorf("Origin %q was refused against PUBLIC_URL %q", origin, h.srv.cfg.PublicURL)
		}
	}

	// A genuinely foreign origin is still refused, including one that merely
	// starts with ours. "null" is deliberately absent: it is what a referrer
	// policy produces, not a sender, and TestSameOriginTreatsOpaqueOriginAsNoSignal
	// covers it.
	for _, origin := range []string{"https://evil.example", "http://example.com", "https://example.com.evil.test"} {
		r := httptest.NewRequest(http.MethodPost, "/consent", nil)
		r.Header.Set("Origin", origin)
		if h.srv.sameOrigin(r) {
			t.Errorf("Origin %q was accepted against PUBLIC_URL %q", origin, h.srv.cfg.PublicURL)
		}
	}
}

// TestBindingCookieIsSecureOverHTTPS pins the Secure attribute to the parsed
// scheme. It used to come from a case-sensitive prefix test on the raw
// PUBLIC_URL, so a mixed-case scheme validated as https but shipped the cookie
// that gates consent without Secure.
func TestBindingCookieIsSecureOverHTTPS(t *testing.T) {
	h := newHarness(t)

	secureFor := func(publicURL string) bool {
		h.srv.cfg.PublicURL = publicURL
		if err := h.srv.cfg.derivePublic(); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.srv.browserSecret(w, httptest.NewRequest(http.MethodGet, "/authorize", nil))
		for _, c := range w.Result().Cookies() {
			if c.Name == consentCookie {
				return c.Secure
			}
		}
		t.Fatalf("browserSecret set no %s cookie", consentCookie)
		return false
	}

	for _, publicURL := range []string{"https://example.com", "HTTPS://example.com", "Https://example.com:8443"} {
		if !secureFor(publicURL) {
			t.Errorf("PUBLIC_URL %q produced a binding cookie without Secure", publicURL)
		}
	}

	// Loopback http is the one supported case where Secure would stop the cookie
	// being stored at all.
	if secureFor("http://127.0.0.1:8080") {
		t.Error("PUBLIC_URL http://127.0.0.1:8080 produced a Secure cookie, which the browser will not send back over http")
	}
}

// TestConsentPageDoesNotSuppressItsOwnOrigin is the regression test for a page
// that refused its own submissions.
//
// Under a no-referrer policy the Fetch spec has the browser serialise the
// Origin header of a form submission as "null". renderConsent set exactly that
// policy, and sameOrigin refused "null" outright, so every consent submission
// from a real browser was rejected with 403 and no authorization could
// complete. Go's http.Client does not implement referrer policy, which is why
// the existing tests all passed.
func TestConsentPageDoesNotSuppressItsOwnOrigin(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)

	resp := h.get(h.authorizeURL(clientID, redirect, s256("v")))
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}

	// Both the header and the in-page meta drive the same policy, and either one
	// set to no-referrer reintroduces the bug.
	if got := resp.Header.Get("Referrer-Policy"); got == "no-referrer" {
		t.Errorf("Referrer-Policy is %q, which makes the browser send Origin: null on this page's own form", got)
	}
	if strings.Contains(buf.String(), `content="no-referrer"`) {
		t.Error(`the page carries <meta name="referrer" content="no-referrer">, which makes the browser send Origin: null on its own form`)
	}
}

func TestSameOriginTreatsOpaqueOriginAsNoSignal(t *testing.T) {
	h := newHarness(t)

	req := func(origin, fetchSite string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/consent", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		return r
	}

	// Opaque and absent origins carry no information, so they defer to the
	// browser binding rather than failing shut.
	for _, origin := range []string{"", "null"} {
		if !h.srv.sameOrigin(req(origin, "")) {
			t.Errorf("Origin %q was refused; it says nothing about the sender and the cookie is the real gate", origin)
		}
	}

	// A real foreign origin is still refused.
	if h.srv.sameOrigin(req("https://evil.example", "")) {
		t.Error("a foreign Origin was accepted")
	}

	// Sec-Fetch-Site is not affected by referrer policy, so it still catches a
	// cross-site post whose Origin has been suppressed.
	if h.srv.sameOrigin(req("null", "cross-site")) {
		t.Error("Sec-Fetch-Site: cross-site was accepted")
	}
	if h.srv.sameOrigin(req("", "same-site")) {
		t.Error("Sec-Fetch-Site: same-site was accepted; the consent form is always same-origin")
	}
	if !h.srv.sameOrigin(req(h.srv.cfg.PublicOrigin, "same-origin")) {
		t.Error("a genuine same-origin submission was refused")
	}
}
