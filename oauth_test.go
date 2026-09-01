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
	"slices"
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

	// Two further MCP endpoints, mounted under distinct prefixes, so a
	// multi-target test can tell which upstream a request actually reached and
	// assert that the other was never touched. upstreamPaths records the path
	// each one saw, which is how the prefix stripping is checked.
	alphaHits, betaHits atomic.Int64
	upstreamPaths       chan string

	// refuseAlpha makes the alpha upstream answer 401 the way a server does when
	// the credential it was given has been revoked: chunked, with its own
	// challenge header.
	refuseAlpha atomic.Bool

	// encodedRefusal makes that 401 carry a Content-Encoding, as a server behind
	// a compressing layer would. Brotli rather than gzip on purpose: Go's
	// transport negotiates and unwraps gzip by itself, so a gzip response never
	// reaches ModifyResponse still encoded and could not show whether the
	// rewrite clears the header.
	encodedRefusal atomic.Bool
}

// targetBuilder lets a test choose the target layout. It runs once PUBLIC_URL is
// known, because a target's resource is derived from it.
type targetBuilder func(cfg *Config, upstreamURL string) []Target

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

func newHarnessWith(t *testing.T, build targetBuilder) *harness {
	t.Helper()

	// The default is the original single unnamed target, so every test that does
	// not care keeps exercising that path.
	if build == nil {
		build = func(cfg *Config, upstreamURL string) []Target {
			return []Target{{
				UpstreamMCP: upstreamURL,
				Mode:        CredProviderToken,
				Resource:    cfg.PublicURL + "/mcp",
			}}
		}
	}

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

	// Distinct upstreams for the multi-target tests. Each records the path it was
	// given, which is what proves the "/<target>" segment was stripped before
	// forwarding rather than passed through to a server that knows nothing of it.
	h.upstreamPaths = make(chan string, 16)
	//
	// They echo the credential they were given, which is what lets a per-user
	// test assert that the CALLER'S OWN credential arrived rather than the
	// provider's token. Without that a per_user test passes just as happily when
	// the mode is ignored and the provider token is forwarded instead.
	echo := func(target string, hits *atomic.Int64) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			h.upstreamPaths <- r.URL.Path
			if target == "alpha" && h.refuseAlpha.Load() {
				// No Content-Length set, so Go serves this chunked, which is what
				// the rewrite has to survive.
				w.Header().Set("WWW-Authenticate", `Bearer realm="upstream"`)
				payload := []byte(`{"error":"unauthorized","detail":"token revoked upstream"}`)
				if h.encodedRefusal.Load() {
					w.Header().Set("Content-Encoding", "br")
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write(payload)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"target":             target,
				"saw_authorization":  r.Header.Get("Authorization"),
				"saw_workspace":      r.Header.Get("x-workspace-slug"),
				"saw_smuggled":       r.Header.Get("X-Api-Key"),
				"saw_forwarded_user": r.Header.Get("X-Forwarded-User"),
			})
		}
	}
	providerMux.HandleFunc("/alpha-upstream/", echo("alpha", &h.alphaHits))
	providerMux.HandleFunc("/beta-upstream/", echo("beta", &h.betaHits))

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

	// Unstarted, because the routes depend on configuration that depends on this
	// server's own address. A target's resource is derived from PUBLIC_URL and
	// captured by the handlers, so it has to be settled before routes() runs.
	// The listener has an address before the server accepts anything, which is
	// what breaks the circle.
	h.proxy = httptest.NewUnstartedServer(nil)
	t.Cleanup(h.proxy.Close)

	// Deriving the public scheme and origin through the same path LoadConfig uses
	// keeps the harness honest: if that derivation breaks, these tests break too.
	cfg.PublicURL = "http://" + h.proxy.Listener.Addr().String()
	if err := cfg.derivePublic(); err != nil {
		t.Fatal(err)
	}
	cfg.UpstreamIssuer = h.provider.URL
	cfg.UpstreamMCP = h.provider.URL
	cfg.Targets = build(cfg, h.provider.URL)
	s.upstream = NewUpstream(cfg)

	s.proxies = map[string]http.Handler{}
	for _, tgt := range cfg.Targets {
		u, parseErr := url.Parse(tgt.UpstreamMCP)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		enrolURL := ""
		if tgt.Mode == CredPerUser {
			enrolURL = cfg.PublicURL + "/settings"
		}
		s.proxies[tgt.Name] = newReverseProxy(u, enrolURL)
	}

	h.proxy.Config.Handler = s.routes()
	h.proxy.Start()
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
	return h.authorizeURLFor(clientID, redirectURI, challenge, "")
}

// authorizeURLFor adds the RFC 8707 resource parameter, which is optional with
// one target and required with several.
func (h *harness) authorizeURLFor(clientID, redirectURI, challenge, resource string) string {
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	if resource != "" {
		q.Set("resource", resource)
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
	return h.authorizeThroughConsentFor(clientID, redirect, verifier, "")
}

func (h *harness) authorizeThroughConsentFor(clientID, redirect, verifier, resource string) string {
	h.t.Helper()

	flowID := h.consentFlowID(h.get(h.authorizeURLFor(clientID, redirect, s256(verifier), resource)))

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
	return h.tokensFor(clientID, redirect, "")
}

func (h *harness) tokensFor(clientID, redirect, resource string) (access, refresh string) {
	h.t.Helper()

	verifier := newSecret()
	code := h.authorizeThroughConsentFor(clientID, redirect, verifier, resource)

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
	if err := h.srv.persistToken(ctx, sessionID, "subject", h.srv.cfg.Targets[0].Resource, expired, true); err != nil {
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

	cookieFor := func(publicURL string) *http.Cookie {
		h.srv.cfg.PublicURL = publicURL
		if err := h.srv.cfg.derivePublic(); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.srv.browserSecret(w, httptest.NewRequest(http.MethodGet, "/authorize", nil))
		got := w.Result().Cookies()
		if len(got) != 1 {
			t.Fatalf("browserSecret set %d cookies, want 1", len(got))
		}
		return got[0]
	}

	// Over https the __Host- prefix is what stops a sibling host under the same
	// registrable domain setting this cookie for the parent domain. A browser
	// refuses a __Host- cookie that is not Secure, is not Path=/, or carries a
	// Domain, so the name and the attributes have to agree.
	for _, publicURL := range []string{"https://example.com", "HTTPS://example.com", "Https://example.com:8443"} {
		c := cookieFor(publicURL)
		if !c.Secure {
			t.Errorf("PUBLIC_URL %q produced a binding cookie without Secure", publicURL)
		}
		if c.Name != "__Host-"+consentCookie {
			t.Errorf("PUBLIC_URL %q named the cookie %q, want the __Host- prefix", publicURL, c.Name)
		}
		if c.Path != "/" || c.Domain != "" {
			t.Errorf("PUBLIC_URL %q produced Path=%q Domain=%q, which a browser refuses under __Host-", publicURL, c.Path, c.Domain)
		}
	}

	// Loopback http is the one supported case where Secure would stop the cookie
	// being stored at all, and __Host- requires Secure, so the prefix is dropped
	// with it rather than producing a cookie the browser silently discards.
	c := cookieFor("http://127.0.0.1:8080")
	if c.Secure {
		t.Error("PUBLIC_URL http://127.0.0.1:8080 produced a Secure cookie, which the browser will not send back over http")
	}
	if c.Name != consentCookie {
		t.Errorf("over http the cookie is %q, want the unprefixed name", c.Name)
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

// TestConsentCSPAllowsTheProviderRedirect is the regression test for a consent
// page whose own Approve button did nothing.
//
// A browser applies form-action to every hop of the redirect chain a submission
// triggers, not just its immediate target. With only 'self' listed, the POST
// reached the server and approved the flow, but the redirect on to the provider
// was blocked, so the page sat there. Tapping again then reported the flow as
// already used. Verified in a real browser: Chrome logs "Sending form data to
// .../consent violates the following Content Security Policy directive:
// form-action 'self'. The request has been blocked."
func TestConsentCSPAllowsTheProviderRedirect(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)

	resp := h.get(h.authorizeURL(clientID, redirect, s256("v")))
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("the consent page carries no Content-Security-Policy")
	}

	// The provider is on a different origin from the proxy in every real
	// deployment, so naming only 'self' is what breaks the flow.
	if !strings.Contains(csp, h.provider.URL) {
		t.Errorf("form-action does not name the provider origin %q, so the browser will block the redirect after approval.\nCSP: %s",
			h.provider.URL, csp)
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("form-action no longer allows this origin, so the submission itself would be blocked.\nCSP: %s", csp)
	}
}

func TestFormActionOriginsPrefersTheDiscoveredEndpoint(t *testing.T) {
	h := newHarness(t)

	got := h.srv.upstream.FormActionOrigins(context.Background())
	if len(got) == 0 {
		t.Fatal("no origins returned, so form-action would name only 'self'")
	}
	if !slices.Contains(got, h.provider.URL) {
		t.Errorf("FormActionOrigins = %v, want it to include the provider origin %q", got, h.provider.URL)
	}

	// A provider that hosts its authorization endpoint on another host must have
	// that host named, not just its issuer.
	elsewhere := &Upstream{
		cfg: &Config{UpstreamIssuer: "https://issuer.example"},
		// fetchedAt is set because a cached document is only trusted for
		// discoveryTTL; a zero time reads as stale and would trigger a refetch.
		meta:      &upstreamMeta{AuthorizationEndpoint: "https://login.example/authorize"},
		fetchedAt: time.Now(),
	}
	origins := elsewhere.FormActionOrigins(context.Background())
	if !slices.Contains(origins, "https://login.example") {
		t.Errorf("FormActionOrigins = %v, want it to include the authorization endpoint's own origin", origins)
	}
}
