package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// perUserTargets makes alpha require a credential of the user's own and leaves
// beta forwarding the provider token, so one harness covers both modes.
func perUserTargets(cfg *Config, upstreamURL string) []Target {
	return []Target{
		{
			Name:        "alpha",
			DisplayName: "Alpha Service",
			UpstreamMCP: upstreamURL + "/alpha-upstream",
			Mode:        CredPerUser,
			UserFields: []UserHeaderField{
				{Header: "Authorization", Label: "Access token", Prefix: "Bearer "},
				{Header: "x-workspace-slug", Label: "Workspace"},
			},
			Resource: cfg.PublicURL + "/alpha/mcp",
		},
		{
			Name:        "beta",
			UpstreamMCP: upstreamURL + "/beta-upstream",
			Mode:        CredProviderToken,
			Resource:    cfg.PublicURL + "/beta/mcp",
		},
	}
}

// enrol stores a credential directly, standing in for the browser session that
// the settings page would establish. The page's own handlers are covered
// separately.
func (h *harness) enrol(subject, target string, headers map[string]string) {
	h.t.Helper()
	raw, err := json.Marshal(headers)
	if err != nil {
		h.t.Fatal(err)
	}
	sealed, err := h.srv.sealer.seal(raw)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.srv.store.PutUserCredential(h.t.Context(), subject, target, sealed); err != nil {
		h.t.Fatal(err)
	}
}

// TestPerUserCredentialIsInjected: the whole point. The caller's own stored
// credential reaches the upstream, and their proxy token does not.
func TestPerUserCredentialIsInjected(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

	// user-42 is the subject the test provider's userinfo returns.
	h.enrol("user-42 (alice)", "alpha", map[string]string{
		"Authorization":    "Bearer alices-own-token",
		"x-workspace-slug": "alices-workspace",
	})

	resp := h.mcpRequest("/alpha/mcp", access)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := h.alphaHits.Load(); got != 1 {
		t.Fatalf("alpha upstream hits = %d, want 1", got)
	}

	// Asserting the status alone would prove nothing: ignoring per_user mode and
	// forwarding the provider's token also answers 200. What matters is WHICH
	// credential arrived.
	var saw struct {
		Authorization string `json:"saw_authorization"`
		Workspace     string `json:"saw_workspace"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&saw); err != nil {
		t.Fatal(err)
	}
	if saw.Authorization != "Bearer alices-own-token" {
		t.Errorf("upstream saw Authorization %q, want the user's own credential", saw.Authorization)
	}
	if saw.Workspace != "alices-workspace" {
		t.Errorf("upstream saw x-workspace-slug %q", saw.Workspace)
	}
	if strings.Contains(saw.Authorization, "upstream-access-token") {
		t.Error("the provider's token reached the upstream instead of the user's credential")
	}
}

// TestUnenrolledUserIsRefusedWithoutReachingUpstream: a 403 naming the enrolment
// page, and no request to the MCP server. A 401 challenge here would send a
// well-behaved client round the OAuth loop, which would succeed and change
// nothing.
func TestUnenrolledUserIsRefusedWithoutReachingUpstream(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

	resp := h.mcpRequest("/alpha/mcp", access)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	if got := h.alphaHits.Load(); got != 0 {
		t.Errorf("upstream was reached %d times for an unenrolled user", got)
	}

	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Description, "/settings") {
		t.Errorf("error_description = %q, want it to name the settings page", body.Description)
	}
}

// TestOneUsersCredentialIsNotAnothers: credentials are keyed on the subject, so
// enrolling one user must not let a different one through.
func TestOneUsersCredentialIsNotAnothers(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

	// Somebody else is enrolled; the caller is not.
	h.enrol("someone-else", "alpha", map[string]string{"Authorization": "Bearer not-yours"})

	resp := h.mcpRequest("/alpha/mcp", access)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	if got := h.alphaHits.Load(); got != 0 {
		t.Errorf("upstream reached %d times using another user's credential", got)
	}
}

// TestCredentialIsScopedToItsTarget: enrolment for one target must not satisfy
// another, which is why the key is (subject, target) and not subject alone.
func TestCredentialIsScopedToItsTarget(t *testing.T) {
	h := newHarnessWith(t, func(cfg *Config, upstreamURL string) []Target {
		ts := perUserTargets(cfg, upstreamURL)
		ts[1].Mode = CredPerUser
		ts[1].UserFields = []UserHeaderField{{Header: "Authorization", Label: "Token"}}
		return ts
	})

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	betaResource := h.srv.cfg.Targets[1].Resource
	access, _ := h.tokensFor(clientID, redirect, betaResource)

	// Enrolled for alpha only, but calling beta.
	h.enrol("user-42 (alice)", "alpha", map[string]string{"Authorization": "Bearer alpha-only"})

	resp := h.mcpRequest("/beta/mcp", access)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	if got := h.betaHits.Load(); got != 0 {
		t.Errorf("beta upstream reached %d times with an alpha-only credential", got)
	}
}

// TestSettingsRequiresSignIn: the page sends an anonymous visitor to the
// provider rather than rendering anything.
func TestSettingsRequiresSignIn(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	resp := h.get(h.proxy.URL + "/settings")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want a redirect to the provider", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if want := h.provider.URL; !strings.HasPrefix(loc.String(), want) {
		t.Errorf("Location = %q, want it to start with %q", loc, want)
	}
	if got := loc.Query().Get("redirect_uri"); got != h.proxy.URL+"/settings/callback" {
		t.Errorf("redirect_uri = %q, want the settings callback", got)
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Error("the settings login must use PKCE")
	}
}

// TestSettingsRoundTrip walks the enrolment the way a browser does: sign in,
// submit the form, and then confirm the credential actually works on a
// subsequent MCP call.
func TestSettingsRoundTrip(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	// Sign in: the provider redirects straight back to the settings callback.
	start := h.get(h.proxy.URL + "/settings")
	start.Body.Close()
	toProvider := h.get(start.Header.Get("Location"))
	toProvider.Body.Close()
	back := h.get(toProvider.Header.Get("Location"))
	back.Body.Close()
	if back.StatusCode != http.StatusFound {
		t.Fatalf("settings callback: status %d, want a redirect", back.StatusCode)
	}

	page := h.get(h.proxy.URL + "/settings")
	defer page.Body.Close()
	if page.StatusCode != http.StatusOK {
		t.Fatalf("settings page: status %d, want 200", page.StatusCode)
	}

	// Only per_user targets are offered.
	body, err := io.ReadAll(page.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Alpha Service") {
		t.Error("the catalogue does not show the display name")
	}
	if strings.Contains(string(body), ">beta<") {
		t.Error("the catalogue lists beta, which is not a per_user target")
	}

	// Enrol through the form.
	save := h.postForm("/settings", url.Values{
		"target":                 {"alpha"},
		"action":                 {"save"},
		"field_Authorization":    {"pasted-token"},
		"field_x-workspace-slug": {"acme"},
	})
	save.Body.Close()
	if save.StatusCode != http.StatusFound {
		t.Fatalf("saving: status %d, want a redirect", save.StatusCode)
	}

	// And it works on a real call.
	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

	resp := h.mcpRequest("/alpha/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after enrolling: status %d, want 200", resp.StatusCode)
	}
}

// TestSettingsRejectsUnknownTarget: the target arrives in the form body, so it is
// matched against configuration rather than trusted.
func TestSettingsRejectsUnknownTarget(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	start := h.get(h.proxy.URL + "/settings")
	start.Body.Close()
	toProvider := h.get(start.Header.Get("Location"))
	toProvider.Body.Close()
	h.get(toProvider.Header.Get("Location")).Body.Close()

	for _, target := range []string{"nonexistent", "beta"} {
		resp := h.postForm("/settings", url.Values{
			"target":              {target},
			"action":              {"save"},
			"field_Authorization": {"x"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("target %q: status %d, want 400", target, resp.StatusCode)
		}
	}
}
