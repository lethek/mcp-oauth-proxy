package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// testRegistry serves targets for tests that build a Server by hand.
func testRegistry(t *testing.T, targets ...Target) *registry {
	t.Helper()
	snap, err := newSnapshot(targets, "https://p.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	reg := &registry{}
	reg.Store(snap)
	return reg
}

// The routes for named targets are wildcards, so a name no target has reaches
// the handler. It has to answer 404 on every pattern rather than fall through
// to a default target.
func TestUnknownTargetAnswers404(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	for _, path := range []string{"/nope/mcp", "/nope/mcp/sub/path"} {
		resp := h.mcpRequest(path, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s: status %d, want 404", path, resp.StatusCode)
		}
	}

	resp := h.get(h.proxy.URL + "/.well-known/oauth-protected-resource/nope/mcp")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("metadata for an unknown target: status %d, want 404", resp.StatusCode)
	}

	resp = h.get(h.proxy.URL + "/.well-known/oauth-protected-resource/alpha/mcp")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("metadata for a known target: status %d, want 200", resp.StatusCode)
	}
}

// The traversal check runs before the target lookup, so the wildcard routes
// cannot be used to reach the upstream with an escaped path, whether or not the
// name in front exists.
func TestDotSegmentsRefusedUnderWildcardRoutes(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	for _, path := range []string{
		"/alpha/mcp/%2e%2e/%2e%2e/escaped",
		"/alpha/mcp/%2E%2E/escaped",
		"/alpha/mcp/%2e/escaped",
		"/nope/mcp/%2e%2e/escaped",
		"/%2e%2e/mcp",
	} {
		resp := h.mcpRequest(path, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s: status %d, want 400", path, resp.StatusCode)
		}
	}
	if got := h.alphaHits.Load(); got != 0 {
		t.Errorf("upstream reached %d times by a traversal", got)
	}
}

// A rebuild keeps the proxy of any target whose stamp is unchanged, so its
// in-flight limit and connection pool survive, and replaces the others.
func TestRebuildReusesProxyForUnchangedStamp(t *testing.T) {
	targets := []Target{
		{Name: "alpha", UpstreamMCP: "http://alpha.internal/mcp", Mode: CredProviderToken, Resource: "https://p.example/alpha/mcp"},
		{Name: "beta", UpstreamMCP: "http://beta.internal/mcp", Mode: CredProviderToken, Resource: "https://p.example/beta/mcp"},
	}
	first, err := newSnapshot(targets, "https://p.example", nil)
	if err != nil {
		t.Fatal(err)
	}

	next := append([]Target(nil), targets...)
	next[1].UpstreamMCP = "http://beta.internal/moved"
	// A field outside the stamp, which must not cost alpha its proxy.
	next[0].DisplayName = "Renamed"
	second, err := newSnapshot(next, "https://p.example", first)
	if err != nil {
		t.Fatal(err)
	}

	if second.byName["alpha"].Proxy != first.byName["alpha"].Proxy {
		t.Error("alpha's stamp is unchanged but its proxy was rebuilt")
	}
	if second.byName["alpha"].Target.DisplayName != "Renamed" {
		t.Error("the rebuilt entry did not take the new definition")
	}
	if second.byName["beta"].Proxy == first.byName["beta"].Proxy {
		t.Error("beta now points elsewhere but kept the old proxy")
	}
}

// A static target with no headers is a configuration fault. It must refuse
// rather than fall through to forwarding the provider token to a server that
// was never meant to receive it.
func TestStaticTargetWithNoHeadersFailsClosed(t *testing.T) {
	h := newHarnessWith(t, func(cfg *Config, upstreamURL string) []Target {
		ts := twoTargets(cfg, upstreamURL)
		ts[0].Mode = CredStatic
		return ts
	})

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

	resp := h.mcpRequest("/alpha/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
	if got := h.alphaHits.Load(); got != 0 {
		t.Errorf("upstream reached %d times; the provider token may have been forwarded", got)
	}
}

// /settings is always registered, and with nothing to enrol it says so instead
// of disappearing. An anonymous visitor sees that directly, with no provider
// redirect first.
func TestSettingsShowsEmptyStateWithoutPerUserTargets(t *testing.T) {
	h := newHarness(t)

	resp := h.get(h.proxy.URL + "/settings")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "No server on this proxy asks for a credential") {
		t.Error("the empty state is not shown")
	}
}

// Only provider_token may forward the provider's token. A target whose mode is
// empty or unknown must refuse rather than receive it.
func TestUnknownModeFailsClosed(t *testing.T) {
	for _, mode := range []CredentialMode{"", "bogus"} {
		h := newHarnessWith(t, func(cfg *Config, upstreamURL string) []Target {
			ts := twoTargets(cfg, upstreamURL)
			ts[0].Mode = mode
			return ts
		})

		const redirect = "https://client.example/callback"
		clientID := h.register(redirect)
		access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

		resp := h.mcpRequest("/alpha/mcp", access)
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("mode %q: status %d, want 500", mode, resp.StatusCode)
		}
		if got := h.alphaHits.Load(); got != 0 {
			t.Errorf("mode %q: upstream reached %d times", mode, got)
		}
	}
}

// A per_user target sends the caller's own credential and never the provider
// token the session holds.
func TestPerUserTargetNeverReceivesProviderToken(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)
	h.enrol("user-42", "alpha", map[string]string{"Authorization": "Bearer alices-token"})

	resp := h.mcpRequest("/alpha/mcp", access)
	defer resp.Body.Close()
	var body struct {
		SawAuthorization string `json:"saw_authorization"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.SawAuthorization != "Bearer alices-token" {
		t.Errorf("upstream saw Authorization %q, want the enrolled credential", body.SawAuthorization)
	}
}

func TestNewSnapshotRefusesNoTargets(t *testing.T) {
	if _, err := newSnapshot(nil, "https://p.example", nil); err == nil {
		t.Error("an empty target list was accepted")
	}
}
