package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// twoTargets is the layout every test in this file uses: alpha and beta, each
// pointing at its own prefix on the shared test provider so a request that
// reaches the wrong one is visible.
func twoTargets(cfg *Config, upstreamURL string) []Target {
	return []Target{
		{
			Name:        "alpha",
			UpstreamMCP: upstreamURL + "/alpha-upstream",
			Mode:        CredProviderToken,
			Resource:    cfg.PublicURL + "/alpha/mcp",
		},
		{
			Name:        "beta",
			UpstreamMCP: upstreamURL + "/beta-upstream",
			Mode:        CredProviderToken,
			Resource:    cfg.PublicURL + "/beta/mcp",
		},
	}
}

func (h *harness) mcpRequest(path, token string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest("POST", h.proxy.URL+path, strings.NewReader("{}"))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// TestTokenIsBoundToItsTarget is the reason multi-target support has an audience
// check at all. Two targets behind one proxy are two separate permissions; a
// token minted for one must be inert at the other. Without this the change would
// convert deployment isolation into a bug, handing every user of one MCP server
// access to the other.
func TestTokenIsBoundToItsTarget(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	alphaResource := h.srv.cfg.Targets[0].Resource

	access, _ := h.tokensFor(clientID, redirect, alphaResource)

	// The token works where it was issued for.
	resp := h.mcpRequest("/alpha/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alpha with its own token: status %d, want 200", resp.StatusCode)
	}
	if got := h.alphaHits.Load(); got != 1 {
		t.Fatalf("alpha upstream hits = %d, want 1", got)
	}

	// The same token at the other target must not work.
	resp = h.mcpRequest("/beta/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("beta with alpha's token: status %d, want 401", resp.StatusCode)
	}

	// And it must not have reached beta's upstream on the way to being refused.
	if got := h.betaHits.Load(); got != 0 {
		t.Errorf("beta upstream was reached %d times with a token for alpha", got)
	}

	// The challenge has to name beta's own metadata, otherwise a client cannot
	// discover which resource it should have asked for.
	auth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(auth, "/.well-known/oauth-protected-resource/beta/mcp") {
		t.Errorf("WWW-Authenticate = %q, want beta's resource metadata", auth)
	}
}

// TestResourcelessTokenIsRefusedWithSeveralTargets covers the move from one
// target to several. A session written while the deployment had a single
// unnamed target carries an empty resource, and the audience check lets it through
// only while there is exactly one target to mean. Once there are several, such
// a token must fail at every named target, or a token minted for one of them
// would be honoured at all the others.
func TestResourcelessTokenIsRefusedWithSeveralTargets(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	// Written directly, as the single-target proxy would have: a valid sealed
	// upstream token and no resource. The multi-target flow cannot produce one.
	raw, err := json.Marshal(UpstreamToken{AccessToken: "upstream-access", TokenType: "Bearer"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealer.seal(purposeUpstreamToken, raw)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := newSecret()
	if err := h.srv.store.CreateSession(t.Context(), sessionID, "user-42", "", sealed); err != nil {
		t.Fatal(err)
	}
	access := newSecret()
	if err := h.srv.store.CreateAccessToken(t.Context(), access, sessionID, clientID, time.Hour); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/alpha/mcp", "/beta/mcp"} {
		resp := h.mcpRequest(path, access)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s with a resource-less token: status %d, want 401", path, resp.StatusCode)
		}
	}
	if got := h.alphaHits.Load(); got != 0 {
		t.Errorf("alpha upstream was reached %d times with a resource-less token", got)
	}
	if got := h.betaHits.Load(); got != 0 {
		t.Errorf("beta upstream was reached %d times with a resource-less token", got)
	}
}

// TestTargetPrefixIsStrippedUpstream guards a mistake that would be invisible in
// a test using a bare upstream URL: ReverseProxy joins the upstream path with the
// incoming one, so /alpha/mcp would arrive as /alpha-upstream/alpha/mcp.
func TestTargetPrefixIsStrippedUpstream(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)

	resp := h.mcpRequest("/alpha/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	select {
	case got := <-h.upstreamPaths:
		if got != "/alpha-upstream/mcp" {
			t.Errorf("upstream saw %q, want /alpha-upstream/mcp", got)
		}
	default:
		t.Fatal("the upstream recorded no request")
	}
}

// TestResourceRequiredWithSeveralTargets: with more than one target there is no
// sensible default, and guessing would mint a token for the wrong service.
func TestResourceRequiredWithSeveralTargets(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	resp := h.get(h.authorizeURL(clientID, redirect, s256(newSecret())))
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want a redirect carrying the error", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); !strings.Contains(got, "invalid_target") {
		t.Errorf("Location = %q, want invalid_target", got)
	}
}

func TestUnknownResourceIsRefused(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	resp := h.get(h.authorizeURLFor(clientID, redirect, s256(newSecret()), "https://elsewhere.example/mcp"))
	resp.Body.Close()
	if got := resp.Header.Get("Location"); !strings.Contains(got, "invalid_target") {
		t.Errorf("Location = %q, want invalid_target", got)
	}
}

// TestPerTargetMetadata: each target publishes its own RFC 9728 document, and
// the bare path refuses to name one of several arbitrarily.
func TestPerTargetMetadata(t *testing.T) {
	h := newHarnessWith(t, twoTargets)

	for _, tgt := range h.srv.cfg.Targets {
		resp := h.get(h.proxy.URL + tgt.MetadataPath())
		var doc struct {
			Resource string `json:"resource"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if doc.Resource != tgt.Resource {
			t.Errorf("%s: resource = %q, want %q", tgt.Name, doc.Resource, tgt.Resource)
		}
	}

	resp := h.get(h.proxy.URL + "/.well-known/oauth-protected-resource")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("bare metadata path: status %d, want 404 when several resources are served", resp.StatusCode)
	}
}

// TestSingleTargetKeepsItsPaths: an existing deployment must not have to change
// anything. The unnamed target stays at /mcp with the bare metadata document,
// and resource stays optional.
func TestSingleTargetKeepsItsPaths(t *testing.T) {
	h := newHarness(t)

	resp := h.get(h.proxy.URL + "/.well-known/oauth-protected-resource")
	var doc struct {
		Resource string `json:"resource"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := h.proxy.URL + "/mcp"; doc.Resource != want {
		t.Errorf("resource = %q, want %q", doc.Resource, want)
	}

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokens(clientID, redirect) // no resource parameter

	r := h.mcpRequest("/mcp", access)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Errorf("/mcp with a resource-less token: status %d, want 200", r.StatusCode)
	}
}
