package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// replica starts a second server over the same database, standing in for another
// pod. mutate changes its copy of the targets, as a different TARGETS would.
func (h *harness) replica(mutate func([]Target)) *httptest.Server {
	h.t.Helper()
	cfg := *h.srv.cfg
	cfg.Targets = append([]Target(nil), h.srv.cfg.Targets...)
	mutate(cfg.Targets)

	s := &Server{
		cfg: &cfg, store: h.srv.store, sealer: h.srv.sealer, upstream: h.srv.upstream,
		registerLimit:   newLimiter(1000, time.Minute),
		flowLimit:       newLimiter(1000, time.Minute),
		credentialLimit: newLimiter(1000, time.Minute),
		mcpLimit:        newLimiter(1000, time.Minute),
		reg:             &registry{},
	}
	snap, err := newSnapshot(cfg.Targets, cfg.PublicURL, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	s.reg.Store(snap)
	srv := httptest.NewServer(s.routes())
	h.t.Cleanup(srv.Close)
	return srv
}

// With the definition changed, a token issued under the old one is refused and
// nothing reaches the upstream, with no purge involved.
func TestSessionFromAnotherDefinitionIsRefused(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[1].Resource) // beta, provider_token

	other := h.replica(func(ts []Target) { ts[1].UpstreamMCP += "/elsewhere" })

	req, _ := http.NewRequest("POST", other.URL+"/beta/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for a session issued under another definition", resp.StatusCode)
	}
	if got := h.betaHits.Load(); got != 0 {
		t.Errorf("upstream was reached %d times", got)
	}

	// The same token still works on the replica that issued it.
	ok := h.mcpRequest("/beta/mcp", access)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Errorf("issuing replica: status %d, want 200", ok.StatusCode)
	}
}

// The provider_token case above is also refused by the sealed token failing to
// open under the new stamp. A per_user target never loads that token, so here
// the check in handleMCP is the only thing standing between a stale session and
// the upstream.
func TestPerUserSessionFromAnotherDefinitionIsRefused(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource) // alpha, per_user
	h.enrol("user-42", "alpha", map[string]string{
		"Authorization":    "Bearer alices-own-token",
		"x-workspace-slug": "alices-workspace",
	})

	other := h.replica(func(ts []Target) { ts[0].UpstreamMCP += "/elsewhere" })

	req, _ := http.NewRequest("POST", other.URL+"/alpha/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for a session issued under another definition", resp.StatusCode)
	}
	if got := h.alphaHits.Load(); got != 0 {
		t.Errorf("upstream was reached %d times", got)
	}

	ok := h.mcpRequest("/alpha/mcp", access)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Errorf("issuing replica: status %d, want 200", ok.StatusCode)
	}
}

// A flow whose definition changed between /authorize and /callback creates no
// session; the user is sent back with an error.
func TestCallbackRefusesAFlowWhoseStampMoved(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	flow := Flow{
		ID: newSecret(), ClientID: clientID, RedirectURI: redirect, CodeChallenge: "c",
		UpstreamVerifier: newSecret(), Resource: h.srv.cfg.Targets[1].Resource,
		Target: "beta", Stamp: "config:stale", BrowserSecret: "b",
	}
	ctx := t.Context()
	if err := h.srv.store.CreateFlow(ctx, flow); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.store.ApproveFlow(ctx, flow.ID, "b"); err != nil {
		t.Fatal(err)
	}
	resp := h.get(h.proxy.URL + "/callback?state=" + flow.ID + "&code=upstream-code&iss=" + url.QueryEscape(h.provider.URL))
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") == "" || loc.Query().Get("code") != "" {
		t.Errorf("redirect %q: want an error and no code", loc)
	}
	var n int
	if err := h.srv.store.pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d sessions exist, want none", n)
	}
}

// A flow with no resource in a multi-target deployment, or one naming no target,
// is refused rather than falling back to the first target.
func TestCallbackRefusesAFlowWithNoUsableResource(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	for name, resource := range map[string]string{
		"empty":   "",
		"unknown": h.srv.cfg.PublicURL + "/nowhere/mcp",
	} {
		t.Run(name, func(t *testing.T) {
			first := h.srv.cfg.Targets[0]
			flow := Flow{
				ID: newSecret(), ClientID: clientID, RedirectURI: redirect, CodeChallenge: "c",
				UpstreamVerifier: newSecret(), Resource: resource,
				Target: first.Name, Stamp: first.Stamp(), BrowserSecret: "b",
			}
			ctx := t.Context()
			if err := h.srv.store.CreateFlow(ctx, flow); err != nil {
				t.Fatal(err)
			}
			if _, err := h.srv.store.ApproveFlow(ctx, flow.ID, "b"); err != nil {
				t.Fatal(err)
			}
			resp := h.get(h.proxy.URL + "/callback?state=" + flow.ID + "&code=upstream-code&iss=" + url.QueryEscape(h.provider.URL))
			defer resp.Body.Close()
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if loc.Query().Get("error") == "" || loc.Query().Get("code") != "" {
				t.Errorf("redirect %q: want an error and no code", loc)
			}
		})
	}
}

// Two pods with different definitions of one name each keep their own
// credential; neither overwrites the other, and neither can use the other's.
func TestReplicasWithDifferentDefinitionsKeepTheirOwnCredentials(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	old := h.srv.cfg.Targets[0]
	changed := old
	changed.UpstreamMCP += "/v2"

	h.enrol("user-42", "alpha", map[string]string{"Authorization": "Bearer old", "x-workspace-slug": "w"})
	// The same user, under the other definition, as the second pod would store it.
	raw, _ := json.Marshal(map[string]string{"Authorization": "Bearer new", "x-workspace-slug": "w"})
	sealed, err := h.srv.sealer.seal(boundPurpose(purposeUserCredential, changed.Stamp()), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.store.PutUserCredential(t.Context(), "user-42", "alpha", changed.Stamp(), sealed); err != nil {
		t.Fatal(err)
	}

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, old.Resource)
	resp := h.mcpRequest("/alpha/mcp", access)
	defer resp.Body.Close()
	var saw struct {
		Authorization string `json:"saw_authorization"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&saw); err != nil {
		t.Fatal(err)
	}
	if saw.Authorization != "Bearer old" {
		t.Errorf("upstream saw %q; the session's own definition must get its own credential", saw.Authorization)
	}
}
