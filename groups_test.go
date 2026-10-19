package main

import (
	"net/http"
	"net/url"
	"testing"
)

// restrictedBeta is twoTargets with beta limited to admins, the shape of a
// static target that shares one credential among everyone who reaches it.
func restrictedBeta(cfg *Config, upstreamURL string) []Target {
	targets := twoTargets(cfg, upstreamURL)
	targets[1].AllowedGroups = []string{"admins"}
	return targets
}

func (h *harness) setGroups(groups ...string) { h.groups.Store(&groups) }

// callbackRedirect walks the flow for a resource and returns where /callback
// sent the browser, whether that carries a code or an error.
func (h *harness) callbackRedirect(clientID, redirect, resource string) *url.URL {
	h.t.Helper()

	flowID := h.consentFlowID(h.get(h.authorizeURLFor(clientID, redirect, s256(newSecret()), resource)))
	consent := h.postForm("/consent", url.Values{"flow_id": {flowID}, "decision": {"approve"}})
	consent.Body.Close()
	toProvider := h.get(consent.Header.Get("Location"))
	toProvider.Body.Close()

	callback := h.get(toProvider.Header.Get("Location"))
	callback.Body.Close()
	if callback.StatusCode != http.StatusFound {
		h.t.Fatalf("callback: status %d, want a redirect to the client", callback.StatusCode)
	}
	back, err := url.Parse(callback.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	return back
}

func assertRefused(t *testing.T, back *url.URL) {
	t.Helper()
	if got := back.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q, want access_denied", got)
	}
	if back.Query().Get("code") != "" {
		t.Error("a code was issued to a caller outside the allowed groups")
	}
}

// TestRestrictedTargetRefusesOutsiders is why ALLOWED_GROUPS exists. A static
// target hands everyone the same credential, so the only place to keep a caller
// out is before they get a token. The unrestricted target beside it must keep
// working for the same person.
func TestRestrictedTargetRefusesOutsiders(t *testing.T) {
	h := newHarnessWith(t, restrictedBeta)
	h.setGroups("users")

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	assertRefused(t, h.callbackRedirect(clientID, redirect, h.srv.cfg.Targets[1].Resource))

	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)
	resp := h.mcpRequest("/alpha/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unrestricted alpha: status %d, want 200", resp.StatusCode)
	}
	if got := h.betaHits.Load(); got != 0 {
		t.Errorf("beta upstream was reached %d times", got)
	}
}

func TestRestrictedTargetAdmitsMembers(t *testing.T) {
	h := newHarnessWith(t, restrictedBeta)
	h.setGroups("users", "admins")

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)

	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[1].Resource)
	resp := h.mcpRequest("/beta/mcp", access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("beta for an admin: status %d, want 200", resp.StatusCode)
	}
}

// TestRestrictedTargetFailsClosed covers a provider that says nothing about
// groups, or nothing at all. Either way the restriction cannot be shown to be
// met, so the caller is refused rather than let through.
func TestRestrictedTargetFailsClosed(t *testing.T) {
	const redirect = "https://client.example/callback"

	t.Run("no groups claim", func(t *testing.T) {
		h := newHarnessWith(t, restrictedBeta)
		clientID := h.register(redirect)
		assertRefused(t, h.callbackRedirect(clientID, redirect, h.srv.cfg.Targets[1].Resource))
	})

	t.Run("userinfo refused", func(t *testing.T) {
		h := newHarnessWith(t, restrictedBeta)
		h.setGroups("admins")
		h.refuseUserinfo.Store(true)
		clientID := h.register(redirect)
		assertRefused(t, h.callbackRedirect(clientID, redirect, h.srv.cfg.Targets[1].Resource))
	})
}

func TestTargetAdmits(t *testing.T) {
	open := Target{}
	limited := Target{AllowedGroups: []string{"admins", "ops"}}

	for _, tc := range []struct {
		name   string
		target Target
		groups []string
		want   bool
	}{
		{"open target, no groups", open, nil, true},
		{"limited, member of one", limited, []string{"users", "ops"}, true},
		{"limited, member of none", limited, []string{"users"}, false},
		{"limited, no groups", limited, nil, false},
		{"limited, case differs", limited, []string{"Admins"}, false},
	} {
		if got := tc.target.Admits(tc.groups); got != tc.want {
			t.Errorf("%s: Admits = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseAllowedGroups(t *testing.T) {
	set := func(t *testing.T, raw string) {
		t.Helper()
		t.Setenv("TARGETS", "plane")
		t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")
		t.Setenv("TARGET_PLANE_ALLOWED_GROUPS", raw)
	}

	t.Run("trims and drops empties", func(t *testing.T) {
		set(t, " admins, ,ops ")
		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g := got[0].AllowedGroups; len(g) != 2 || g[0] != "admins" || g[1] != "ops" {
			t.Errorf("AllowedGroups = %q, want [admins ops]", g)
		}
	})

	t.Run("unset leaves the target open", func(t *testing.T) {
		set(t, "")
		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got[0].AllowedGroups) != 0 {
			t.Errorf("AllowedGroups = %q, want none", got[0].AllowedGroups)
		}
	})

	// Separators alone must not quietly mean "everyone".
	t.Run("a value naming no group is refused", func(t *testing.T) {
		set(t, " , ")
		if _, err := parseTargets("https://proxy.example"); err == nil {
			t.Fatal("ALLOWED_GROUPS of only separators was accepted")
		}
	})
}
