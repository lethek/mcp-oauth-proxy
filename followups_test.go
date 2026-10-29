package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The spec orders the checks freshness, session stamp, then target. A token
// for alpha presented at beta fails both the stamp and the audience check, and
// must get the stamp check's answer, which is the generic "unknown or expired"
// rather than the one that names a resource.
func TestSessionStampIsCheckedBeforeAudience(t *testing.T) {
	h := newHarnessWith(t, twoTargets)
	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.Targets[0].Resource)

	resp := h.mcpRequest("/beta/mcp", access)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(string(body), "the access token is unknown or expired") {
		t.Errorf("body = %s, want the stamp check's answer", body)
	}
	if strings.Contains(string(body), "was not issued for") {
		t.Errorf("body = %s, the audience check answered first", body)
	}
}

// With the feature off the sweep still removes admin-stamped rows that no
// targets row backs, because an operator may switch it off after a removal
// whose purge failed. Rows for a live target and for config targets stay.
func TestDisabledFeatureSweepPurgesOrphanedAdminRows(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	if h.srv.store.admin != nil {
		t.Fatal("the feature should be off")
	}
	ctx := t.Context()
	pool := h.srv.store.pool

	h.seedStamped("gone", "admin:orphan", "u")
	h.seedStamped("live", "admin:live", "u")
	h.seedStamped("alpha", "config:keep", "u")
	if _, err := pool.Exec(ctx, `INSERT INTO targets (name, display_name, upstream_mcp, mode, stamp, updated_by)
VALUES ('live', 'Live', 'https://mcp.example/', 'provider_token', 'admin:live', 'root')`); err != nil {
		t.Fatal(err)
	}

	h.srv.sweepOnce(ctx)

	count := func(stamp string) int {
		n := 0
		for _, table := range []string{"flows", "sessions", "user_credentials"} {
			n += h.count(`SELECT count(*) FROM `+table+` WHERE stamp = $1`, stamp)
		}
		return n
	}
	if got := count("admin:orphan"); got != 0 {
		t.Errorf("%d orphaned admin rows survived the sweep", got)
	}
	if got := count("admin:live"); got != 3 {
		t.Errorf("%d rows for a live target remain, want 3", got)
	}
	if got := count("config:keep"); got != 3 {
		t.Errorf("%d config rows remain, want 3", got)
	}
}

// Admin targets enabled with none yet: the snapshot is empty. Nothing may
// panic or name an empty list.
func TestEmptySnapshotSaysNoServersAreAvailable(t *testing.T) {
	h := newHarnessWith(t, func(cfg *Config, upstreamURL string) []Target {
		adminOn(cfg, upstreamURL)
		return nil
	})
	clientID := h.register(testRedirect)

	for name, resource := range map[string]string{"no resource": "", "a resource": h.proxy.URL + "/alpha/mcp"} {
		resp := h.get(h.authorizeURLFor(clientID, testRedirect, "challenge", resource))
		resp.Body.Close()
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "temporarily_unavailable" {
			t.Errorf("%s: status %d, Location %q, want a temporarily_unavailable redirect", name, resp.StatusCode, loc)
		}
		if got := loc.Query().Get("error_description"); got != noTargetsMessage {
			t.Errorf("%s: error_description = %q", name, got)
		}
	}

	for path, want := range map[string]int{
		"/.well-known/oauth-protected-resource":           http.StatusServiceUnavailable,
		"/.well-known/oauth-protected-resource/alpha/mcp": http.StatusNotFound,
		"/.well-known/oauth-authorization-server":         http.StatusOK,
	} {
		resp := h.get(h.proxy.URL + path)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
		if strings.Contains(string(body), "one of them: ") {
			t.Errorf("%s: body = %s, names an empty list", path, body)
		}
	}
}
