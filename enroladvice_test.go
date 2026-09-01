package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// TestUpstreamUnauthorizedBecomesEnrolAdvice covers the revoked-credential path:
// the MCP server rejects the stored credential, and the client must be told to
// replace it rather than handed an unexplained "unauthorized" about a credential
// it has never seen.
//
// The upstream here answers with chunked encoding and its own WWW-Authenticate,
// which is what a real server does, so the rewrite has to cope with both.
func TestUpstreamUnauthorizedBecomesEnrolAdvice(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	// Point alpha's upstream at a handler that always refuses.
	h.refuseAlpha.Store(true)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)
	h.enrol("user-42", "alpha", map[string]string{
		"Authorization": "Bearer revoked-token",
	})

	resp := h.mcpRequest("/alpha/mcp", access)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403 so the client does not retry OAuth pointlessly", resp.StatusCode)
	}

	// The upstream's own challenge names a realm the client cannot act on.
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want it removed", got)
	}

	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("the rewritten body did not decode, which is what a stale Content-Length looks like: %v", err)
	}
	if body.Error != "access_denied" {
		t.Errorf("error = %q", body.Error)
	}

	// A Content-Length left over from the upstream's body would either truncate
	// this one or leave the client waiting for bytes that never come.
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil {
			t.Fatalf("Content-Length %q is not a number", cl)
		}
		if int64(n) != resp.ContentLength {
			t.Errorf("Content-Length header %d disagrees with ContentLength %d", n, resp.ContentLength)
		}
	}
}
