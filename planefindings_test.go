package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Tests for the Plane work items filed against HEAD 699e2dc (MOP-5, MOP-6,
// MOP-9). Each one reproduced before its fix.

// injectFailure makes every statement of the given kind on a table fail, the
// way a statement timeout, a failover or a saturated pool would, and removes
// the fault when the test ends or when the returned func is called.
func injectFailure(t *testing.T, s *Store, event, table string) (clear func()) {
	t.Helper()
	ctx := context.Background()
	fn := "injected_" + strings.ToLower(event) + "_" + table
	if _, err := s.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected `+event+` failure on `+table+`'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `CREATE TRIGGER `+fn+` BEFORE `+event+` ON `+table+
		` FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatal(err)
	}
	clear = func() {
		_, _ = s.pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+fn+` ON `+table)
		_, _ = s.pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+fn)
	}
	t.Cleanup(clear)
	return clear
}

// MOP-6: a client_name cut on a byte boundary inside a multi-byte rune is not
// valid UTF-8, and Postgres refuses to store it, so a valid registration got a
// 500.
func TestRegisterTruncatesClientNameOnRunes(t *testing.T) {
	h := newHarness(t)

	body, _ := json.Marshal(map[string]any{
		"client_name":   strings.Repeat("a", 99) + "é Corporation",
		"redirect_uris": []string{"http://127.0.0.1:9999/cb"},
	})
	resp, err := h.client.Post(h.proxy.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d, want 201", resp.StatusCode)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	c, err := h.srv.store.GetClient(context.Background(), out.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(c.Name) {
		t.Errorf("stored name is not valid UTF-8: %q", c.Name)
	}
	if n := utf8.RuneCountInString(c.Name); n != 100 {
		t.Errorf("stored name is %d runes, want 100", n)
	}
}

// MOP-6, second site: the CIMD name is never stored, but the same cut left it
// rendering as U+FFFD on the consent page.
func TestCIMDTruncatesClientNameOnRunes(t *testing.T) {
	id := "https://client.example/mcp"
	body := mustJSON(t, map[string]any{
		"client_id":     id,
		"client_name":   strings.Repeat("a", 99) + "é Corporation",
		"redirect_uris": []string{"https://client.example/callback"},
	})
	c, err := parseCIMD(id, body)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(c.Name) {
		t.Errorf("name is not valid UTF-8: %q", c.Name)
	}
	if n := utf8.RuneCountInString(c.Name); n != 100 {
		t.Errorf("name is %d runes, want 100", n)
	}
}

// MOP-9: the provider has already rotated the refresh token by the time the
// persist runs, so a transient database failure there must not fail the request
// that holds the only usable copy of the new token.
func TestRefreshedUpstreamTokenIsServedWhenThePersistFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sessionID := newSecret()
	expired := UpstreamToken{
		AccessToken:  "stale-access-token",
		RefreshToken: "stale-refresh-token",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	if err := h.srv.persistToken(ctx, sessionID, "subject", h.srv.cfg.Targets[0].Resource, expired, true); err != nil {
		t.Fatal(err)
	}

	injectFailure(t, h.srv.store, "UPDATE", "sessions")

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	tok, err := h.srv.currentUpstreamToken(req, sessionID)
	if err != nil {
		t.Fatalf("the request that obtained the fresh token failed: %v", err)
	}
	if tok.AccessToken != "upstream-access-token" {
		t.Errorf("served %q, want the token the provider just issued", tok.AccessToken)
	}
	if n := h.providerTokenHits.Load(); n != 1 {
		t.Errorf("provider token endpoint called %d times, want 1", n)
	}
}

// MOP-5: an authorization code is consumed on read, so a failure while writing
// the tokens it buys must roll that consumption back or the client can never
// retry the exchange.
func TestCodeExchangeCanBeRetriedAfterATransientFailure(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	verifier := newSecret()
	code := h.authorizeThroughConsent(clientID, redirect, verifier)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}

	clear := injectFailure(t, h.srv.store, "INSERT", "access_tokens")
	failed := h.postForm("/token", form)
	failed.Body.Close()
	if failed.StatusCode != http.StatusInternalServerError {
		t.Fatalf("exchange during the fault: status %d, want 500", failed.StatusCode)
	}
	clear()

	retry := h.postForm("/token", form)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retrying the exchange after the fault cleared: status %d, want 200", retry.StatusCode)
	}
}

// MOP-5, refresh side. Worse than the code case: the consumed token looks like
// a replay on retry, and replay revokes the whole session.
func TestRefreshCanBeRetriedAfterATransientFailure(t *testing.T) {
	h := newHarness(t)

	redirect := "http://127.0.0.1:9999/cb"
	clientID := h.register(redirect)
	access, refresh := h.tokens(clientID, redirect)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}

	clear := injectFailure(t, h.srv.store, "INSERT", "access_tokens")
	failed := h.postForm("/token", form)
	failed.Body.Close()
	if failed.StatusCode != http.StatusInternalServerError {
		t.Fatalf("refresh during the fault: status %d, want 500", failed.StatusCode)
	}
	clear()

	retry := h.postForm("/token", form)
	retry.Body.Close()
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("retrying the refresh after the fault cleared: status %d, want 200", retry.StatusCode)
	}

	// And the session survived: the original access token still works.
	mcp, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/mcp", nil)
	mcp.Header.Set("Authorization", "Bearer "+access)
	resp, err := h.client.Do(mcp)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("the session was revoked by a retry of a refresh that never succeeded")
	}
}
