package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestDiscoveryFailureIsRememberedBriefly stops an outage at the provider
// turning every waiting caller into two more attempts against it. Each Meta
// call tries both well-known paths, so without this an outage amplifies load on
// a provider that is already struggling, and every caller waits out the client
// timeout twice before failing.
func TestDiscoveryFailureIsRememberedBriefly(t *testing.T) {
	var hits atomic.Int64

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	u := NewUpstream(&Config{UpstreamIssuer: down.URL})
	ctx := context.Background()

	if _, err := u.Meta(ctx); err == nil {
		t.Fatal("Meta succeeded against a provider returning 503")
	}
	afterFirst := hits.Load()
	if afterFirst == 0 {
		t.Fatal("the provider was never contacted")
	}

	for range 10 {
		if _, err := u.Meta(ctx); err == nil {
			t.Fatal("Meta succeeded against a provider returning 503")
		}
	}
	if got := hits.Load(); got != afterFirst {
		t.Errorf("10 further calls during the outage made %d more attempts, want 0", got-afterFirst)
	}

	// Recovery must not be blocked for longer than the retry window.
	if discoveryRetryAfter > 30*time.Second {
		t.Errorf("discoveryRetryAfter is %s, long enough to delay recovery noticeably", discoveryRetryAfter)
	}
}

// TestDiscoverySucceedsAfterTheProviderRecovers makes sure the negative cache
// is a delay, not a latch.
func TestDiscoverySucceedsAfterTheProviderRecovers(t *testing.T) {
	var healthy atomic.Bool

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 "https://provider.example",
			"authorization_endpoint": "https://provider.example/authorize",
			"token_endpoint":         "https://provider.example/token",
		})
	}))
	defer provider.Close()

	u := NewUpstream(&Config{UpstreamIssuer: provider.URL})
	ctx := context.Background()

	if _, err := u.Meta(ctx); err == nil {
		t.Fatal("Meta succeeded while the provider was down")
	}

	healthy.Store(true)
	// Expire the remembered failure rather than sleeping out the real window.
	u.mu.Lock()
	u.failedAt = time.Now().Add(-discoveryRetryAfter - time.Second)
	u.mu.Unlock()

	meta, err := u.Meta(ctx)
	if err != nil {
		t.Fatalf("Meta after recovery: %v", err)
	}
	if meta.TokenEndpoint != "https://provider.example/token" {
		t.Errorf("unexpected token endpoint %q", meta.TokenEndpoint)
	}
}
