package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
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

// TestConcurrentDiscoveryFetchesAreCollapsed (MOP-7): the backoff only starts
// once a fetch has failed, so callers that arrived while the first fetch was
// still hanging each started their own. Against a hung provider, 20 callers
// made 40 requests. One fetch should run on behalf of everyone waiting.
func TestConcurrentDiscoveryFetchesAreCollapsed(t *testing.T) {
	var hits atomic.Int64
	release := make(chan struct{})

	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer hung.Close()

	u := NewUpstream(&Config{UpstreamIssuer: hung.URL})
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := u.Meta(ctx); err == nil {
				t.Error("Meta succeeded against a provider returning 503")
			}
		})
	}

	// Let the first request reach the provider and the rest pile up behind it.
	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	// One fetch tries both well-known paths, so two requests is the floor.
	if got := hits.Load(); got > 2 {
		t.Errorf("20 concurrent Meta calls made %d discovery requests, want at most 2", got)
	}
}

// TestDiscoverySucceedsAfterTheProviderRecovers makes sure the negative cache
// is a delay, not a latch.
func TestDiscoverySucceedsAfterTheProviderRecovers(t *testing.T) {
	var healthy atomic.Bool

	// The document has to declare its own URL as the issuer. RFC 8414 section
	// 3.3 requires that to match what was asked for, so a fixture naming some
	// other issuer is now rejected before the recovery under test is reached.
	var issuer atomic.Value
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		base, _ := issuer.Load().(string)
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
		})
	}))
	defer provider.Close()
	issuer.Store(provider.URL)

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
	if meta.TokenEndpoint != provider.URL+"/token" {
		t.Errorf("unexpected token endpoint %q", meta.TokenEndpoint)
	}
}

// TestStaleDiscoveryIsServedThroughAnOutage covers the fallback that exists so a
// provider restart does not take every authorization down with it.
//
// The second call is the one that matters. Serving the stale document only from
// the branch that attempts a fetch meant one call in each retry window survived
// the outage and every other call failed, which is not what the fallback was
// added to do.
func TestStaleDiscoveryIsServedThroughAnOutage(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)

	provider := httptest.NewUnstartedServer(nil)
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 "http://" + provider.Listener.Addr().String(),
			"authorization_endpoint": "https://provider.example/authorize",
			"token_endpoint":         "https://provider.example/token",
		})
	})
	provider.Start()
	defer provider.Close()

	u := NewUpstream(&Config{UpstreamIssuer: provider.URL})
	ctx := context.Background()

	first, err := u.Meta(ctx)
	if err != nil {
		t.Fatalf("initial discovery: %v", err)
	}

	// Age the document past its TTL and take the provider away.
	healthy.Store(false)
	u.mu.Lock()
	u.fetchedAt = time.Now().Add(-discoveryTTL - time.Second)
	u.mu.Unlock()

	for i := range 5 {
		got, err := u.Meta(ctx)
		if err != nil {
			t.Fatalf("call %d during the outage failed with a usable document in memory: %v", i+1, err)
		}
		if got.TokenEndpoint != first.TokenEndpoint {
			t.Fatalf("call %d returned %q, want the cached %q", i+1, got.TokenEndpoint, first.TokenEndpoint)
		}
	}
}

// TestStaleDiscoveryIsNotServedForever bounds the fallback above. Without a
// bound, a provider we can no longer reach leaves the process running on a
// document nobody has confirmed, and a rotated endpoint never takes effect.
func TestStaleDiscoveryIsNotServedForever(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	u := NewUpstream(&Config{UpstreamIssuer: down.URL})
	u.meta = &upstreamMeta{
		Issuer:                down.URL,
		AuthorizationEndpoint: "https://provider.example/authorize",
		TokenEndpoint:         "https://provider.example/token",
	}
	u.fetchedAt = time.Now().Add(-discoveryMaxStale - time.Minute)

	if _, err := u.Meta(context.Background()); err == nil {
		t.Error("a document older than discoveryMaxStale was served")
	}
	// And again, now that the failure is cached, so the bound holds on the
	// backoff path too.
	if _, err := u.Meta(context.Background()); err == nil {
		t.Error("a document older than discoveryMaxStale was served during retry backoff")
	}
}
