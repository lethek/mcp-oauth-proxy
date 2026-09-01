package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrepareUpstreamHeaders(t *testing.T) {
	t.Run("static mode replaces the caller's credential", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header.Set("Authorization", "Bearer caller-token")

		settled := prepareUpstreamHeaders(r, map[string]string{
			"Authorization":    "Bearer plane-pat",
			"x-workspace-slug": "acme",
		})

		if !settled {
			t.Fatal("want settled=true in static mode")
		}
		if got := r.Header.Get("Authorization"); got != "Bearer plane-pat" {
			t.Errorf("Authorization = %q, want the static credential", got)
		}
		if got := r.Header.Get("x-workspace-slug"); got != "acme" {
			t.Errorf("x-workspace-slug = %q", got)
		}
	})

	// The reason the drop is unconditional: a static config that sets only a
	// custom header must not let the caller's own token through to the upstream.
	t.Run("caller's token never survives, even when not overwritten", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header.Set("Authorization", "Bearer caller-token")

		settled := prepareUpstreamHeaders(r, map[string]string{"x-api-key": "k"})

		if !settled {
			t.Fatal("want settled=true")
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("caller's token leaked upstream: %q", got)
		}
	})

	t.Run("token mode reports unsettled and clears the caller's token", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header.Set("Authorization", "Bearer caller-token")

		if settled := prepareUpstreamHeaders(r, nil); settled {
			t.Fatal("want settled=false with no static headers")
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("caller's token should be cleared before the token swap, got %q", got)
		}
	})
}

// TestUpstreamConcurrencyIsBounded covers what replaced ResponseHeaderTimeout.
//
// Removing that timeout was right: it capped every tool call at 60 seconds. It
// also removed the only bound on a request to an upstream that accepts the
// connection and never answers, and the rate limiter does not supply one
// because it counts arrivals per minute rather than concurrent work. A caller
// who opens requests and holds them open would otherwise accumulate goroutines
// and upstream connections without limit.
func TestUpstreamConcurrencyIsBounded(t *testing.T) {
	release := make(chan struct{})
	var arrived atomic.Int64

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Add(1)
		<-release
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(newReverseProxy(target, ""))
	defer front.Close()

	// Fill every slot. Each of these stays parked in the upstream handler until
	// release is closed.
	var wg sync.WaitGroup
	for range maxInFlightPerTarget {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(front.URL + "/mcp")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	defer func() {
		close(release)
		wg.Wait()
	}()

	deadline := time.Now().Add(10 * time.Second)
	for arrived.Load() < maxInFlightPerTarget {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d requests reached the upstream", arrived.Load(), maxInFlightPerTarget)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A short client timeout, so that a proxy with no bound fails this test
	// rather than hanging in the upstream handler until the suite times out.
	refused := &http.Client{Timeout: 5 * time.Second}
	resp, err := refused.Get(front.URL + "/mcp")
	if err != nil {
		t.Fatalf("the request past the bound was forwarded to the blocked upstream instead of being refused: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("request past the concurrency bound: status %d, want 503", resp.StatusCode)
	}
	// A refusal the client can act on, rather than one it has to guess about.
	if resp.Header.Get("Retry-After") == "" {
		t.Error("the refusal carried no Retry-After")
	}
	// The upstream must not have been contacted by the refused request.
	if got := arrived.Load(); got != maxInFlightPerTarget {
		t.Errorf("%d requests reached the upstream, want %d: the refused one was forwarded", got, maxInFlightPerTarget)
	}
}

// TestConcurrencySlotsAreReleased: a bound that leaked slots would refuse
// everything after the first burst, turning a safeguard into an outage.
func TestConcurrencySlotsAreReleased(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(newReverseProxy(target, ""))
	defer front.Close()

	for i := range maxInFlightPerTarget * 3 {
		resp, err := http.Get(front.URL + "/mcp")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200; slots are not being released", i+1, resp.StatusCode)
		}
	}
}
