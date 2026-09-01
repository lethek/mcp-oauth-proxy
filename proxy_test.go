package main

import (
	"net/http/httptest"
	"testing"
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
