package main

import "testing"

func TestParseStaticHeaders(t *testing.T) {
	t.Run("empty yields no headers", func(t *testing.T) {
		got, err := parseStaticHeaders("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("want no headers, got %v", got)
		}
	})

	t.Run("parses pairs and trims", func(t *testing.T) {
		got, err := parseStaticHeaders("Authorization: Bearer abc123\n  x-workspace-slug:  acme  \n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("want 2 headers, got %d: %v", len(got), got)
		}
		if got["Authorization"] != "Bearer abc123" {
			t.Errorf("Authorization = %q", got["Authorization"])
		}
		if got["x-workspace-slug"] != "acme" {
			t.Errorf("x-workspace-slug = %q", got["x-workspace-slug"])
		}
	})

	t.Run("keeps colons in the value", func(t *testing.T) {
		got, err := parseStaticHeaders("X-Target: https://example.com:8443/path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["X-Target"] != "https://example.com:8443/path" {
			t.Errorf("X-Target = %q", got["X-Target"])
		}
	})

	t.Run("skips blank lines", func(t *testing.T) {
		got, err := parseStaticHeaders("\n\nA: 1\n\n\nB: 2\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("want 2 headers, got %v", got)
		}
	})

	for name, raw := range map[string]string{
		"no colon":     "Authorization Bearer abc",
		"empty name":   ": value",
		"empty value":  "Authorization:   ",
		"one bad line": "A: 1\nbroken\nB: 2",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := parseStaticHeaders(raw); err == nil {
				t.Fatalf("want an error for %q, got none", raw)
			}
		})
	}
}
