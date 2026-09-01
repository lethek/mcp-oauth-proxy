package main

import "testing"

func TestParseTargetsLegacy(t *testing.T) {
	t.Run("bare upstream is one unnamed target forwarding the provider token", func(t *testing.T) {
		t.Setenv("UPSTREAM_MCP_URL", "http://mcp.internal:8080")

		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("want 1 target, got %d", len(got))
		}
		if got[0].Name != "" {
			t.Errorf("name = %q, want empty for the legacy target", got[0].Name)
		}
		if got[0].Mode != CredProviderToken {
			t.Errorf("mode = %q, want provider_token", got[0].Mode)
		}
		if want := "https://proxy.example/mcp"; got[0].Resource != want {
			t.Errorf("resource = %q, want %q", got[0].Resource, want)
		}
	})

	t.Run("static headers switch the legacy target's mode", func(t *testing.T) {
		t.Setenv("UPSTREAM_MCP_URL", "http://mcp.internal:8080")
		t.Setenv("UPSTREAM_STATIC_HEADERS", "Authorization: Bearer x")

		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got[0].Mode != CredStatic {
			t.Errorf("mode = %q, want static", got[0].Mode)
		}
	})
}

func TestParseTargetsMulti(t *testing.T) {
	setTwo := func(t *testing.T) {
		t.Helper()
		t.Setenv("TARGETS", "forgejo,plane")
		t.Setenv("TARGET_FORGEJO_UPSTREAM_MCP_URL", "http://forgejo-mcp:8080")
		t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane-mcp:8211/http/api-key")
		t.Setenv("TARGET_PLANE_CREDENTIAL_MODE", "static")
		t.Setenv("TARGET_PLANE_STATIC_HEADERS", "Authorization: Bearer pat\nx-workspace-slug: acme")
	}

	t.Run("parses both with their own modes and resources", func(t *testing.T) {
		setTwo(t)

		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("want 2 targets, got %d", len(got))
		}
		if got[0].Name != "forgejo" || got[0].Mode != CredProviderToken {
			t.Errorf("forgejo = %+v", got[0])
		}
		if want := "https://proxy.example/forgejo/mcp"; got[0].Resource != want {
			t.Errorf("forgejo resource = %q, want %q", got[0].Resource, want)
		}
		if got[1].Mode != CredStatic || got[1].StaticHeaders["x-workspace-slug"] != "acme" {
			t.Errorf("plane = %+v", got[1])
		}
	})

	// Combining the two schemes is ambiguous about which upstream is meant, and
	// quietly preferring one would route real traffic on a guess.
	t.Run("rejects the legacy variables alongside TARGETS", func(t *testing.T) {
		setTwo(t)
		t.Setenv("UPSTREAM_MCP_URL", "http://old:8080")

		if _, err := parseTargets("https://proxy.example"); err == nil {
			t.Fatal("want an error when TARGETS is combined with UPSTREAM_MCP_URL")
		}
	})

	for name, setup := range map[string]func(*testing.T){
		"invalid target name": func(t *testing.T) {
			t.Setenv("TARGETS", "Plane")
			t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")
		},
		"duplicate target": func(t *testing.T) {
			t.Setenv("TARGETS", "plane,plane")
			t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")
		},
		"missing upstream url": func(t *testing.T) {
			t.Setenv("TARGETS", "plane")
		},
		"unknown credential mode": func(t *testing.T) {
			t.Setenv("TARGETS", "plane")
			t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")
			t.Setenv("TARGET_PLANE_CREDENTIAL_MODE", "magic")
		},
		"static without headers": func(t *testing.T) {
			t.Setenv("TARGETS", "plane")
			t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")
			t.Setenv("TARGET_PLANE_CREDENTIAL_MODE", "static")
		},
		// Headers that will never be sent are a config that does not mean what it
		// looks like, so they are refused rather than ignored.
		"headers without static mode": func(t *testing.T) {
			t.Setenv("TARGETS", "plane")
			t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")
			t.Setenv("TARGET_PLANE_STATIC_HEADERS", "Authorization: Bearer x")
		},
		"empty target list": func(t *testing.T) {
			t.Setenv("TARGETS", " , ")
		},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			setup(t)
			if _, err := parseTargets("https://proxy.example"); err == nil {
				t.Fatalf("want an error for %s", name)
			}
		})
	}
}

func TestDisplayName(t *testing.T) {
	t.Run("defaults to the capitalised name", func(t *testing.T) {
		t.Setenv("TARGETS", "plane")
		t.Setenv("TARGET_PLANE_UPSTREAM_MCP_URL", "http://plane:8211")

		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got[0].DisplayName != "Plane" {
			t.Errorf("DisplayName = %q, want %q", got[0].DisplayName, "Plane")
		}
	})

	t.Run("an explicit value wins", func(t *testing.T) {
		t.Setenv("TARGETS", "git-mcp")
		t.Setenv("TARGET_GIT_MCP_UPSTREAM_MCP_URL", "http://forgejo-mcp:8080")
		t.Setenv("TARGET_GIT_MCP_DISPLAY_NAME", "Forgejo")

		got, err := parseTargets("https://proxy.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got[0].DisplayName != "Forgejo" {
			t.Errorf("DisplayName = %q, want %q", got[0].DisplayName, "Forgejo")
		}
		// The identity used in URLs and lookups must not change with it.
		if got[0].Name != "git-mcp" {
			t.Errorf("Name = %q, want it untouched", got[0].Name)
		}
	})
}

func TestEnvPrefix(t *testing.T) {
	for name, want := range map[string]string{
		"plane":   "TARGET_PLANE_",
		"git-mcp": "TARGET_GIT_MCP_",
	} {
		if got := envPrefix(name); got != want {
			t.Errorf("envPrefix(%q) = %q, want %q", name, got, want)
		}
	}
}

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
