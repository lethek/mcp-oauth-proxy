package main

import (
	"strings"
	"testing"
)

// minimalEnv sets everything LoadConfig demands, so a test can vary the one
// setting it is about.
func minimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PUBLIC_URL", "https://proxy.example")
	t.Setenv("UPSTREAM_MCP_URL", "http://mcp.internal:8080")
	t.Setenv("UPSTREAM_ISSUER", "https://idp.example")
	t.Setenv("UPSTREAM_CLIENT_ID", "proxy")
	t.Setenv("UPSTREAM_CLIENT_SECRET", "secret")
	t.Setenv("DATABASE_URL", "postgres://localhost/proxy")
	t.Setenv("ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
}

// MOP-13: a hop count alone lets anything that can reach this process directly
// present its own X-Forwarded-For, so the networks the proxies connect from have
// to be stated too. Refusing at boot is the only place that can be said clearly.
func TestTrustedProxyHopsRequireTrustedProxyCIDRs(t *testing.T) {
	t.Run("hops without networks is refused", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("TRUSTED_PROXY_HOPS", "1")

		_, err := LoadConfig()
		if err == nil {
			t.Fatal("a hop count with no trusted networks was accepted")
		}
		if !strings.Contains(err.Error(), "TRUSTED_PROXY_CIDRS") {
			t.Errorf("error = %q, want it to name the setting that is missing", err)
		}
	})

	t.Run("hops with networks is accepted", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("TRUSTED_PROXY_HOPS", "1")
		t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.TrustedProxyCIDRs) != 2 {
			t.Fatalf("parsed %d networks, want 2", len(cfg.TrustedProxyCIDRs))
		}
	})

	t.Run("a value that is not a network is refused", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("TRUSTED_PROXY_HOPS", "1")
		t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.1")

		if _, err := LoadConfig(); err == nil {
			t.Fatal("a bare address was accepted where a network is required")
		}
	})

	t.Run("no hops needs no networks", func(t *testing.T) {
		minimalEnv(t)

		if _, err := LoadConfig(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// MOP-16: PUBLIC_URL is concatenated with a suffix to build every advertised
// URL, so only the path component was refused and a query or fragment swallowed
// the suffix instead: "https://proxy.example?x=1" + "/callback" points at the
// root with a nonsense parameter.
func TestPublicURLMustBeABareOrigin(t *testing.T) {
	for _, raw := range []string{
		"https://proxy.example/prefix",
		"https://proxy.example?x=1",
		"https://proxy.example/?x=1",
		"https://proxy.example#frag",
		"https://user:pw@proxy.example",
	} {
		t.Run(raw, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv("PUBLIC_URL", raw)

			if _, err := LoadConfig(); err == nil {
				t.Errorf("%q was accepted, but every advertised URL built from it is wrong", raw)
			}
		})
	}
}

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
		got, err := parseStaticHeaders("UPSTREAM_STATIC_HEADERS", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("want no headers, got %v", got)
		}
	})

	t.Run("parses pairs and trims", func(t *testing.T) {
		got, err := parseStaticHeaders("UPSTREAM_STATIC_HEADERS", "Authorization: Bearer abc123\n  x-workspace-slug:  acme  \n")
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
		got, err := parseStaticHeaders("UPSTREAM_STATIC_HEADERS", "X-Target: https://example.com:8443/path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["X-Target"] != "https://example.com:8443/path" {
			t.Errorf("X-Target = %q", got["X-Target"])
		}
	})

	t.Run("skips blank lines", func(t *testing.T) {
		got, err := parseStaticHeaders("UPSTREAM_STATIC_HEADERS", "\n\nA: 1\n\n\nB: 2\n")
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
			if _, err := parseStaticHeaders("UPSTREAM_STATIC_HEADERS", raw); err == nil {
				t.Fatalf("want an error for %q, got none", raw)
			}
		})
	}
}

func TestParseUserHeaderFields(t *testing.T) {
	t.Run("parses a valid set", func(t *testing.T) {
		got, err := parseUserHeaderFields(`[
			{"header":"Authorization","label":"Token","prefix":"Bearer "},
			{"header":"x-workspace-slug","label":"Workspace"}
		]`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0].Prefix != "Bearer " || got[1].Header != "x-workspace-slug" {
			t.Errorf("parsed as %+v", got)
		}
	})

	t.Run("empty yields nothing", func(t *testing.T) {
		got, err := parseUserHeaderFields("  ")
		if err != nil || got != nil {
			t.Errorf("got %v, %v; want nil, nil", got, err)
		}
	})

	// Each of these would otherwise be discovered at request time, as a 502 with
	// nothing on screen to explain it, rather than at boot.
	for name, raw := range map[string]string{
		"malformed json":        `[{"header":`,
		"not an array":          `{"header":"A","label":"B"}`,
		"empty header name":     `[{"header":"","label":"Token"}]`,
		"invalid header name":   `[{"header":"Bad Header","label":"Token"}]`,
		"header with a colon":   `[{"header":"A:B","label":"Token"}]`,
		"missing label":         `[{"header":"Authorization","label":"  "}]`,
		"prefix with a newline": `[{"header":"Authorization","label":"Token","prefix":"Bearer \n"}]`,
		"duplicate field":       `[{"header":"A","label":"one"},{"header":"A","label":"two"}]`,
		// Case-insensitive, because HTTP header names are.
		"duplicate differing only in case": `[{"header":"a","label":"one"},{"header":"A","label":"two"}]`,
		"empty array":                      `[]`,
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := parseUserHeaderFields(raw); err == nil {
				t.Errorf("accepted %s", name)
			}
		})
	}
}

func TestDefaultDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"plane":   "Plane",
		"forgejo": "Forgejo",
		"git-mcp": "Git-mcp",
		"":        "",
	} {
		if got := defaultDisplayName(in); got != want {
			t.Errorf("defaultDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}
