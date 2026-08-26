package main

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	valid := []string{
		"https://example.com/callback",
		"https://example.com:8443/cb?x=1",
		"http://127.0.0.1:1455/callback",
		"http://[::1]:1455/callback",
		"http://localhost/callback",
		"com.example.app:/oauth/callback",
		"com.example.app://callback",
	}
	for _, u := range valid {
		if err := validateRedirectURI(u); err != nil {
			t.Errorf("validateRedirectURI(%q) = %v, want nil", u, err)
		}
	}

	// Everything here is accepted by url.Parse, which is why the old check let
	// all of it through.
	invalid := []string{
		"",
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"/relative/path",
		"example.com/callback",
		"https://example.com/cb#fragment",
		"http://evil.example/callback",
		"http://127.0.0.1.evil.example/callback",
		"https:///nohost",
		"file:///etc/passwd",
	}
	for _, u := range invalid {
		if err := validateRedirectURI(u); err == nil {
			t.Errorf("validateRedirectURI(%q) = nil, want an error", u)
		}
	}
}

func TestCheckURLRequiringSecure(t *testing.T) {
	valid := []string{
		"https://proxy.example",
		"https://proxy.example:8443",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
	}
	for _, u := range valid {
		if err := checkURL(u, true); err != nil {
			t.Errorf("checkURL(%q, true) = %v, want nil", u, err)
		}
	}

	invalid := []string{
		"",
		"http://proxy.example",
		"proxy.example",
		"ftp://proxy.example",
		"https://",
	}
	for _, u := range invalid {
		if err := checkURL(u, true); err == nil {
			t.Errorf("checkURL(%q, true) = nil, want an error", u)
		}
	}
}

// TestCheckTransportURLAllowsPrivateHTTP guards the MCP hop's weaker rule. The
// ordinary deployment puts the MCP server next to this proxy on a private
// network, so demanding TLS there would refuse a perfectly normal setup.
func TestCheckURLAllowsPrivateHTTP(t *testing.T) {
	valid := []string{
		"http://forgejo-mcp:8080",
		"http://mcp.internal/mcp",
		"http://127.0.0.1:3000",
		"https://mcp.example.com",
	}
	for _, u := range valid {
		if err := checkURL(u, false); err != nil {
			t.Errorf("checkURL(%q, false) = %v, want nil", u, err)
		}
	}

	for _, u := range []string{"", "mcp.internal", "ftp://mcp.internal", "file:///mcp"} {
		if err := checkURL(u, false); err == nil {
			t.Errorf("checkURL(%q, false) = nil, want an error", u)
		}
	}

	// The same URL is still refused for the browser-facing settings.
	if err := checkURL("http://forgejo-mcp:8080", true); err == nil {
		t.Error("checkURL accepted plain http to a non-loopback host")
	}
}

func TestIsPlaintextUpstream(t *testing.T) {
	cases := map[string]bool{
		"http://forgejo-mcp:8080": true,
		"http://mcp.internal/mcp": true,
		"http://127.0.0.1:3000":   false,
		"http://localhost:3000":   false,
		"https://mcp.example.com": false,
	}
	for raw, want := range cases {
		c := &Config{UpstreamMCP: raw}
		if got := c.IsPlaintextUpstream(); got != want {
			t.Errorf("IsPlaintextUpstream(%q) = %v, want %v", raw, got, want)
		}
	}
}
