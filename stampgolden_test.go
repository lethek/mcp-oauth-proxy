package main

import "testing"

// Config stamps are stored in every flow, session and credential row, so any
// change to them signs everyone out. These values were computed by v0.13.0 and
// are pinned byte for byte; a diff here is a migration, never a refactor.
func TestConfigStampsAreByteIdenticalToV0130(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		want   string
	}{
		{"unnamed", Target{UpstreamMCP: "http://mcp.internal:8080", Mode: CredProviderToken}, "config:619a957f3d4b8d0f0068a67fc7dbfe603cad73c569e1c45a712e1737ee1d0f5b"},
		{"provider_token", Target{Name: "forgejo", UpstreamMCP: "https://forgejo.example/mcp", Mode: CredProviderToken}, "config:ef4b0f14d2fa02078598dc970b6c7883b920879e75058647d1720e1f11c0dfdd"},
		{"static", Target{Name: "docs", UpstreamMCP: "https://docs.example/mcp", Mode: CredStatic,
			StaticHeaders: map[string]string{"Authorization": "Bearer x"}}, "config:c95dd0dee91a005787c5743f4f9849a57b19876c25828dc94be44f1ef610ab8e"},
		{"per_user", baseTarget(), "config:29f3b053863742356e4ee191c0709402ad1ad4e92468a3a5ffdb7400588079ab"},
		{"odd bytes", Target{Name: "odd", UpstreamMCP: "https://h.example/\xff\"é", Mode: CredPerUser,
			UserFields: []UserHeaderField{{Header: "X-Key", Label: "Key", Prefix: "T \x00"}}}, "config:7c894ecd982aa95bb94a5106145b5ac9b80d39bc58f3791b0e873bb815133f3d"},
	}
	for _, c := range cases {
		if got := c.target.Stamp(); got != c.want {
			t.Errorf("%s: stamp = %q, want %q", c.name, got, c.want)
		}
	}
}
