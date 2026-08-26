package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Config is assembled entirely from the environment. Every field is required
// except Scopes and ListenAddr, which have defaults.
type Config struct {
	// PublicURL is the externally reachable origin of this proxy. It is both the
	// OAuth issuer we advertise and the base for every URL in our metadata, so it
	// must match what clients actually dial. No trailing slash.
	PublicURL string

	// UpstreamMCP is the MCP server we forward to once a request is authorized.
	UpstreamMCP string

	// Upstream* describe the OAuth provider that actually authenticates people.
	// The client credentials are for a single application registered by hand with
	// that provider; every downstream MCP client shares them, which is the whole
	// point of this proxy.
	UpstreamIssuer       string
	UpstreamClientID     string
	UpstreamClientSecret string
	UpstreamScopes       string

	DatabaseURL string

	// EncryptionKey protects upstream tokens at rest. 32 bytes, base64.
	EncryptionKey []byte

	ListenAddr string
}

func LoadConfig() (*Config, error) {
	c := &Config{
		PublicURL:            strings.TrimRight(os.Getenv("PUBLIC_URL"), "/"),
		UpstreamMCP:          strings.TrimRight(os.Getenv("UPSTREAM_MCP_URL"), "/"),
		UpstreamIssuer:       strings.TrimRight(os.Getenv("UPSTREAM_ISSUER"), "/"),
		UpstreamClientID:     os.Getenv("UPSTREAM_CLIENT_ID"),
		UpstreamClientSecret: os.Getenv("UPSTREAM_CLIENT_SECRET"),
		UpstreamScopes:       os.Getenv("UPSTREAM_SCOPES"),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		ListenAddr:           os.Getenv("LISTEN_ADDR"),
	}

	if c.UpstreamScopes == "" {
		c.UpstreamScopes = "openid profile email"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}

	missing := []string{}
	for name, v := range map[string]string{
		"PUBLIC_URL":             c.PublicURL,
		"UPSTREAM_MCP_URL":       c.UpstreamMCP,
		"UPSTREAM_ISSUER":        c.UpstreamIssuer,
		"UPSTREAM_CLIENT_ID":     c.UpstreamClientID,
		"UPSTREAM_CLIENT_SECRET": c.UpstreamClientSecret,
		"DATABASE_URL":           c.DatabaseURL,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}

	rawKey := os.Getenv("ENCRYPTION_KEY")
	if rawKey == "" {
		return nil, fmt.Errorf("missing required environment: ENCRYPTION_KEY")
	}
	key, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY is not valid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must decode to 32 bytes, got %d", len(key))
	}
	c.EncryptionKey = key

	return c, nil
}

// ResourceURI is the canonical identifier of the MCP endpoint, used as the
// `resource` value in metadata and as the audience of the tokens we issue.
func (c *Config) ResourceURI() string { return c.PublicURL + "/mcp" }
