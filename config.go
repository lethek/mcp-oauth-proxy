package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is assembled entirely from the environment. Every field is required
// except Scopes, ListenAddr and the two lifetimes, which have defaults.
type Config struct {
	// PublicURL is the externally reachable origin of this proxy. It is both the
	// OAuth issuer we advertise and the base for every URL in our metadata, so it
	// must match what clients actually dial. No trailing slash.
	PublicURL string

	// PublicScheme and PublicOrigin are parsed out of PublicURL once, at load.
	//
	// Nothing may re-derive these from the raw string later. Validation parses
	// the URL, and Go lowercases a parsed scheme, so a raw-text check disagrees
	// with what was validated: a PUBLIC_URL of "HTTPS://host" validates as https
	// while a prefix test for "https://" says otherwise. PublicOrigin is also
	// canonical, with any default port removed, so it can be compared against a
	// browser's Origin header, which never carries one.
	PublicScheme string
	PublicOrigin string

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

	// RefreshTokenTTL is how long a refresh token stays usable since it was
	// issued. Rotation issues a fresh one, so this behaves as an idle timeout.
	RefreshTokenTTL time.Duration

	// SessionTTL caps how long a single authorization lasts no matter how
	// actively it is refreshed. Reaching it forces the user back through the
	// provider.
	SessionTTL time.Duration

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

	// A browser reaches both of these, and both carry credentials across whatever
	// network sits in between. An http origin is accepted only on loopback, where
	// there is nothing to intercept, so a misconfigured deployment fails at boot
	// rather than silently downgrading every token exchange.
	for name, raw := range map[string]string{
		"PUBLIC_URL":      c.PublicURL,
		"UPSTREAM_ISSUER": c.UpstreamIssuer,
	} {
		if err := checkURL(raw, true); err != nil {
			return nil, fmt.Errorf("%s is not usable: %w", name, err)
		}
	}

	if err := c.derivePublic(); err != nil {
		return nil, fmt.Errorf("PUBLIC_URL is not usable: %w", err)
	}

	// The MCP server is held to a weaker rule on purpose. No browser goes there,
	// and the common deployment puts it alongside this proxy on a private
	// network, where plain http is normal and demanding TLS would refuse a
	// perfectly ordinary setup. It still carries a bearer token, so anything
	// beyond loopback is worth saying out loud.
	if err := checkURL(c.UpstreamMCP, false); err != nil {
		return nil, fmt.Errorf("UPSTREAM_MCP_URL is not usable: %w", err)
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

	if c.RefreshTokenTTL, err = durationEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = durationEnv("SESSION_TTL", 90*24*time.Hour); err != nil {
		return nil, err
	}
	if c.SessionTTL < c.RefreshTokenTTL {
		return nil, fmt.Errorf("SESSION_TTL (%s) must not be shorter than REFRESH_TOKEN_TTL (%s)", c.SessionTTL, c.RefreshTokenTTL)
	}

	return c, nil
}

func durationEnv(name string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", name, d)
	}
	return d, nil
}

// secureTransport is the one place the rule lives: https carries credentials
// anywhere, http only on loopback where there is no network to intercept.
// Callers wrap the message with whatever they are describing.
//
// It takes a parsed URL because every caller has already parsed one.
func secureTransport(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("uses http against a non-loopback host; use https")
	default:
		return fmt.Errorf("uses unsupported scheme %q", u.Scheme)
	}
}

// checkURL validates a configured URL. With requireSecure it demands the
// transport rule above; without it, any absolute http or https URL passes,
// which is what a server-to-server hop on the operator's own network needs.
func checkURL(raw string, requireSecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", raw)
	}
	if !requireSecure {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%q uses unsupported scheme %q", raw, u.Scheme)
		}
		return nil
	}
	if err := secureTransport(u); err != nil {
		return fmt.Errorf("%q %w", raw, err)
	}
	return nil
}

// derivePublic records the scheme and canonical origin of PublicURL, so that
// the cookie's Secure attribute and the consent Origin check both read what was
// validated rather than re-parsing the string their own way.
func (c *Config) derivePublic() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", c.PublicURL)
	}
	c.PublicScheme = u.Scheme
	c.PublicOrigin = canonicalOrigin(u)
	return nil
}

// canonicalOrigin renders a URL the way a browser writes the Origin header:
// scheme, host, and a port only when it is not the default for that scheme.
// Comparing raw url.Host instead would reject every request from a deployment
// whose PUBLIC_URL spells out :443.
func canonicalOrigin(u *url.URL) string {
	host := strings.ToLower(u.Host)
	switch {
	case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return u.Scheme + "://" + host
}

// IsPlaintextUpstream reports whether the MCP hop runs unencrypted somewhere
// other than loopback, which is worth a line in the log at boot.
func (c *Config) IsPlaintextUpstream() bool {
	u, err := url.Parse(c.UpstreamMCP)
	if err != nil {
		return false
	}
	return u.Scheme == "http" && !isLoopbackHost(u.Hostname())
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ResourceURI is the canonical identifier of the MCP endpoint, used as the
// `resource` value in metadata and as the audience of the tokens we issue.
func (c *Config) ResourceURI() string { return c.PublicURL + "/mcp" }
