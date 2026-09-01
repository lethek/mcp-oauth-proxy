package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/http/httpguts"
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

	// Targets is every upstream MCP server this proxy serves, always at least
	// one. A deployment configured the original way has a single unnamed target.
	Targets []Target

	// CIMDEnabled accepts an https client_id and fetches the client's metadata
	// from it, per draft-ietf-oauth-client-id-metadata-document.
	//
	// Off by default, and deliberately so. It makes this process fetch a URL the
	// caller chose, which is a network capability rather than a parsing change,
	// and it should be a decision someone made rather than something that
	// arrived with an upgrade. Clients negotiate on the advertised metadata, so
	// leaving it off simply keeps them on dynamic registration.
	CIMDEnabled bool

	// TrustedProxyHops is how many reverse proxies sit in front of this process.
	// It decides how far into X-Forwarded-For the rate limiter may read; see
	// clientKey. Zero means the header is ignored entirely.
	TrustedProxyHops int

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

// CredentialMode says how a target authenticates to its MCP server.
type CredentialMode string

const (
	// CredProviderToken forwards the provider's own token, the original behaviour.
	CredProviderToken CredentialMode = "provider_token"
	// CredStatic sends fixed headers instead, for a server with its own credential.
	CredStatic CredentialMode = "static"
	// CredPerUser sends headers each user supplied for themselves, so the MCP
	// server can tell one caller from another.
	CredPerUser CredentialMode = "per_user"
)

// UserHeaderField describes one value a user provides at /settings.
type UserHeaderField struct {
	// Header is the HTTP header the value becomes.
	Header string `json:"header"`
	// Label is what the enrolment form calls it.
	Label string `json:"label"`
	// Prefix is prepended when the header is built, so a user pastes a bare
	// token rather than having to type "Bearer " themselves.
	Prefix string `json:"prefix,omitempty"`
}

// targetNamePattern constrains names because they appear in URLs and in
// environment variable names.
var targetNamePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// Target is one upstream MCP server. A deployment serves one or several.
type Target struct {
	// Name is empty for a single-target deployment configured the original way,
	// which keeps serving /mcp. Named targets are served at /<name>/mcp.
	Name string

	// DisplayName is what a person sees on the enrolment page. Names are
	// constrained to lowercase because they appear in URLs, which reads badly in
	// a heading, so this carries the presentable form.
	DisplayName string

	UpstreamMCP   string
	Mode          CredentialMode
	StaticHeaders map[string]string

	// UserFields are the values a user supplies for themselves in per_user mode.
	UserFields []UserHeaderField

	// Resource is this target's RFC 8707 identifier and the audience of every
	// token issued for it. Computed once, because comparing it is on the path of
	// every proxied request.
	Resource string
}

// envPrefix maps a target name onto its variable prefix: "git-mcp" reads
// TARGET_GIT_MCP_*.
func envPrefix(name string) string {
	return "TARGET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// parseStaticHeaders reads newline-separated "Name: Value" pairs. Newlines
// rather than commas because header values routinely contain commas, and a
// YAML block scalar expresses this shape cleanly in a manifest.
func parseStaticHeaders(varName, raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf(varName+": %q is not \"Name: Value\"", line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf(varName+": empty header name in %q", line)
		}
		if value == "" {
			return nil, fmt.Errorf(varName+": %s has an empty value", name)
		}
		out[name] = value
	}
	return out, nil
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

	if raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXY_HOPS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("TRUSTED_PROXY_HOPS must be a non-negative integer, got %q", raw)
		}
		c.TrustedProxyHops = n
	}

	switch strings.ToLower(strings.TrimSpace(os.Getenv("CIMD_ENABLED"))) {
	case "", "false", "0", "no":
	case "true", "1", "yes":
		c.CIMDEnabled = true
	default:
		return nil, fmt.Errorf("CIMD_ENABLED must be true or false, got %q", os.Getenv("CIMD_ENABLED"))
	}

	if c.UpstreamScopes == "" {
		c.UpstreamScopes = "openid profile email"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}

	required := map[string]string{
		"PUBLIC_URL":             c.PublicURL,
		"UPSTREAM_ISSUER":        c.UpstreamIssuer,
		"UPSTREAM_CLIENT_ID":     c.UpstreamClientID,
		"UPSTREAM_CLIENT_SECRET": c.UpstreamClientSecret,
		"DATABASE_URL":           c.DatabaseURL,
	}
	// UPSTREAM_MCP_URL describes the single legacy target and is required only
	// when TARGETS is absent.
	if strings.TrimSpace(os.Getenv("TARGETS")) == "" {
		required["UPSTREAM_MCP_URL"] = c.UpstreamMCP
	}

	missing := []string{}
	for name, v := range required {
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

	// Every route is registered at the root and every advertised URL is built by
	// appending to this, so a path component would produce metadata and redirect
	// URIs that match nothing this process actually serves.
	if u, err := url.Parse(c.PublicURL); err == nil && u.Path != "" {
		return nil, fmt.Errorf("PUBLIC_URL must not have a path component, got %q", u.Path)
	}

	targets, err := parseTargets(c.PublicURL)
	if err != nil {
		return nil, err
	}
	c.Targets = targets

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

// parseTargets builds the target list from either the multi-target variables or
// the original flat ones.
//
// The two are mutually exclusive and setting both is an error rather than a
// precedence rule. A deployment that names TARGETS and also leaves an old
// UPSTREAM_MCP_URL in place is ambiguous about which upstream it means, and
// quietly picking one would route real traffic on a guess.
func parseTargets(publicURL string) ([]Target, error) {
	raw := strings.TrimSpace(os.Getenv("TARGETS"))
	legacyURL := strings.TrimRight(os.Getenv("UPSTREAM_MCP_URL"), "/")
	legacyHeaders := os.Getenv("UPSTREAM_STATIC_HEADERS")

	if raw == "" {
		headers, err := parseStaticHeaders("UPSTREAM_STATIC_HEADERS", legacyHeaders)
		if err != nil {
			return nil, err
		}
		t := Target{
			// Unnamed, so there is nothing to capitalise. The consent page still
			// has to call it something.
			DisplayName:   "the MCP server",
			UpstreamMCP:   legacyURL,
			Mode:          CredProviderToken,
			StaticHeaders: headers,
			Resource:      publicURL + "/mcp",
		}
		if len(headers) > 0 {
			t.Mode = CredStatic
		}
		if err := checkTargetURL("UPSTREAM_MCP_URL", t.UpstreamMCP); err != nil {
			return nil, err
		}
		return []Target{t}, nil
	}

	if legacyURL != "" || legacyHeaders != "" {
		return nil, fmt.Errorf("TARGETS cannot be combined with UPSTREAM_MCP_URL or UPSTREAM_STATIC_HEADERS; move them into TARGET_<NAME>_* variables")
	}

	var targets []Target
	seen := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !targetNamePattern.MatchString(name) {
			return nil, fmt.Errorf("TARGETS: %q is not a valid target name (lowercase letters, digits and hyphens)", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("TARGETS: %q is listed twice", name)
		}
		seen[name] = true

		p := envPrefix(name)
		t := Target{
			Name:        name,
			DisplayName: strings.TrimSpace(os.Getenv(p + "DISPLAY_NAME")),
			UpstreamMCP: strings.TrimRight(os.Getenv(p+"UPSTREAM_MCP_URL"), "/"),
			Mode:        CredentialMode(os.Getenv(p + "CREDENTIAL_MODE")),
			Resource:    publicURL + "/" + name + "/mcp",
		}
		if t.DisplayName == "" {
			t.DisplayName = defaultDisplayName(name)
		}
		if t.UpstreamMCP == "" {
			return nil, fmt.Errorf("missing required environment: %sUPSTREAM_MCP_URL", p)
		}
		if err := checkTargetURL(p+"UPSTREAM_MCP_URL", t.UpstreamMCP); err != nil {
			return nil, err
		}

		switch t.Mode {
		case "":
			t.Mode = CredProviderToken
		case CredProviderToken, CredStatic, CredPerUser:
		default:
			return nil, fmt.Errorf("%sCREDENTIAL_MODE: %q is not one of provider_token, static, per_user", p, t.Mode)
		}

		headers, err := parseStaticHeaders(p+"STATIC_HEADERS", os.Getenv(p+"STATIC_HEADERS"))
		if err != nil {
			return nil, err
		}
		if t.Mode == CredStatic && len(headers) == 0 {
			return nil, fmt.Errorf("%sSTATIC_HEADERS is required when %sCREDENTIAL_MODE is static", p, p)
		}
		if t.Mode != CredStatic && len(headers) > 0 {
			return nil, fmt.Errorf("%sSTATIC_HEADERS is set but %sCREDENTIAL_MODE is %s", p, p, t.Mode)
		}
		t.StaticHeaders = headers

		fields, err := parseUserHeaderFields(os.Getenv(p + "USER_HEADERS"))
		if err != nil {
			return nil, fmt.Errorf("%sUSER_HEADERS: %w", p, err)
		}
		if t.Mode == CredPerUser && len(fields) == 0 {
			return nil, fmt.Errorf("%sUSER_HEADERS is required when %sCREDENTIAL_MODE is per_user", p, p)
		}
		if t.Mode != CredPerUser && len(fields) > 0 {
			return nil, fmt.Errorf("%sUSER_HEADERS is set but %sCREDENTIAL_MODE is %s", p, p, t.Mode)
		}
		t.UserFields = fields

		targets = append(targets, t)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("TARGETS is set but names no targets")
	}
	return targets, nil
}

// defaultDisplayName capitalises the first letter, which is right for the
// ordinary single-word name. Anything else should set DISPLAY_NAME rather than
// have this guess at hyphens and acronyms.
func defaultDisplayName(name string) string {
	r := []rune(name)
	if len(r) == 0 {
		return name
	}
	return string(unicode.ToUpper(r[0])) + string(r[1:])
}

// parseUserHeaderFields reads the per-user field definitions. JSON rather than a
// delimited format, because each field carries three values and inventing
// separators for that is how a config format becomes a parser.
func parseUserHeaderFields(raw string) ([]UserHeaderField, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var fields []UserHeaderField
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	seen := map[string]bool{}
	for i, f := range fields {
		// Validated here rather than left to fail at request time, when the value
		// would be rejected by the transport and surface to a user as a 502 on
		// every call with nothing to point at.
		if !httpguts.ValidHeaderFieldName(f.Header) {
			return nil, fmt.Errorf("field %d has an invalid header name %q", i, f.Header)
		}
		if strings.TrimSpace(f.Label) == "" {
			return nil, fmt.Errorf("field %q has no label", f.Header)
		}
		if !httpguts.ValidHeaderFieldValue(f.Prefix) {
			return nil, fmt.Errorf("field %q has an invalid prefix", f.Header)
		}
		key := http.CanonicalHeaderKey(f.Header)
		if seen[key] {
			return nil, fmt.Errorf("field %q is listed twice", f.Header)
		}
		seen[key] = true
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("names no fields")
	}
	return fields, nil
}

// HasPerUserTargets reports whether the enrolment page has anything to offer.
func (c *Config) HasPerUserTargets() bool {
	for _, t := range c.Targets {
		if t.Mode == CredPerUser {
			return true
		}
	}
	return false
}

// checkTargetURL holds an MCP server to a weaker rule than a browser-facing URL
// on purpose. No browser goes there, and the common deployment puts it beside
// this proxy on a private network, where plain http is normal and demanding TLS
// would refuse a perfectly ordinary setup. It still carries a credential, so
// anything beyond loopback is worth saying out loud.
func checkTargetURL(name, raw string) error {
	if err := checkURL(raw, false); err != nil {
		return fmt.Errorf("%s is not usable: %w", name, err)
	}
	return nil
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

// isPlaintextURL reports whether an MCP hop runs unencrypted somewhere other
// than loopback, which is worth a line in the log at boot.
func isPlaintextURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "http" && !isLoopbackHost(u.Hostname())
}

func isLoopbackHost(host string) bool {
	// Case-folded and with a trailing root dot removed: url.Parse does neither,
	// so "LOCALHOST" and "localhost." were refused as though they were remote.
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ResourceURI is the canonical identifier of the MCP endpoint, used as the
// `resource` value in metadata and as the audience of the tokens we issue.
// Meaningful only for a single-target deployment.
func (c *Config) ResourceURI() string { return c.Targets[0].Resource }

// MultiTarget reports whether this deployment serves named targets. It governs
// two behaviours: whether the `resource` parameter is required at /authorize,
// and whether a session carrying no resource may be used at all.
func (c *Config) MultiTarget() bool { return c.Targets[0].Name != "" }

// TargetByResource finds the target a `resource` value names.
func (c *Config) TargetByResource(resource string) (Target, bool) {
	resource = strings.TrimRight(resource, "/")
	for _, t := range c.Targets {
		if t.Resource == resource {
			return t, true
		}
	}
	return Target{}, false
}

// ResourceList is every resource this proxy serves, for error messages.
func (c *Config) ResourceList() string {
	out := make([]string, 0, len(c.Targets))
	for _, t := range c.Targets {
		out = append(out, t.Resource)
	}
	return strings.Join(out, ", ")
}

// MetadataPath is where RFC 9728 says this target's protected-resource document
// lives: the resource's path, appended to the well-known prefix.
func (t Target) MetadataPath() string {
	if t.Name == "" {
		return "/.well-known/oauth-protected-resource/mcp"
	}
	return "/.well-known/oauth-protected-resource/" + t.Name + "/mcp"
}

// MCPPath is where clients reach this target.
func (t Target) MCPPath() string {
	if t.Name == "" {
		return "/mcp"
	}
	return "/" + t.Name + "/mcp"
}
