package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
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

	// Targets is every upstream MCP server the environment defines. A deployment
	// configured the original way has a single unnamed target. It is empty only
	// when admin targets are enabled, which is what supplies the rest.
	Targets []Target

	// AdminSubjects and AdminGroups say who may manage targets from the web page.
	// Setting either enables the feature. Both live in the environment so nobody
	// can grant themselves admin through the page.
	AdminSubjects []string
	AdminGroups   []string

	// AllowedUpstreamHosts and AllowedUpstreamNetworks bound where an admin target
	// may point. They are independent: a listed host does not open any address
	// range, and a listed network does not authorise any host. Neither applies to
	// config targets, which the operator controls.
	AllowedUpstreamHosts    []hostPattern
	AllowedUpstreamNetworks []netip.Prefix

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

	// TrustedProxyCIDRs are the networks those proxies connect from. The header
	// is read only when the peer is inside one of them, so a caller that reaches
	// this process directly cannot choose its own rate-limit bucket. Required
	// whenever TrustedProxyHops is non-zero.
	TrustedProxyCIDRs []*net.IPNet

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

	// AllowedGroups limits authorization for this target to members of at least
	// one of these provider groups. Empty admits everyone the provider admits.
	// It matters most for a static target, where every caller acts with the same
	// credential and nothing upstream tells them apart.
	AllowedGroups []string

	// Resource is this target's RFC 8707 identifier and the audience of every
	// token issued for it. Computed once, because comparing it is on the path of
	// every proxied request.
	Resource string

	// Source is SourceAdmin for a target stored in the database and empty (config)
	// otherwise. Generation is the random id of an admin target's row, re-rolled
	// on every replacement, and is empty for config. Both feed Stamp.
	Source     string
	Generation string
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

	for _, part := range strings.Split(os.Getenv("TRUSTED_PROXY_CIDRS"), ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS must be a comma-separated list of networks in CIDR notation, got %q", p)
		}
		c.TrustedProxyCIDRs = append(c.TrustedProxyCIDRs, n)
	}

	// Counting hops says how far into the header to read; it says nothing about
	// who wrote it. Without the networks the proxies connect from, anything that
	// can reach this process directly supplies its own X-Forwarded-For and picks
	// whichever rate-limit bucket it likes, which is worse than not reading the
	// header at all. Refuse at boot rather than serve that.
	if c.TrustedProxyHops > 0 && len(c.TrustedProxyCIDRs) == 0 {
		return nil, fmt.Errorf("TRUSTED_PROXY_HOPS is set, so TRUSTED_PROXY_CIDRS must name the networks the proxies connect from")
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
	if err := c.loadAdmin(); err != nil {
		return nil, err
	}

	// UPSTREAM_MCP_URL describes the single legacy target and is required only
	// when TARGETS is absent, and not even then when admin targets will supply
	// the targets.
	unnamed := strings.TrimSpace(os.Getenv("TARGETS")) == ""
	if unnamed && !c.AdminEnabled() {
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
	// appending to this, so anything after the origin lands in the middle of what
	// this process publishes. A path produces metadata and redirect URIs matching
	// nothing it serves; a query or fragment is worse, because the suffix is
	// swallowed by it and "https://proxy.example?x=1" + "/callback" is a redirect
	// URI pointing at the root with a nonsense parameter.
	if u, err := url.Parse(c.PublicURL); err == nil {
		switch {
		case u.Path != "":
			return nil, fmt.Errorf("PUBLIC_URL must not have a path component, got %q", u.Path)
		case u.RawQuery != "" || u.ForceQuery:
			return nil, fmt.Errorf("PUBLIC_URL must not have a query string, got %q", u.RawQuery)
		case u.Fragment != "":
			return nil, fmt.Errorf("PUBLIC_URL must not have a fragment, got %q", u.Fragment)
		case u.User != nil:
			// PublicOrigin is derived from u.Host, which drops these, so the origin
			// this process compares against would not be the string it advertises.
			return nil, fmt.Errorf("PUBLIC_URL must not carry credentials")
		}
	}

	switch {
	case !unnamed || !c.AdminEnabled():
		targets, err := parseTargets(c.PublicURL)
		if err != nil {
			return nil, err
		}
		c.Targets = targets
	case c.UpstreamMCP != "" || os.Getenv("UPSTREAM_STATIC_HEADERS") != "":
		// The unnamed target serves /mcp, and adding a second target flips the
		// meaning of the resource parameter and of resource-less sessions.
		return nil, fmt.Errorf("ADMIN_SUBJECTS and ADMIN_GROUPS need named targets, so they cannot be combined with UPSTREAM_MCP_URL or UPSTREAM_STATIC_HEADERS; move those into TARGETS and TARGET_<NAME>_* variables")
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

// AdminEnabled reports whether targets can be managed from the web page.
func (c *Config) AdminEnabled() bool {
	return len(c.AdminSubjects) > 0 || len(c.AdminGroups) > 0
}

// NamedMode reports whether this deployment serves named targets at
// /<name>/mcp, as opposed to one unnamed target at /mcp. It is fixed by the
// configuration, not by what happens to be in the registry, so a deployment
// whose admin targets are all removed is still named.
func (c *Config) NamedMode() bool {
	return c.AdminEnabled() || (len(c.Targets) > 0 && c.Targets[0].Name != "")
}

// loadAdmin reads the variables that switch on admin-managed targets. The
// feature has no safe default for where targets may point, so enabling it
// without ALLOWED_UPSTREAM_HOSTS is refused rather than left open.
func (c *Config) loadAdmin() error {
	var err error
	if c.AdminSubjects, err = commaList("ADMIN_SUBJECTS"); err != nil {
		return err
	}
	if c.AdminGroups, err = commaList("ADMIN_GROUPS"); err != nil {
		return err
	}

	hosts, err := commaList("ALLOWED_UPSTREAM_HOSTS")
	if err != nil {
		return err
	}
	for _, h := range hosts {
		p, err := parseHostPattern(h)
		if err != nil {
			return fmt.Errorf("ALLOWED_UPSTREAM_HOSTS: %w", err)
		}
		c.AllowedUpstreamHosts = append(c.AllowedUpstreamHosts, p)
	}

	nets, err := commaList("ALLOWED_UPSTREAM_NETWORKS")
	if err != nil {
		return err
	}
	for _, n := range nets {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return fmt.Errorf("ALLOWED_UPSTREAM_NETWORKS must be a comma-separated list of networks in CIDR notation, got %q", n)
		}
		c.AllowedUpstreamNetworks = append(c.AllowedUpstreamNetworks, p.Masked())
	}

	if !c.AdminEnabled() {
		return nil
	}
	if len(c.AllowedUpstreamHosts) == 0 {
		return fmt.Errorf("ADMIN_SUBJECTS or ADMIN_GROUPS is set, so ALLOWED_UPSTREAM_HOSTS must list the host:port pairs admin targets may use")
	}
	// Some providers send groups only when the scope is requested, so this is a
	// warning: the first admin sign-in finds out if the claim never arrives.
	if len(c.AdminGroups) > 0 && !slices.Contains(strings.Fields(c.UpstreamScopes), "groups") {
		slog.Warn("ADMIN_GROUPS is set but UPSTREAM_SCOPES has no groups scope; the provider may not send the groups claim")
	}
	return nil
}

// commaList reads a comma-separated variable. A value that is set but names
// nothing is an error, because for an access list "empty" would silently mean
// "feature off" or "no restriction".
func commaList(name string) ([]string, error) {
	raw := os.Getenv(name)
	out := splitList(raw)
	if strings.TrimSpace(raw) != "" && len(out) == 0 {
		return nil, fmt.Errorf("%s is set but names nothing", name)
	}
	return out, nil
}

// splitList splits a comma-separated value, trimming each entry and dropping
// empty ones. It returns nil when nothing is left.
func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseHostPattern reads one host:port entry. The port is required because a
// name alone would also admit every other service on that machine.
func parseHostPattern(raw string) (hostPattern, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return hostPattern{}, fmt.Errorf("%q is not host:port", raw)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return hostPattern{}, fmt.Errorf("%q has an invalid port", raw)
	}
	if host == "" || strings.ContainsAny(host, "/@*? \t") {
		return hostPattern{}, fmt.Errorf("%q has an invalid host", raw)
	}
	return hostPattern{Host: strings.ToLower(host), Port: port}, nil
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
		if err := validateTarget(t); err != nil {
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
		// Checked before the variables are read, so a bad name is reported as
		// such rather than as a missing TARGET_<NAME>_UPSTREAM_MCP_URL.
		if err := validateTargetName(name); err != nil {
			return nil, err
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

		if t.Mode == "" {
			t.Mode = CredProviderToken
		}

		headers, err := parseStaticHeaders(p+"STATIC_HEADERS", os.Getenv(p+"STATIC_HEADERS"))
		if err != nil {
			return nil, err
		}
		t.StaticHeaders = headers

		fields, err := parseUserHeaderFields(os.Getenv(p + "USER_HEADERS"))
		if err != nil {
			return nil, fmt.Errorf("%sUSER_HEADERS: %w", p, err)
		}
		t.UserFields = fields

		rawGroups := os.Getenv(p + "ALLOWED_GROUPS")
		t.AllowedGroups = splitList(rawGroups)
		// A value that names no group would otherwise read as "no restriction",
		// opening the target to everyone while the config says it is limited.
		if strings.TrimSpace(rawGroups) != "" && len(t.AllowedGroups) == 0 {
			return nil, fmt.Errorf("%sALLOWED_GROUPS is set but names no groups", p)
		}

		if err := validateTarget(t); err != nil {
			return nil, err
		}
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
	if err := validateUserFields(fields); err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("names no fields")
	}
	return fields, nil
}

func validateUserFields(fields []UserHeaderField) error {
	seen := map[string]bool{}
	for i, f := range fields {
		// Validated here rather than left to fail at request time, when the value
		// would be rejected by the transport and surface to a user as a 502 on
		// every call with nothing to point at.
		if !httpguts.ValidHeaderFieldName(f.Header) {
			return fmt.Errorf("field %d has an invalid header name %q", i, f.Header)
		}
		if strings.TrimSpace(f.Label) == "" {
			return fmt.Errorf("field %q has no label", f.Header)
		}
		if !httpguts.ValidHeaderFieldValue(f.Prefix) {
			return fmt.Errorf("field %q has an invalid prefix", f.Header)
		}
		key := http.CanonicalHeaderKey(f.Header)
		if seen[key] {
			return fmt.Errorf("field %q is listed twice", f.Header)
		}
		seen[key] = true
	}
	return nil
}

func validateTargetName(name string) error {
	if !targetNamePattern.MatchString(name) {
		return fmt.Errorf("TARGETS: %q is not a valid target name (lowercase letters, digits and hyphens)", name)
	}
	return nil
}

// validateTarget holds the rules every target must meet, wherever it was
// defined, so the environment parser and the admin handlers cannot drift apart.
// The messages name the environment variables, which suits the boot path.
func validateTarget(t Target) error {
	p := "UPSTREAM_"
	if t.Name != "" {
		if err := validateTargetName(t.Name); err != nil {
			return err
		}
		p = envPrefix(t.Name)
	}
	if strings.TrimSpace(t.DisplayName) == "" {
		return fmt.Errorf("%sDISPLAY_NAME is empty", p)
	}

	switch t.Mode {
	case CredProviderToken, CredStatic, CredPerUser:
	default:
		return fmt.Errorf("%sCREDENTIAL_MODE: %q is not one of provider_token, static, per_user", p, t.Mode)
	}

	// A name or value the transport rejects would otherwise surface as a 502 on
	// every proxied call, with nothing to point at. RFC 9110 section 5.
	// Names that differ only in case are one header, and a map would send
	// whichever came first in iteration order.
	canonical := map[string]bool{}
	for name, value := range t.StaticHeaders {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("%sSTATIC_HEADERS: %q is not a valid header name", p, name)
		}
		key := http.CanonicalHeaderKey(name)
		if canonical[key] {
			return fmt.Errorf("%sSTATIC_HEADERS: %s is listed twice", p, key)
		}
		canonical[key] = true
		if !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("%sSTATIC_HEADERS: the value of %s is not a valid header value", p, name)
		}
	}
	if t.Mode == CredStatic && len(t.StaticHeaders) == 0 {
		return fmt.Errorf("%sSTATIC_HEADERS is required when %sCREDENTIAL_MODE is static", p, p)
	}
	if t.Mode != CredStatic && len(t.StaticHeaders) > 0 {
		return fmt.Errorf("%sSTATIC_HEADERS is set but %sCREDENTIAL_MODE is %s", p, p, t.Mode)
	}

	if err := validateUserFields(t.UserFields); err != nil {
		return fmt.Errorf("%sUSER_HEADERS: %w", p, err)
	}
	if t.Mode == CredPerUser && len(t.UserFields) == 0 {
		return fmt.Errorf("%sUSER_HEADERS is required when %sCREDENTIAL_MODE is per_user", p, p)
	}
	if t.Mode != CredPerUser && len(t.UserFields) > 0 {
		return fmt.Errorf("%sUSER_HEADERS is set but %sCREDENTIAL_MODE is %s", p, p, t.Mode)
	}

	// An empty group would match a provider group with no name, or read as no
	// restriction, either of which is not what a limited target means.
	for _, g := range t.AllowedGroups {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("%sALLOWED_GROUPS contains an empty group", p)
		}
	}
	return nil
}

// Admits reports whether someone in these groups may authorize for the target.
func (t Target) Admits(groups []string) bool {
	if len(t.AllowedGroups) == 0 {
		return true
	}
	for _, g := range groups {
		if slices.Contains(t.AllowedGroups, g) {
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
