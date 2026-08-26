package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// upstreamMeta is the subset of the provider's discovery document we use.
type upstreamMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// UpstreamToken is what the provider hands back, and what we store encrypted.
type UpstreamToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

func (t UpstreamToken) expired() bool {
	// Treat anything within a minute of expiry as expired, so a request does not
	// race the clock between our check and the upstream API's.
	return !t.ExpiresAt.IsZero() && time.Now().Add(time.Minute).After(t.ExpiresAt)
}

type Upstream struct {
	cfg  *Config
	http *http.Client

	mu   sync.RWMutex
	meta *upstreamMeta
}

func NewUpstream(cfg *Config) *Upstream {
	return &Upstream{cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}}
}

// Meta fetches and caches the provider's OIDC discovery document. Forgejo
// serves openid-configuration but not oauth-authorization-server, so we try the
// OIDC path first and fall back rather than assuming either.
func (u *Upstream) Meta(ctx context.Context) (*upstreamMeta, error) {
	u.mu.RLock()
	m := u.meta
	u.mu.RUnlock()
	if m != nil {
		return m, nil
	}

	var lastErr error
	for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.cfg.UpstreamIssuer+p, nil)
		if err != nil {
			return nil, err
		}
		resp, err := u.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s returned %d", p, resp.StatusCode)
			continue
		}
		var got upstreamMeta
		if err := json.Unmarshal(body, &got); err != nil {
			lastErr = err
			continue
		}
		if got.AuthorizationEndpoint == "" || got.TokenEndpoint == "" {
			lastErr = fmt.Errorf("%s lacked authorization or token endpoint", p)
			continue
		}
		u.mu.Lock()
		u.meta = &got
		u.mu.Unlock()
		return &got, nil
	}
	return nil, fmt.Errorf("upstream discovery failed: %w", lastErr)
}

// AuthorizeURL builds the URL we send the browser to. The state we pass is our
// own flow id; the client's state never leaves our database.
func (u *Upstream) AuthorizeURL(ctx context.Context, state, verifier string) (string, error) {
	m, err := u.Meta(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", u.cfg.UpstreamClientID)
	q.Set("redirect_uri", u.cfg.PublicURL+"/callback")
	q.Set("state", state)
	q.Set("scope", u.cfg.UpstreamScopes)
	q.Set("code_challenge", s256(verifier))
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(m.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return m.AuthorizationEndpoint + sep + q.Encode(), nil
}

func (u *Upstream) Exchange(ctx context.Context, code, verifier string) (UpstreamToken, error) {
	return u.postToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {u.cfg.PublicURL + "/callback"},
		"code_verifier": {verifier},
	})
}

func (u *Upstream) Refresh(ctx context.Context, refreshToken string) (UpstreamToken, error) {
	return u.postToken(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func (u *Upstream) postToken(ctx context.Context, form url.Values) (UpstreamToken, error) {
	var out UpstreamToken
	m, err := u.Meta(ctx)
	if err != nil {
		return out, err
	}

	form.Set("client_id", u.cfg.UpstreamClientID)
	form.Set("client_secret", u.cfg.UpstreamClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := u.http.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("upstream token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return out, fmt.Errorf("upstream token response was not JSON: %w", err)
	}
	if raw.AccessToken == "" {
		return out, fmt.Errorf("upstream token response carried no access_token")
	}

	out = UpstreamToken{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
	}
	if raw.ExpiresIn > 0 {
		out.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return out, nil
}

// Subject asks the provider who the token belongs to, so a session can be tied
// to a person for auditing and revocation. Best effort by design: a provider
// without a userinfo endpoint must not stop anyone logging in, so the caller
// treats an empty result as "unknown" rather than as a failure.
func (u *Upstream) Subject(ctx context.Context, accessToken string) (string, error) {
	m, err := u.Meta(ctx)
	if err != nil {
		return "", err
	}
	if m.UserinfoEndpoint == "" {
		return "", nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.UserinfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := u.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return "", fmt.Errorf("userinfo response was not JSON: %w", err)
	}

	// sub is the stable identifier; the friendlier claims only decorate it so a
	// log line is readable without a second lookup. Choosing the decoration
	// first states the username-beats-email preference once, rather than leaving
	// it implicit in the order of a longer switch.
	name := claims.PreferredUsername
	if name == "" {
		name = claims.Email
	}
	switch {
	case claims.Sub != "" && name != "":
		return claims.Sub + " (" + name + ")", nil
	case claims.Sub != "":
		return claims.Sub, nil
	default:
		return name, nil
	}
}
