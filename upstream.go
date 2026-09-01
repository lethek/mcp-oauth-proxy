package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
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

// discoveryRetryAfter is how long a failed discovery is remembered. Without it,
// every request that needs the provider retries both well-known paths itself,
// so an outage turns each waiting caller into two more attempts against a
// provider that is already struggling, and each of them waits out the client
// timeout twice before failing.
const discoveryRetryAfter = 5 * time.Second

type Upstream struct {
	cfg  *Config
	http *http.Client

	mu       sync.RWMutex
	meta     *upstreamMeta
	failedAt time.Time
	failErr  error
}

func NewUpstream(cfg *Config) *Upstream {
	return &Upstream{cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}}
}

// Meta fetches and caches the provider's OIDC discovery document. Forgejo
// serves openid-configuration but not oauth-authorization-server, so we try the
// OIDC path first and fall back rather than assuming either.
func (u *Upstream) Meta(ctx context.Context) (*upstreamMeta, error) {
	u.mu.RLock()
	m, failedAt, failErr := u.meta, u.failedAt, u.failErr
	u.mu.RUnlock()
	if m != nil {
		return m, nil
	}
	if failErr != nil && time.Since(failedAt) < discoveryRetryAfter {
		return nil, failErr
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
		u.failErr = nil
		u.mu.Unlock()
		return &got, nil
	}

	err := fmt.Errorf("upstream discovery failed: %w", lastErr)
	u.mu.Lock()
	u.failedAt = time.Now()
	u.failErr = err
	u.mu.Unlock()
	return nil, err
}

// FormActionOrigins names every origin a consent submission may legitimately
// end up at.
//
// The browser checks form-action against each hop of the redirect chain that
// follows a submission, not just its immediate target, so the provider's
// authorization endpoint has to be named or the redirect after approval is
// blocked and the page simply sits there. Bouncing through a same-origin URL
// first does not help, for the same reason.
//
// The endpoint's own origin is preferred, since a provider may host it on a
// different host from its issuer. The issuer is included as well, to cover the
// case where discovery has not answered yet.
func (u *Upstream) FormActionOrigins(ctx context.Context) []string {
	var origins []string
	add := func(raw string) {
		p, err := url.Parse(raw)
		if err != nil || p.Host == "" {
			return
		}
		if o := canonicalOrigin(p); !slices.Contains(origins, o) {
			origins = append(origins, o)
		}
	}

	add(u.cfg.UpstreamIssuer)
	if m, err := u.Meta(ctx); err == nil {
		add(m.AuthorizationEndpoint)
	}
	return origins
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
	return u.ExchangeWithRedirect(ctx, code, verifier, u.cfg.PublicURL+"/callback")
}

// ExchangeWithRedirect exists because the settings page runs its own login and
// returns to a different path. The redirect_uri must match the one the
// authorization request used, so it cannot be assumed.
func (u *Upstream) ExchangeWithRedirect(ctx context.Context, code, verifier, redirectURI string) (UpstreamToken, error) {
	return u.postToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
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
// UserIdentity separates the stable identifier from the readable decoration, so
// a caller cannot accidentally key storage on something that changes.
type UserIdentity struct {
	// Subject is the OIDC sub claim. Durable rows are keyed on this.
	Subject string
	// Display is preferred_username or email, for logs and the settings page.
	Display string
}

// Label is the readable form, used only where a human reads it.
func (u UserIdentity) Label() string {
	if u.Display == "" {
		return u.Subject
	}
	return u.Subject + " (" + u.Display + ")"
}

func (u *Upstream) Identity(ctx context.Context, accessToken string) (UserIdentity, error) {
	m, err := u.Meta(ctx)
	if err != nil {
		return UserIdentity{}, err
	}
	if m.UserinfoEndpoint == "" {
		return UserIdentity{}, errors.New("the provider publishes no userinfo endpoint, so users cannot be identified")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.UserinfoEndpoint, nil)
	if err != nil {
		return UserIdentity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := u.http.Do(req)
	if err != nil {
		return UserIdentity{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return UserIdentity{}, fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return UserIdentity{}, fmt.Errorf("userinfo response was not JSON: %w", err)
	}

	// Only sub identifies the account. It is the one claim OIDC requires to be
	// stable and never reassigned, and it is what durable rows are keyed on.
	//
	// The friendlier claims are returned separately, for logs and for the
	// settings page. They must not be folded into the identifier: a username is
	// mutable, so a rename would silently orphan everything stored under the old
	// value, and where a provider omits sub entirely a reused username would
	// inherit the previous holder's stored credentials.
	name := claims.PreferredUsername
	if name == "" {
		name = claims.Email
	}
	if claims.Sub == "" {
		return UserIdentity{}, errors.New("userinfo returned no sub claim, so there is no stable identifier to key on")
	}
	return UserIdentity{Subject: claims.Sub, Display: name}, nil
}
