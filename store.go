package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

const (
	flowTTL = 10 * time.Minute
	codeTTL = 60 * time.Second
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

// migrate is deliberately a single idempotent statement block rather than a
// migration framework. The schema is small and this runs on every boot.
func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT[] NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    subject        TEXT NOT NULL DEFAULT '',
    upstream_token BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- An in-flight authorization: created when the client hits /authorize and
-- consumed when the upstream provider redirects back to /callback.
CREATE TABLE IF NOT EXISTS flows (
    id                TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    redirect_uri      TEXT NOT NULL,
    client_state      TEXT NOT NULL DEFAULT '',
    code_challenge    TEXT NOT NULL,
    upstream_verifier TEXT NOT NULL,
    resource          TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash      BYTEA PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    resource       TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash BYTEA PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash BYTEA PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`)
	return err
}

// ---------- clients ----------

type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
}

func (s *Store) CreateClient(ctx context.Context, c Client) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO clients (client_id, client_name, redirect_uris) VALUES ($1,$2,$3)`,
		c.ID, c.Name, c.RedirectURIs)
	return err
}

func (s *Store) GetClient(ctx context.Context, id string) (Client, error) {
	var c Client
	err := s.pool.QueryRow(ctx,
		`SELECT client_id, client_name, redirect_uris FROM clients WHERE client_id=$1`, id).
		Scan(&c.ID, &c.Name, &c.RedirectURIs)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// ---------- flows ----------

type Flow struct {
	ID               string
	ClientID         string
	RedirectURI      string
	ClientState      string
	CodeChallenge    string
	UpstreamVerifier string
	Resource         string
}

func (s *Store) CreateFlow(ctx context.Context, f Flow) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO flows (id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, resource)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		f.ID, f.ClientID, f.RedirectURI, f.ClientState, f.CodeChallenge, f.UpstreamVerifier, f.Resource)
	return err
}

// TakeFlow fetches and deletes a flow in one statement, so a replayed callback
// finds nothing.
func (s *Store) TakeFlow(ctx context.Context, id string) (Flow, error) {
	var f Flow
	err := s.pool.QueryRow(ctx,
		`DELETE FROM flows WHERE id=$1 AND created_at > now() - $2::interval
		 RETURNING id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, resource`,
		id, flowTTL.String()).
		Scan(&f.ID, &f.ClientID, &f.RedirectURI, &f.ClientState, &f.CodeChallenge, &f.UpstreamVerifier, &f.Resource)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

// ---------- sessions ----------

func (s *Store) CreateSession(ctx context.Context, id, subject string, sealedToken []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, subject, upstream_token) VALUES ($1,$2,$3)`,
		id, subject, sealedToken)
	return err
}

func (s *Store) SessionToken(ctx context.Context, id string) ([]byte, error) {
	var b []byte
	err := s.pool.QueryRow(ctx, `SELECT upstream_token FROM sessions WHERE id=$1`, id).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *Store) UpdateSessionToken(ctx context.Context, id string, sealedToken []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET upstream_token=$2, updated_at=now() WHERE id=$1`, id, sealedToken)
	return err
}

// ---------- authorization codes ----------

type AuthCode struct {
	SessionID     string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
}

func (s *Store) CreateAuthCode(ctx context.Context, code string, a AuthCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_codes (code_hash, session_id, client_id, redirect_uri, code_challenge, resource)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		hashToken(code), a.SessionID, a.ClientID, a.RedirectURI, a.CodeChallenge, a.Resource)
	return err
}

// TakeAuthCode enforces single use by deleting on read.
func (s *Store) TakeAuthCode(ctx context.Context, code string) (AuthCode, error) {
	var a AuthCode
	err := s.pool.QueryRow(ctx,
		`DELETE FROM auth_codes WHERE code_hash=$1 AND created_at > now() - $2::interval
		 RETURNING session_id, client_id, redirect_uri, code_challenge, resource`,
		hashToken(code), codeTTL.String()).
		Scan(&a.SessionID, &a.ClientID, &a.RedirectURI, &a.CodeChallenge, &a.Resource)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// ---------- bearer tokens ----------

func (s *Store) CreateAccessToken(ctx context.Context, token, sessionID, clientID string, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO access_tokens (token_hash, session_id, client_id, expires_at) VALUES ($1,$2,$3, now() + $4::interval)`,
		hashToken(token), sessionID, clientID, ttl.String())
	return err
}

func (s *Store) LookupAccessToken(ctx context.Context, token string) (sessionID string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT session_id FROM access_tokens WHERE token_hash=$1 AND expires_at > now()`,
		hashToken(token)).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return sessionID, err
}

func (s *Store) CreateRefreshToken(ctx context.Context, token, sessionID, clientID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, session_id, client_id) VALUES ($1,$2,$3)`,
		hashToken(token), sessionID, clientID)
	return err
}

// TakeRefreshToken consumes the token, so refresh rotation is enforced.
func (s *Store) TakeRefreshToken(ctx context.Context, token string) (sessionID, clientID string, err error) {
	err = s.pool.QueryRow(ctx,
		`DELETE FROM refresh_tokens WHERE token_hash=$1 RETURNING session_id, client_id`,
		hashToken(token)).Scan(&sessionID, &clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return sessionID, clientID, err
}

// Sweep clears rows that are past their usefulness. Expired access tokens are
// already rejected on lookup; this just stops the tables growing forever.
func (s *Store) Sweep(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
DELETE FROM flows      WHERE created_at < now() - INTERVAL '1 hour';
DELETE FROM auth_codes WHERE created_at < now() - INTERVAL '1 hour';
DELETE FROM access_tokens WHERE expires_at < now() - INTERVAL '1 day';
`)
	return err
}
