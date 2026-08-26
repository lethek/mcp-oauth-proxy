package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")

	// ErrTokenReused means a refresh token that had already been rotated was
	// presented again. That is the signature of a stolen token, so the caller is
	// expected to tear the session down rather than simply refuse.
	ErrTokenReused = errors.New("refresh token was already used")
)

const (
	flowTTL = 10 * time.Minute
	codeTTL = 60 * time.Second

	// unusedClientTTL bounds how long an anonymous registration survives without
	// ever being used, so the clients table cannot grow without limit.
	unusedClientTTL = 30 * 24 * time.Hour
)

type Store struct {
	pool *pgxpool.Pool

	refreshTTL time.Duration
	sessionTTL time.Duration
}

func NewStore(ctx context.Context, url string, refreshTTL, sessionTTL time.Duration) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{pool: pool, refreshTTL: refreshTTL, sessionTTL: sessionTTL}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

// migrate is deliberately a single idempotent statement block rather than a
// migration framework. The schema is small and this runs on every boot. The
// ALTERs bring a database created by an earlier version up to date.
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

-- An in-flight authorization: created when the client hits /authorize, marked
-- approved when the user accepts at /consent, and consumed when the upstream
-- provider redirects back to /callback. A flow that was never approved can
-- never produce a token.
CREATE TABLE IF NOT EXISTS flows (
    id                TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    redirect_uri      TEXT NOT NULL,
    client_state      TEXT NOT NULL DEFAULT '',
    code_challenge    TEXT NOT NULL,
    upstream_verifier TEXT NOT NULL,
    approved          BOOLEAN NOT NULL DEFAULT false,
    browser_hash      BYTEA,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE flows ADD COLUMN IF NOT EXISTS approved BOOLEAN NOT NULL DEFAULT false;
-- Nullable so an upgrade does not have to invent a value. A NULL never matches
-- the equality test in ApproveFlow, so a row from an older version fails shut.
ALTER TABLE flows ADD COLUMN IF NOT EXISTS browser_hash BYTEA;

-- resource was collected and never used. It is validated at /authorize against
-- the one resource this proxy serves, so there is nothing left to carry per
-- row, and a column nobody writes reads as a control that exists when it does
-- not. Dropped rather than left behind.
ALTER TABLE flows DROP COLUMN IF EXISTS resource;

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash      BYTEA PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE auth_codes DROP COLUMN IF EXISTS resource;

CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash BYTEA PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- A rotated refresh token is kept, marked used, rather than deleted.
-- Presenting one again is how a theft announces itself.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash BYTEA PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT false,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS used BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS access_tokens_session_idx  ON access_tokens (session_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_session_idx ON refresh_tokens (session_id);

-- The sweep asks, for each client, whether anything still refers to it. Without
-- these that question scans all three tables on every pass.
CREATE INDEX IF NOT EXISTS access_tokens_client_idx  ON access_tokens (client_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_client_idx ON refresh_tokens (client_id);
CREATE INDEX IF NOT EXISTS flows_client_idx          ON flows (client_id);
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

	// BrowserSecret ties this flow to the browser that was shown the consent
	// page. Only the hash is stored. It is write-only: CreateFlow reads it and
	// nothing ever returns it, so a caller cannot accidentally leak it back out.
	BrowserSecret string
}

const flowColumns = `id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier`

func scanFlow(row pgx.Row) (Flow, error) {
	var f Flow
	err := row.Scan(&f.ID, &f.ClientID, &f.RedirectURI, &f.ClientState, &f.CodeChallenge, &f.UpstreamVerifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (s *Store) CreateFlow(ctx context.Context, f Flow) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO flows (id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, browser_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		f.ID, f.ClientID, f.RedirectURI, f.ClientState, f.CodeChallenge, f.UpstreamVerifier,
		hashToken(f.BrowserSecret))
	return err
}

// ApproveFlow records the user's decision at the consent screen.
//
// The browser secret is checked here, in the same statement, rather than in the
// handler. Knowing a flow id is not proof of anything: anyone may call
// /authorize and read the id out of the page they get back. Only the browser
// that was shown the page holds the matching secret, and making the check part
// of the update means no future caller can forget it.
//
// The update is also the atomic step that makes consent single use: a
// resubmitted form finds the flow already approved and gets ErrNotFound.
func (s *Store) ApproveFlow(ctx context.Context, id, browserSecret string) (Flow, error) {
	if browserSecret == "" {
		return Flow{}, ErrNotFound
	}
	return scanFlow(s.pool.QueryRow(ctx,
		`UPDATE flows SET approved=true
		 WHERE id=$1 AND NOT approved AND created_at > now() - $2::interval
		   AND browser_hash = $3
		 RETURNING `+flowColumns,
		id, flowTTL.String(), hashToken(browserSecret)))
}

// TakeFlow fetches and deletes a flow whatever its state, for the path where
// the user declines. It demands the same browser binding as ApproveFlow.
func (s *Store) TakeFlow(ctx context.Context, id, browserSecret string) (Flow, error) {
	if browserSecret == "" {
		return Flow{}, ErrNotFound
	}
	return scanFlow(s.pool.QueryRow(ctx,
		`DELETE FROM flows WHERE id=$1 AND created_at > now() - $2::interval
		   AND browser_hash = $3
		 RETURNING `+flowColumns,
		id, flowTTL.String(), hashToken(browserSecret)))
}

// TakeApprovedFlow is the callback's view: only an approved flow can be
// redeemed, and only once, so a replayed callback finds nothing.
func (s *Store) TakeApprovedFlow(ctx context.Context, id string) (Flow, error) {
	return scanFlow(s.pool.QueryRow(ctx,
		`DELETE FROM flows WHERE id=$1 AND approved AND created_at > now() - $2::interval
		 RETURNING `+flowColumns,
		id, flowTTL.String()))
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
	err := s.pool.QueryRow(ctx,
		`SELECT upstream_token FROM sessions WHERE id=$1 AND created_at > now() - $2::interval`,
		id, s.sessionTTL.String()).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// UpdateSessionToken reports ErrNotFound when the session has gone. An UPDATE
// that matches no rows is not an error to Postgres, so without this a write
// against a revoked session looks like success and the caller carries on.
func (s *Store) UpdateSessionToken(ctx context.Context, id string, sealedToken []byte) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET upstream_token=$2, updated_at=now() WHERE id=$1`, id, sealedToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeSession drops the session and, by cascade, every code and token issued
// against it. Both the revocation endpoint and refresh-reuse detection end here.
func (s *Store) RevokeSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
	return err
}

// ---------- authorization codes ----------

type AuthCode struct {
	SessionID     string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
}

func (s *Store) CreateAuthCode(ctx context.Context, code string, a AuthCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_codes (code_hash, session_id, client_id, redirect_uri, code_challenge)
		 VALUES ($1,$2,$3,$4,$5)`,
		hashToken(code), a.SessionID, a.ClientID, a.RedirectURI, a.CodeChallenge)
	return err
}

// TakeAuthCode enforces single use by deleting on read.
func (s *Store) TakeAuthCode(ctx context.Context, code string) (AuthCode, error) {
	var a AuthCode
	err := s.pool.QueryRow(ctx,
		`DELETE FROM auth_codes WHERE code_hash=$1 AND created_at > now() - $2::interval
		 RETURNING session_id, client_id, redirect_uri, code_challenge`,
		hashToken(code), codeTTL.String()).
		Scan(&a.SessionID, &a.ClientID, &a.RedirectURI, &a.CodeChallenge)
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

// LookupAccessToken also enforces the session's absolute lifetime, so an access
// token minted just before that deadline does not outlive it.
func (s *Store) LookupAccessToken(ctx context.Context, token string) (sessionID string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT t.session_id FROM access_tokens t
		 JOIN sessions s ON s.id = t.session_id
		 WHERE t.token_hash=$1 AND t.expires_at > now() AND s.created_at > now() - $2::interval`,
		hashToken(token), s.sessionTTL.String()).Scan(&sessionID)
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

// TakeRefreshToken marks the token used and returns its session, enforcing both
// the refresh token's own lifetime and the session's absolute one.
//
// It returns ErrTokenReused when the token exists but was already rotated.
// Rotation alone only detects theft; acting on that signal is what contains it,
// so the caller revokes the session.
func (s *Store) TakeRefreshToken(ctx context.Context, token string) (sessionID, clientID string, err error) {
	hash := hashToken(token)

	err = s.pool.QueryRow(ctx,
		`UPDATE refresh_tokens r SET used=true, used_at=now()
		 FROM sessions s
		 WHERE r.token_hash=$1
		   AND NOT r.used
		   AND r.created_at > now() - $2::interval
		   AND s.id = r.session_id
		   AND s.created_at > now() - $3::interval
		 RETURNING r.session_id, r.client_id`,
		hash, s.refreshTTL.String(), s.sessionTTL.String()).Scan(&sessionID, &clientID)
	if err == nil {
		return sessionID, clientID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}

	// The token did not qualify. If it is on file as already used, this is a
	// replay rather than an expiry or a typo.
	var reusedSession string
	if e := s.pool.QueryRow(ctx,
		`SELECT session_id FROM refresh_tokens WHERE token_hash=$1 AND used`, hash).
		Scan(&reusedSession); e == nil {
		return reusedSession, "", ErrTokenReused
	}
	return "", "", ErrNotFound
}

// SessionForToken resolves either kind of bearer token to its session without
// consuming it or checking expiry, so revoking an already-expired credential
// still tears down the session behind it.
func (s *Store) SessionForToken(ctx context.Context, token string) (string, error) {
	var sessionID string
	err := s.pool.QueryRow(ctx,
		`SELECT session_id FROM access_tokens WHERE token_hash=$1
		 UNION ALL
		 SELECT session_id FROM refresh_tokens WHERE token_hash=$1
		 LIMIT 1`,
		hashToken(token)).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return sessionID, err
}

// Sweep clears rows that are past their usefulness. Expired credentials are
// already refused on lookup; this bounds the tables and, for sessions, makes
// sure an upstream token stops existing rather than merely stops being
// reachable.
// Each statement runs on its own because a parameterised Exec uses the extended
// protocol, which carries one statement at a time.
func (s *Store) Sweep(ctx context.Context) error {
	statements := []struct {
		sql  string
		args []any
	}{
		{sql: `DELETE FROM flows WHERE created_at < now() - INTERVAL '1 hour'`},
		{sql: `DELETE FROM auth_codes WHERE created_at < now() - INTERVAL '1 hour'`},
		{sql: `DELETE FROM access_tokens WHERE expires_at < now() - INTERVAL '1 day'`},

		// A used token is kept for one refresh lifetime beyond its own, so a late
		// replay is still recognised as reuse rather than mistaken for an unknown
		// token.
		{
			sql:  `DELETE FROM refresh_tokens WHERE created_at < now() - $1::interval - INTERVAL '1 day'`,
			args: []any{s.refreshTTL.String()},
		},

		// The session, and with it the encrypted upstream credential, past its
		// absolute lifetime.
		{
			sql:  `DELETE FROM sessions WHERE created_at < now() - $1::interval`,
			args: []any{s.sessionTTL.String()},
		},

		// A session whose authorization code was never redeemed holds a live
		// upstream token that nothing can reach. The code lives for a minute, so
		// anything older than an hour with nothing pointing at it is abandoned.
		{sql: `
DELETE FROM sessions s
 WHERE s.created_at < now() - INTERVAL '1 hour'
   AND NOT EXISTS (SELECT 1 FROM access_tokens  t WHERE t.session_id = s.id)
   AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.session_id = s.id)
   AND NOT EXISTS (SELECT 1 FROM auth_codes     c WHERE c.session_id = s.id)`},

		// A registration that was never carried through to a token.
		{
			sql: `
DELETE FROM clients c
 WHERE c.created_at < now() - $1::interval
   AND NOT EXISTS (SELECT 1 FROM access_tokens  t WHERE t.client_id = c.client_id)
   AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.client_id = c.client_id)
   AND NOT EXISTS (SELECT 1 FROM flows          f WHERE f.client_id = c.client_id)`,
			args: []any{unusedClientTTL.String()},
		},
	}

	for _, st := range statements {
		if _, err := s.pool.Exec(ctx, st.sql, st.args...); err != nil {
			return err
		}
	}
	return nil
}
