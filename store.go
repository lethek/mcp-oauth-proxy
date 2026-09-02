package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// querier is what a statement runs against: the pool on its own, or the
// transaction of a Grant. Both satisfy it.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

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
	//
	// A day, not longer: /register admits 20 registrations a minute per address,
	// each up to maxRedirectURIs * maxRedirectURILen, and the sweep is the only
	// thing that reclaims them. At 30 days that product was 27 GB per address
	// before anything was freed; at a day it is under 1 GB, and only while the
	// sender keeps it up. A client that got as far as a token is not "unused":
	// its refresh token row, rotated or not, refers to it for the refresh
	// lifetime plus a day, so this only shortens the life of a registration
	// that never finished. A day is enough for a registration whose browser
	// step is left until tomorrow; one left longer has to register again.
	unusedClientTTL = 24 * time.Hour
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

-- resource lives here rather than on auth_codes and access_tokens because a
-- session is created for exactly one authorization, which named exactly one
-- resource. Every credential issued against the session inherits it, including
-- refreshed ones, without threading the value through three more tables.
CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    subject        TEXT NOT NULL DEFAULT '',
    resource       TEXT NOT NULL DEFAULT '',
    upstream_token BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';

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

-- resource was dropped when this proxy served exactly one, because a column
-- nobody reads is a control that only appears to exist. It is back, and this
-- time it is enforced: with several targets it decides which upstream a token
-- may be used against. Empty means a single-target deployment that never asked.
ALTER TABLE flows ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';

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

-- What a user supplied for themselves, for a target whose MCP server wants its
-- own credential rather than the provider's token. Keyed on (subject, target)
-- because one person may hold a different credential at each.
--
-- No foreign key to sessions: a credential outlives any single authorization and
-- must survive the user re-authorising.
CREATE TABLE IF NOT EXISTS user_credentials (
    subject        TEXT NOT NULL,
    target         TEXT NOT NULL,
    sealed_headers BYTEA NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, target)
);

-- An in-flight login for the enrolment page. Separate from flows because there
-- is no MCP client involved: nobody registered, there is no redirect_uri to
-- return to and no PKCE challenge of a client's to verify.
CREATE TABLE IF NOT EXISTS settings_flows (
    id                TEXT PRIMARY KEY,
    upstream_verifier TEXT NOT NULL,
    browser_hash      BYTEA NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

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

	// Resource is the target this authorization is for, carried from /authorize
	// to /callback so the session it creates records the right audience.
	Resource string

	// BrowserSecret ties this flow to the browser that was shown the consent
	// page. Only the hash is stored. It is write-only: CreateFlow reads it and
	// nothing ever returns it, so a caller cannot accidentally leak it back out.
	BrowserSecret string
}

const flowColumns = `id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, resource`

func scanFlow(row pgx.Row) (Flow, error) {
	var f Flow
	err := row.Scan(&f.ID, &f.ClientID, &f.RedirectURI, &f.ClientState, &f.CodeChallenge, &f.UpstreamVerifier, &f.Resource)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (s *Store) CreateFlow(ctx context.Context, f Flow) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO flows (id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, resource, browser_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		f.ID, f.ClientID, f.RedirectURI, f.ClientState, f.CodeChallenge, f.UpstreamVerifier,
		f.Resource, hashToken(f.BrowserSecret))
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

func (s *Store) CreateSession(ctx context.Context, id, subject, resource string, sealedToken []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, subject, resource, upstream_token) VALUES ($1,$2,$3,$4)`,
		id, subject, resource, sealedToken)
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
	return takeAuthCode(ctx, s.pool, code)
}

func takeAuthCode(ctx context.Context, q querier, code string) (AuthCode, error) {
	var a AuthCode
	err := q.QueryRow(ctx,
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

// CreateAccessToken writes one token on its own.
//
// Nothing in the serving path uses it: issue() goes through CreateTokenPair,
// because writing the two credentials of one grant separately can leave a client
// unable to retry. Kept for tests that need a single row. New callers wanting a
// grant want CreateTokenPair.
func (s *Store) CreateAccessToken(ctx context.Context, token, sessionID, clientID string, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO access_tokens (token_hash, session_id, client_id, expires_at) VALUES ($1,$2,$3, now() + $4::interval)`,
		hashToken(token), sessionID, clientID, ttl.String())
	return err
}

// LookupAccessToken also enforces the session's absolute lifetime, so an access
// token minted just before that deadline does not outlive it.
//
// It returns the session's resource in the same query, because every proxied
// request needs it to check the token's audience and a second round trip on that
// path would be paid on every call.
func (s *Store) LookupAccessToken(ctx context.Context, token string) (sessionID, resource string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT t.session_id, s.resource FROM access_tokens t
		 JOIN sessions s ON s.id = t.session_id
		 WHERE t.token_hash=$1 AND t.expires_at > now() AND s.created_at > now() - $2::interval`,
		hashToken(token), s.sessionTTL.String()).Scan(&sessionID, &resource)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return sessionID, resource, err
}

// CreateTokenPair writes both credentials of one grant in a single
// transaction.
//
// Separately, a failure between them leaves the client holding nothing usable
// while an access token it never received sits in the database. The pair is one
// grant, so it is one write. The serving path goes further and uses a Grant, so
// the code or refresh token being redeemed is consumed in that same write.
func (s *Store) CreateTokenPair(ctx context.Context, access, refresh, sessionID, clientID string, accessTTL time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := createTokenPair(ctx, tx, access, refresh, sessionID, clientID, accessTTL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func createTokenPair(ctx context.Context, q querier, access, refresh, sessionID, clientID string, accessTTL time.Duration) error {
	if _, err := q.Exec(ctx,
		`INSERT INTO access_tokens (token_hash, session_id, client_id, expires_at) VALUES ($1,$2,$3, now() + $4::interval)`,
		hashToken(access), sessionID, clientID, accessTTL.String()); err != nil {
		return err
	}
	_, err := q.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, session_id, client_id) VALUES ($1,$2,$3)`,
		hashToken(refresh), sessionID, clientID)
	return err
}

// Grant is one transaction spanning the consumption of an authorization code
// or refresh token and the issue of the tokens it buys.
//
// Consumed on read alone, a failure writing the new tokens left the client with
// nothing it could retry: the code was gone, or the refresh token was marked
// used so that the retry looked like a replay and revoked the session. Inside
// one transaction the failure rolls the consumption back too.
type Grant struct {
	s  *Store
	tx pgx.Tx
}

func (s *Store) BeginGrant(ctx context.Context) (*Grant, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &Grant{s: s, tx: tx}, nil
}

func (g *Grant) TakeAuthCode(ctx context.Context, code string) (AuthCode, error) {
	return takeAuthCode(ctx, g.tx, code)
}

func (g *Grant) TakeRefreshToken(ctx context.Context, token, clientID string) (string, error) {
	return g.s.takeRefreshToken(ctx, g.tx, token, clientID)
}

func (g *Grant) CreateTokenPair(ctx context.Context, access, refresh, sessionID, clientID string, accessTTL time.Duration) error {
	return createTokenPair(ctx, g.tx, access, refresh, sessionID, clientID, accessTTL)
}

func (g *Grant) Commit(ctx context.Context) error { return g.tx.Commit(ctx) }

// Rollback is safe to defer after a Commit; it does nothing then.
func (g *Grant) Rollback(ctx context.Context) { _ = g.tx.Rollback(ctx) }

// CreateRefreshToken writes one token on its own. See CreateAccessToken: the
// serving path uses CreateTokenPair instead.
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
func (s *Store) TakeRefreshToken(ctx context.Context, token, clientID string) (sessionID string, err error) {
	return s.takeRefreshToken(ctx, s.pool, token, clientID)
}

func (s *Store) takeRefreshToken(ctx context.Context, q querier, token, clientID string) (sessionID string, err error) {
	hash := hashToken(token)

	// The client binding is part of the same statement, so a request naming the
	// wrong client matches nothing and the token stays unused.
	//
	// Checking it after consumption was a real fault: an invalid refresh would
	// burn the caller's only valid token, and the legitimate retry that followed
	// then looked like a replay and revoked the whole session. A wrong client id
	// is an ordinary mistake and must not be able to destroy a session.
	err = q.QueryRow(ctx,
		`UPDATE refresh_tokens r SET used=true, used_at=now()
		 FROM sessions s
		 WHERE r.token_hash=$1
		   AND NOT r.used
		   AND r.client_id=$2
		   AND r.created_at > now() - $3::interval
		   AND s.id = r.session_id
		   AND s.created_at > now() - $4::interval
		 RETURNING r.session_id`,
		hash, clientID, s.refreshTTL.String(), s.sessionTTL.String()).Scan(&sessionID)
	if err == nil {
		return sessionID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	// The token did not qualify. Only a token already marked used is a replay;
	// a client-id mismatch on an unused token is not, and must not be reported
	// as one or the caller below would tear the session down.
	//
	// This probe deliberately does not check client_id, unlike the UPDATE
	// above. A spent token is dead whoever presents it, so nothing is gained by
	// matching the client, and the client id is public: whoever stole the token
	// took it from storage where the id sits beside it. Scoping the probe would
	// only let a thief who presents (or registers) a different client id replay
	// the token without tripping the theft signal, at no cost to anyone who
	// knows the real id. The asymmetry is the point: the client binding above
	// stops a wrong id from burning an unused token, while a used token is a
	// replay regardless of who claims it.
	var reusedSession string
	if e := q.QueryRow(ctx,
		`SELECT session_id FROM refresh_tokens WHERE token_hash=$1 AND used`, hash).
		Scan(&reusedSession); e == nil {
		return reusedSession, ErrTokenReused
	}
	return "", ErrNotFound
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

// ---------- per-user credentials ----------

// PutUserCredential replaces whatever the subject had for this target. Replacing
// rather than erroring on a duplicate is the point: rotating a leaked token is
// the same action as setting one for the first time.
func (s *Store) PutUserCredential(ctx context.Context, subject, target string, sealed []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_credentials (subject, target, sealed_headers) VALUES ($1,$2,$3)
		 ON CONFLICT (subject, target)
		 DO UPDATE SET sealed_headers = EXCLUDED.sealed_headers, updated_at = now()`,
		subject, target, sealed)
	return err
}

// UserCredentialForSession resolves a session straight to its owner's credential
// for a target, in one query. Every proxied request in per_user mode needs it, so
// fetching the subject and then the credential would cost a second round trip on
// that path.
func (s *Store) UserCredentialForSession(ctx context.Context, sessionID, target string) ([]byte, error) {
	var sealed []byte
	err := s.pool.QueryRow(ctx,
		`SELECT c.sealed_headers FROM sessions s
		 JOIN user_credentials c ON c.subject = s.subject AND c.target = $2
		 WHERE s.id = $1 AND s.subject <> ''`,
		sessionID, target).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sealed, err
}

// EnrolledTargets is the set a subject has already configured, for the catalogue.
func (s *Store) EnrolledTargets(ctx context.Context, subject string) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT target, updated_at FROM user_credentials WHERE subject=$1`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]time.Time{}
	for rows.Next() {
		var target string
		var at time.Time
		if err := rows.Scan(&target, &at); err != nil {
			return nil, err
		}
		out[target] = at
	}
	return out, rows.Err()
}

func (s *Store) DeleteUserCredential(ctx context.Context, subject, target string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM user_credentials WHERE subject=$1 AND target=$2`, subject, target)
	return err
}

// ---------- settings login ----------

func (s *Store) CreateSettingsFlow(ctx context.Context, id, verifier, browserSecret string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO settings_flows (id, upstream_verifier, browser_hash) VALUES ($1,$2,$3)`,
		id, verifier, hashToken(browserSecret))
	return err
}

// TakeSettingsFlow consumes the flow, demanding the same browser that started it.
// Single use by deletion, so a replayed callback finds nothing.
func (s *Store) TakeSettingsFlow(ctx context.Context, id, browserSecret string) (verifier string, err error) {
	if browserSecret == "" {
		return "", ErrNotFound
	}
	err = s.pool.QueryRow(ctx,
		`DELETE FROM settings_flows
		 WHERE id=$1 AND created_at > now() - $2::interval AND browser_hash=$3
		 RETURNING upstream_verifier`,
		id, flowTTL.String(), hashToken(browserSecret)).Scan(&verifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return verifier, err
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
		{sql: `DELETE FROM settings_flows WHERE created_at < now() - INTERVAL '1 hour'`},
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
   AND NOT EXISTS (SELECT 1 FROM flows          f WHERE f.client_id = c.client_id)
   AND NOT EXISTS (SELECT 1 FROM auth_codes     a WHERE a.client_id = c.client_id)`,
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
