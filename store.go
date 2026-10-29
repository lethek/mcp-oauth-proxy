package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
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

	// ErrStaleTarget means a write was made under a stamp that is no longer the
	// target's: it was replaced or removed after the caller read its definition.
	// Nothing was stored.
	ErrStaleTarget = errors.New("the target's settings changed")

	// ErrNotAdmitted means the user is not in a group the target allows, judged
	// against the allowed_groups read under the fence.
	ErrNotAdmitted = errors.New("the user is not in a group the target allows")
)

func isAdminStamp(stamp string) bool { return strings.HasPrefix(stamp, "admin:") }

// fenced runs fn in a short transaction that holds FOR SHARE on the admin
// target's row, and only if the row still carries stamp. An edit takes the row
// lock FOR SHARE conflicts with, so either fn commits first and cleanup removes
// what it wrote, or the edit commits first and the lock query finds a different
// stamp and fn never runs. A plain EXISTS would not do: under READ COMMITTED it
// reads the stamp as of the statement start, so an edit that commits after that
// still lets the insert land. The lock is never held across a provider call.
func (s *Store) fenced(ctx context.Context, name, stamp string, fn func(tx pgx.Tx, allowed []string) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var allowed []string
	err = tx.QueryRow(ctx,
		`SELECT allowed_groups FROM targets WHERE name=$1 AND stamp=$2 FOR SHARE`, name, stamp).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleTarget
	}
	if err != nil {
		return err
	}
	if err := fn(tx, allowed); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

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

	// admin is set when admin targets are enabled. Until then the targets table
	// is neither read nor written, and the freshness join is not issued.
	admin *adminPolicy

	// afterVersionRead, when set, runs inside LoadAdminTargets between reading
	// the version and reading the rows. Tests use it to force an edit into that
	// gap.
	afterVersionRead func()

	// skipCleanup turns off the purge that follows an edit or removal and the
	// admin statements of the sweep. Tests set it to show that the stamp check
	// and the fences refuse stale rows without cleanup's help.
	skipCleanup bool
}

// adminPolicy is what the store needs to accept and read admin targets.
type adminPolicy struct {
	sealer *sealer
	hosts  []hostPattern
	nets   []netip.Prefix
}

// EnableAdminTargets turns on the targets table for this store. It must run
// before the store is shared.
func (s *Store) EnableAdminTargets(seal *sealer, hosts []hostPattern, nets []netip.Prefix) {
	s.admin = &adminPolicy{sealer: seal, hosts: hosts, nets: nets}
}

// freshnessSQL returns the pieces a session reader adds so it can compare the
// stamp the database holds for the session's target with its own snapshot. With
// admin targets off there is nothing to compare and the join is not issued.
func (s *Store) freshnessSQL() (column, join string) {
	if s.admin == nil {
		return "NULL::text", ""
	}
	return "tg.stamp", "LEFT JOIN targets tg ON tg.name = s.target"
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

// credentialKeyMigration rewrites the key of user_credentials in a database
// created before stamps, which keyed it on (subject, target). The advisory lock
// lets two replicas boot together without both rewriting the key.
//
// The table is found with a regclass cast, which resolves through search_path
// exactly as the statements around it do. Asking information_schema for
// current_schema() instead can look in a different schema than they use.
const credentialKeyMigration = `
DO $$
DECLARE
    pk_name text;
    pk_cols int;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('mcp-oauth-proxy-credential-key'));
    SELECT conname, cardinality(conkey) INTO pk_name, pk_cols
      FROM pg_constraint
     WHERE conrelid = 'user_credentials'::regclass AND contype = 'p';
    IF pk_cols = 2 THEN
        EXECUTE format('ALTER TABLE user_credentials DROP CONSTRAINT %I', pk_name);
        ALTER TABLE user_credentials ADD PRIMARY KEY (subject, target, stamp);
    END IF;
END $$;
`

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
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS target TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS stamp  TEXT NOT NULL DEFAULT '';

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
ALTER TABLE flows ADD COLUMN IF NOT EXISTS target TEXT NOT NULL DEFAULT '';
ALTER TABLE flows ADD COLUMN IF NOT EXISTS stamp  TEXT NOT NULL DEFAULT '';

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
-- own credential rather than the provider's token. Keyed on (subject, target,
-- stamp) because one person may hold a different credential at each target, and
-- at each definition of it.
--
-- No foreign key to sessions: a credential outlives any single authorization and
-- must survive the user re-authorising.
CREATE TABLE IF NOT EXISTS user_credentials (
    subject        TEXT NOT NULL,
    target         TEXT NOT NULL,
    stamp          TEXT NOT NULL DEFAULT '',
    sealed_headers BYTEA NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, target, stamp)
);
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS stamp TEXT NOT NULL DEFAULT '';
`+credentialKeyMigration+`
-- When any process last served each (target, stamp). The stray credential sweep
-- reads it so that a definition a rolling deploy, canary or rollback still
-- serves elsewhere does not lose its credentials.
CREATE TABLE IF NOT EXISTS stamp_seen (
    target  TEXT NOT NULL,
    stamp   TEXT NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (target, stamp)
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
-- Which page started the login, so a flow cannot be redeemed at the other
-- page's callback. Rows from before the column belong to the settings page.
ALTER TABLE settings_flows ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'settings';

-- Targets an admin manages from the web page, beside the ones in the
-- environment. stamp is maintained by the application on every save, and
-- generation is re-rolled on every replacement, so a re-added name never
-- shares a stamp with its predecessor. revision counts edits to one row and
-- is not an identity: re-adding a name restarts it, so every mutation is
-- checked against (name, row_id, revision) together.
CREATE TABLE IF NOT EXISTS targets (
    name           TEXT PRIMARY KEY,
    display_name   TEXT NOT NULL,
    upstream_mcp   TEXT NOT NULL,
    mode           TEXT NOT NULL,
    row_id         UUID NOT NULL DEFAULT gen_random_uuid(),
    generation     UUID NOT NULL DEFAULT gen_random_uuid(),
    stamp          TEXT NOT NULL,
    sealed_static  BYTEA,
    user_fields    JSONB,
    allowed_groups TEXT[] NOT NULL DEFAULT '{}',
    revision       BIGINT NOT NULL DEFAULT 1,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by     TEXT NOT NULL
);

-- One row, bumped in the transaction of every change. Replicas poll it.
CREATE TABLE IF NOT EXISTS targets_version (
    id      BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    version BIGINT NOT NULL
);
INSERT INTO targets_version (id, version) VALUES (true, 0) ON CONFLICT DO NOTHING;

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

	// Target and Stamp are the name and stamp of the definition /authorize
	// resolved, so the callback can refuse a flow whose definition has since
	// changed.
	Target string
	Stamp  string

	// BrowserSecret ties this flow to the browser that was shown the consent
	// page. Only the hash is stored. It is write-only: CreateFlow reads it and
	// nothing ever returns it, so a caller cannot accidentally leak it back out.
	BrowserSecret string
}

const flowColumns = `id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, resource, target, stamp`

func scanFlow(row pgx.Row) (Flow, error) {
	var f Flow
	err := row.Scan(&f.ID, &f.ClientID, &f.RedirectURI, &f.ClientState, &f.CodeChallenge, &f.UpstreamVerifier, &f.Resource, &f.Target, &f.Stamp)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (s *Store) CreateFlow(ctx context.Context, f Flow) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO flows (id, client_id, redirect_uri, client_state, code_challenge, upstream_verifier, resource, target, stamp, browser_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		f.ID, f.ClientID, f.RedirectURI, f.ClientState, f.CodeChallenge, f.UpstreamVerifier,
		f.Resource, f.Target, f.Stamp, hashToken(f.BrowserSecret))
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

// CreateSession stores the session. For an admin target the insert is fenced
// (see fenced), and admits, when set, is asked about the allowed_groups the
// fence read, so a replica with an old snapshot cannot admit someone the target
// no longer admits. A refusal returns ErrNotAdmitted before anything is stored.
// admits is not consulted for a config target; the caller checks its snapshot.
func (s *Store) CreateSession(ctx context.Context, id, subject, resource, target, stamp string, sealedToken []byte, admits func(allowed []string) bool) error {
	insert := func(q querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO sessions (id, subject, resource, target, stamp, upstream_token) VALUES ($1,$2,$3,$4,$5,$6)`,
			id, subject, resource, target, stamp, sealedToken)
		return err
	}
	if !isAdminStamp(stamp) {
		return insert(s.pool)
	}
	return s.fenced(ctx, target, stamp, func(tx pgx.Tx, allowed []string) error {
		if admits != nil && !admits(allowed) {
			return ErrNotAdmitted
		}
		return insert(tx)
	})
}

// SessionToken returns the sealed provider token only to a caller that names the
// stamp the session was created under. An empty stamp never matches.
func (s *Store) SessionToken(ctx context.Context, id, stamp string) ([]byte, error) {
	var b []byte
	err := s.pool.QueryRow(ctx,
		`SELECT upstream_token FROM sessions
		 WHERE id=$1 AND stamp=$2 AND stamp <> '' AND created_at > now() - $3::interval`,
		id, stamp, s.sessionTTL.String()).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// UpdateSessionToken reports ErrNotFound when the session has gone. An UPDATE
// that matches no rows is not an error to Postgres, so without this a write
// against a revoked session looks like success and the caller carries on.
//
// Matching the session's own stamp is not enough for an admin target: the
// session keeps its old stamp after a replacement, so the write would still
// land. It takes the same fence as creation, and a refresh that straddles a
// replacement returns ErrStaleTarget having written nothing.
func (s *Store) UpdateSessionToken(ctx context.Context, id, stamp string, sealedToken []byte) error {
	update := func(q querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE sessions SET upstream_token=$3, updated_at=now() WHERE id=$1 AND stamp=$2 AND stamp <> ''`,
			id, stamp, sealedToken)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}
	if !isAdminStamp(stamp) {
		return update(s.pool)
	}
	// The fence needs the target's name, which the session row holds.
	var target string
	err := s.pool.QueryRow(ctx, `SELECT target FROM sessions WHERE id=$1 AND stamp=$2`, id, stamp).Scan(&target)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return s.fenced(ctx, target, stamp, func(tx pgx.Tx, _ []string) error { return update(tx) })
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

// SessionRef is what a proxied request needs to know about the session behind
// its token, fetched in the one query so that path pays no second round trip.
type SessionRef struct {
	ID       string
	Resource string
	Target   string
	Stamp    string

	// CurrentStamp is the stamp the targets table holds under the session's target
	// name, or nil when it holds none. Set only when admin targets are enabled; the
	// caller compares it with its snapshot to learn whether it is behind.
	CurrentStamp *string
}

// LookupAccessToken also enforces the session's absolute lifetime, so an access
// token minted just before that deadline does not outlive it.
//
// It returns the session's resource, target and stamp in the same query, because
// every proxied request needs them to check the token's audience and that the
// target is still the one the session was issued for. A session with an empty
// stamp, one that predates stamps, is never returned.
func (s *Store) LookupAccessToken(ctx context.Context, token string) (SessionRef, error) {
	var ref SessionRef
	column, join := s.freshnessSQL()
	err := s.pool.QueryRow(ctx,
		`SELECT t.session_id, s.resource, s.target, s.stamp, `+column+` FROM access_tokens t
		 JOIN sessions s ON s.id = t.session_id `+join+`
		 WHERE t.token_hash=$1 AND t.expires_at > now() AND s.stamp <> ''
		   AND s.created_at > now() - $2::interval`,
		hashToken(token), s.sessionTTL.String()).Scan(&ref.ID, &ref.Resource, &ref.Target, &ref.Stamp, &ref.CurrentStamp)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionRef{}, ErrNotFound
	}
	return ref, err
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

func (g *Grant) TakeRefreshToken(ctx context.Context, token, clientID string) (SessionRef, error) {
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
	ref, err := s.takeRefreshToken(ctx, s.pool, token, clientID)
	return ref.ID, err
}

// takeRefreshToken also returns the session's target, stamp and the stamp the
// database holds for that target, so the caller can refuse a refresh for a
// definition that has changed. The caller does so before committing the grant,
// which leaves the token unused.
func (s *Store) takeRefreshToken(ctx context.Context, q querier, token, clientID string) (ref SessionRef, err error) {
	hash := hashToken(token)
	column, join := s.freshnessSQL()

	// The client binding is part of the same statement, so a request naming the
	// wrong client matches nothing and the token stays unused.
	//
	// Checking it after consumption was a real fault: an invalid refresh would
	// burn the caller's only valid token, and the legitimate retry that followed
	// then looked like a replay and revoked the whole session. A wrong client id
	// is an ordinary mistake and must not be able to destroy a session.
	err = q.QueryRow(ctx,
		`UPDATE refresh_tokens r SET used=true, used_at=now()
		 FROM sessions s `+join+`
		 WHERE r.token_hash=$1
		   AND NOT r.used
		   AND r.client_id=$2
		   AND r.created_at > now() - $3::interval
		   AND s.id = r.session_id
		   AND s.created_at > now() - $4::interval
		 RETURNING r.session_id, s.target, s.stamp, `+column,
		hash, clientID, s.refreshTTL.String(), s.sessionTTL.String()).
		Scan(&ref.ID, &ref.Target, &ref.Stamp, &ref.CurrentStamp)
	if err == nil {
		return ref, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return SessionRef{}, err
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
		return SessionRef{ID: reusedSession}, ErrTokenReused
	}
	return SessionRef{}, ErrNotFound
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

// StampedName is a target name together with the stamp a credential was saved
// under.
type StampedName struct{ Name, Stamp string }

// PutUserCredential replaces whatever the subject had for this target under this
// stamp. Replacing rather than erroring on a duplicate is the point: rotating a
// leaked token is the same action as setting one for the first time. For an
// admin target the write is fenced and returns ErrStaleTarget if the stamp is no
// longer the target's.
func (s *Store) PutUserCredential(ctx context.Context, subject, target, stamp string, sealed []byte) error {
	if stamp == "" {
		return errors.New("a credential needs the stamp of the target it is for")
	}
	put := func(q querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO user_credentials (subject, target, stamp, sealed_headers) VALUES ($1,$2,$3,$4)
			 ON CONFLICT (subject, target, stamp)
			 DO UPDATE SET sealed_headers = EXCLUDED.sealed_headers, updated_at = now()`,
			subject, target, stamp, sealed)
		return err
	}
	if !isAdminStamp(stamp) {
		return put(s.pool)
	}
	return s.fenced(ctx, target, stamp, func(tx pgx.Tx, _ []string) error { return put(tx) })
}

// UserCredentialForSession resolves a session straight to its owner's credential
// for a target, in one query. Every proxied request in per_user mode needs it, so
// fetching the subject and then the credential would cost a second round trip on
// that path. The credential must have been saved under the stamp the session was
// issued under.
//
// It also returns the stamp the targets table holds for the name (nil if none),
// read in the same statement, so the caller can tell that its snapshot is behind
// before it sends the credential anywhere.
func (s *Store) UserCredentialForSession(ctx context.Context, sessionID, target string) (sealed []byte, current *string, err error) {
	column, join := s.freshnessSQL()
	err = s.pool.QueryRow(ctx,
		`SELECT c.sealed_headers, `+column+` FROM sessions s
		 JOIN user_credentials c ON c.subject = s.subject AND c.target = $2 AND c.stamp = s.stamp `+join+`
		 WHERE s.id = $1 AND s.subject <> '' AND s.stamp <> ''`,
		sessionID, target).Scan(&sealed, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	return sealed, current, err
}

// EnrolledTargets is the set a subject has already configured, for the catalogue.
// It is keyed on the stamp as well as the name, so the catalogue shows a target
// as configured only when the credential belongs to the definition being served
// now.
func (s *Store) EnrolledTargets(ctx context.Context, subject string) (map[StampedName]time.Time, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT target, stamp, updated_at FROM user_credentials WHERE subject=$1`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[StampedName]time.Time{}
	for rows.Next() {
		var target, stamp string
		var at time.Time
		if err := rows.Scan(&target, &stamp, &at); err != nil {
			return nil, err
		}
		out[StampedName{target, stamp}] = at
	}
	return out, rows.Err()
}

func (s *Store) DeleteUserCredential(ctx context.Context, subject, target, stamp string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM user_credentials WHERE subject=$1 AND target=$2 AND stamp=$3`, subject, target, stamp)
	return err
}

// ---------- settings login ----------

// The login pages that share settings_flows.
const (
	flowKindSettings = "settings"
	flowKindAdmin    = "admin"
)

func (s *Store) CreateSettingsFlow(ctx context.Context, id, verifier, browserSecret, kind string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO settings_flows (id, upstream_verifier, browser_hash, kind) VALUES ($1,$2,$3,$4)`,
		id, verifier, hashToken(browserSecret), kind)
	return err
}

// TakeSettingsFlow consumes the flow, demanding the same browser that started it
// and the same kind of login. Single use by deletion, so a replayed callback
// finds nothing, and a flow of the wrong kind is left for its own callback.
func (s *Store) TakeSettingsFlow(ctx context.Context, id, browserSecret, kind string) (verifier string, err error) {
	if browserSecret == "" {
		return "", ErrNotFound
	}
	err = s.pool.QueryRow(ctx,
		`DELETE FROM settings_flows
		 WHERE id=$1 AND created_at > now() - $2::interval AND browser_hash=$3 AND kind=$4
		 RETURNING upstream_verifier`,
		id, flowTTL.String(), hashToken(browserSecret), kind).Scan(&verifier)
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

		// Rows written before stamps, or by a replica that predates them. They
		// match no definition and are refused, so they are only taking space (and,
		// for sessions, holding a provider token that nothing can reach).
		{sql: `DELETE FROM flows WHERE stamp = ''`},
		{sql: `DELETE FROM sessions WHERE stamp = ''`},
		{sql: `DELETE FROM user_credentials WHERE stamp = ''`},

		// Long past the week the stray credential sweep looks back over.
		{sql: `DELETE FROM stamp_seen WHERE seen_at < now() - INTERVAL '30 days'`},

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
	return s.purgeStaleAdminRows(ctx, "")
}

// purgeStaleAdminRows deletes flows, sessions and credentials stamped for an
// admin target definition that no row in targets carries any more, for one
// target or, with an empty name, all of them. It is hygiene, not the control:
// the stamp check already refuses these rows. So it takes no locks beyond its
// own deletes and is not atomic with the edit. If it loses a deadlock against a
// refresh or /revoke it fails, the edit stays committed, and the next sweep
// repeats it.
func (s *Store) purgeStaleAdminRows(ctx context.Context, name string) error {
	if s.admin == nil || s.skipCleanup {
		return nil
	}
	// Every table is tried even if one fails, so a deadlock on sessions does not
	// leave flows and credentials for the next sweep as well.
	var errs []error
	for _, table := range []string{"flows", "sessions", "user_credentials"} {
		_, err := s.pool.Exec(ctx, `DELETE FROM `+table+` x
 WHERE x.stamp LIKE 'admin:%' AND ($1::text = '' OR x.target = $1)
   AND NOT EXISTS (SELECT 1 FROM targets t WHERE t.name = x.target AND t.stamp = x.stamp)`, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("purging stale %s: %w", table, err))
		}
	}
	return errors.Join(errs...)
}

// purgeAfterChange runs the purge for one target once its edit or removal has
// committed, in its own transaction. A failure is logged and left to the sweep.
func (s *Store) purgeAfterChange(ctx context.Context, name string) {
	if err := s.purgeStaleAdminRows(ctx, name); err != nil {
		slog.Warn("could not purge rows left by a target change; the next sweep will", "target", name, "err", err)
	}
}

// strayCredentialAge is how long a config credential must go unsaved, and its
// definition unserved by any process, before it is deleted. The wait has to
// outlast a rolling deploy, canary or rollback; a second definition lingering
// longer than that is not supported (one database, one deployment).
const strayCredentialAge = 7 * 24 * time.Hour

// RecordServedStamps notes that this process serves each of these (name, stamp)
// pairs now. Every process calls it on each sweep pass, so stamp_seen says when
// any process last served a definition.
func (s *Store) RecordServedStamps(ctx context.Context, served []StampedName) error {
	if len(served) == 0 {
		return nil
	}
	names := make([]string, len(served))
	stamps := make([]string, len(served))
	for i, v := range served {
		names[i], stamps[i] = v.Name, v.Stamp
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO stamp_seen (target, stamp, seen_at)
SELECT DISTINCT n, st, now() FROM unnest($1::text[], $2::text[]) AS v(n, st)
ON CONFLICT (target, stamp) DO UPDATE SET seen_at = now()`,
		names, stamps)
	return err
}

// SweepStrayCredentials deletes a config credential once it has not been saved
// for 7 days AND no process has served its definition for 7 days. Credentials
// have no lifetime of their own, so without this one outlives its definition
// indefinitely. The first condition protects a fresh save; the second protects
// a definition that another pod still serves during a rollout or rollback.
func (s *Store) SweepStrayCredentials(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
DELETE FROM user_credentials c
 WHERE c.stamp LIKE 'config:%'
   AND c.updated_at < now() - $1::interval
   AND NOT EXISTS (SELECT 1 FROM stamp_seen s
                    WHERE s.target = c.target AND s.stamp = c.stamp
                      AND s.seen_at > now() - $1::interval)`,
		strayCredentialAge.String())
	return err
}

// ---------- admin targets ----------

var (
	// ErrTargetChanged means the (name, row_id, revision) a change was made against
	// is not the row's now: it was edited, removed, or removed and re-added. The
	// person works from a stale page and has to reload.
	ErrTargetChanged = errors.New("the target changed or was removed")

	// ErrTargetExists means the name is already taken by an admin target.
	ErrTargetExists = errors.New("an admin target already has that name")

	// ErrStaticValueRequired refuses a change that would send a stored static
	// credential somewhere it was not entered for.
	ErrStaticValueRequired = errors.New("a static target needs a new static value when its URL or mode changes")
)

// AdminTarget is a row of the targets table. Target carries the stored
// definition, without the static headers, which stay sealed in SealedStatic
// until a snapshot is built.
type AdminTarget struct {
	Target       Target
	RowID        string
	Revision     int64
	StoredStamp  string
	SealedStatic []byte
	UpdatedAt    time.Time
	UpdatedBy    string
}

// TargetKey is what a change is checked against. Revision alone is not an
// identity, because re-adding a name restarts it at 1.
type TargetKey struct {
	Name     string
	RowID    string
	Revision int64
}

const adminColumns = `name, display_name, upstream_mcp, mode, row_id::text, generation::text, stamp,
	sealed_static, user_fields, allowed_groups, revision, updated_at, updated_by`

func scanAdminTarget(row pgx.Row) (AdminTarget, error) {
	var a AdminTarget
	var mode string
	var fields []byte
	t := &a.Target
	err := row.Scan(&t.Name, &t.DisplayName, &t.UpstreamMCP, &mode, &a.RowID, &t.Generation, &a.StoredStamp,
		&a.SealedStatic, &fields, &t.AllowedGroups, &a.Revision, &a.UpdatedAt, &a.UpdatedBy)
	if err != nil {
		return AdminTarget{}, err
	}
	t.Mode, t.Source = CredentialMode(mode), SourceAdmin
	if fields != nil {
		if err := json.Unmarshal(fields, &t.UserFields); err != nil {
			return AdminTarget{}, fmt.Errorf("target %q: user_fields: %w", t.Name, err)
		}
	}
	return a, nil
}

// LoadAdminTargets reads every row and the version in one REPEATABLE READ
// transaction, so an edit committing between the two reads cannot produce a
// mixed result: the rows are exactly those the version describes.
func (s *Store) LoadAdminTargets(ctx context.Context) ([]AdminTarget, int64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var version int64
	if err := tx.QueryRow(ctx, `SELECT version FROM targets_version`).Scan(&version); err != nil {
		return nil, 0, err
	}
	if s.afterVersionRead != nil {
		s.afterVersionRead()
	}
	rows, err := tx.Query(ctx, `SELECT `+adminColumns+` FROM targets ORDER BY name`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AdminTarget
	for rows.Next() {
		a, err := scanAdminTarget(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, version, rows.Err()
}

// TargetsVersion is the cheap read each replica polls.
func (s *Store) TargetsVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT version FROM targets_version`).Scan(&v)
	return v, err
}

// staticPurpose binds a sealed static value to its row.
func staticPurpose(name, rowID string) string {
	return boundPurpose(purposeAdminStatic, name+"/"+rowID)
}

func (s *Store) openStatic(a AdminTarget) (map[string]string, error) {
	raw, err := s.admin.sealer.open(staticPurpose(a.Target.Name, a.RowID), a.SealedStatic)
	if err != nil {
		return nil, err
	}
	var headers map[string]string
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, err
	}
	return headers, nil
}

// checkAdminTarget applies the rules an admin-supplied definition must meet. It
// runs here so no caller can forget it, and again when a snapshot is built.
func (s *Store) checkAdminTarget(t Target) error {
	if t.Name == "" {
		return errors.New("a target needs a name")
	}
	if slices.Contains(reservedTargetNames, t.Name) {
		return fmt.Errorf("%q is a reserved name", t.Name)
	}
	if err := validateTarget(t); err != nil {
		return err
	}
	if err := validateAdminUpstream(t.UpstreamMCP, s.admin.hosts, s.admin.nets); err != nil {
		return fmt.Errorf("Upstream MCP URL: %w", err)
	}
	return nil
}

// InvalidTargetError marks a refusal the person can fix by changing what they
// entered, as opposed to a failure of the store. Its text is the cause's.
type InvalidTargetError struct{ Err error }

func (e *InvalidTargetError) Error() string { return e.Err.Error() }
func (e *InvalidTargetError) Unwrap() error { return e.Err }

// GetTarget reads one admin target row, or ErrNotFound.
func (s *Store) GetTarget(ctx context.Context, name string) (AdminTarget, error) {
	a, err := scanAdminTarget(s.pool.QueryRow(ctx, `SELECT `+adminColumns+` FROM targets WHERE name=$1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminTarget{}, ErrNotFound
	}
	return a, err
}

// TargetUsage counts what a replacement or removal of the definition with this
// stamp would end: the sessions issued under it and the per-user credentials
// enrolled under it.
func (s *Store) TargetUsage(ctx context.Context, name, stamp string) (sessions, enrolments int, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM sessions WHERE target=$1 AND stamp=$2),
		        (SELECT count(*) FROM user_credentials WHERE target=$1 AND stamp=$2)`,
		name, stamp).Scan(&sessions, &enrolments)
	return sessions, enrolments, err
}

// sealedFor returns the columns that depend on the mode. A static value is only
// kept for a static target, and fields only for a per_user one.
func (s *Store) sealedFor(t Target, rowID string) (sealedStatic, userFields []byte, err error) {
	if t.Mode == CredStatic {
		raw, err := json.Marshal(t.StaticHeaders)
		if err != nil {
			return nil, nil, err
		}
		if sealedStatic, err = s.admin.sealer.seal(staticPurpose(t.Name, rowID), raw); err != nil {
			return nil, nil, err
		}
	}
	if t.Mode == CredPerUser {
		if userFields, err = json.Marshal(t.UserFields); err != nil {
			return nil, nil, err
		}
	}
	return sealedStatic, userFields, nil
}

func normaliseAdminTarget(t Target) Target {
	t.UpstreamMCP = strings.TrimRight(strings.TrimSpace(t.UpstreamMCP), "/")
	t.DisplayName = strings.TrimSpace(t.DisplayName)
	t.Source = SourceAdmin
	return t
}

// bumpTargetsVersion runs in the transaction of every change, so a replica that
// sees the new version also sees the change.
func bumpTargetsVersion(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `UPDATE targets_version SET version = version + 1`)
	return err
}

// CreateTarget adds a target under a new row id and generation, so no stamp
// from an earlier holder of the name can match it.
func (s *Store) CreateTarget(ctx context.Context, t Target, by string) (AdminTarget, error) {
	if s.admin == nil {
		return AdminTarget{}, errors.New("admin targets are not enabled")
	}
	if by == "" {
		return AdminTarget{}, errors.New("a change needs the subject that made it")
	}
	t = normaliseAdminTarget(t)
	if err := s.checkAdminTarget(t); err != nil {
		return AdminTarget{}, &InvalidTargetError{err}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AdminTarget{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var rowID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text, gen_random_uuid()::text`).Scan(&rowID, &t.Generation); err != nil {
		return AdminTarget{}, err
	}
	sealedStatic, userFields, err := s.sealedFor(t, rowID)
	if err != nil {
		return AdminTarget{}, err
	}
	a, err := scanAdminTarget(tx.QueryRow(ctx,
		`INSERT INTO targets (name, display_name, upstream_mcp, mode, row_id, generation, stamp,
		                      sealed_static, user_fields, allowed_groups, updated_by)
		 VALUES ($1,$2,$3,$4,$5::uuid,$6::uuid,$7,$8,$9,$10,$11)
		 RETURNING `+adminColumns,
		t.Name, t.DisplayName, t.UpstreamMCP, string(t.Mode), rowID, t.Generation, t.Stamp(),
		sealedStatic, userFields, nonNil(t.AllowedGroups), by))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return AdminTarget{}, ErrTargetExists
	}
	if err != nil {
		return AdminTarget{}, err
	}
	if err := bumpTargetsVersion(ctx, tx); err != nil {
		return AdminTarget{}, err
	}
	return a, tx.Commit(ctx)
}

// nonNil keeps a nil slice from being sent as NULL to a NOT NULL column.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UpdateTarget replaces a target's definition, checked against key in the same
// transaction that applies it. Display name and allowed groups keep the stamp.
// A change to the URL, mode or per-user fields is a replacement: the generation
// is re-rolled so the stamp changes even if an earlier definition is put back.
//
// A static target keeps its sealed value when t carries none and the URL and
// mode are unchanged. Otherwise it must supply one, so a credential entered for
// one server is never silently sent to another.
func (s *Store) UpdateTarget(ctx context.Context, key TargetKey, t Target, by string) (AdminTarget, error) {
	if s.admin == nil {
		return AdminTarget{}, errors.New("admin targets are not enabled")
	}
	if by == "" {
		return AdminTarget{}, errors.New("a change needs the subject that made it")
	}
	if t.Name != key.Name {
		return AdminTarget{}, errors.New("a target cannot be renamed")
	}
	t = normaliseAdminTarget(t)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AdminTarget{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanAdminTarget(tx.QueryRow(ctx,
		`SELECT `+adminColumns+` FROM targets WHERE name=$1 AND row_id=$2::uuid AND revision=$3 FOR UPDATE`,
		key.Name, key.RowID, key.Revision))
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminTarget{}, ErrTargetChanged
	}
	if err != nil {
		return AdminTarget{}, err
	}

	if t.Mode == CredStatic && len(t.StaticHeaders) == 0 {
		if cur.Target.Mode != CredStatic || cur.Target.UpstreamMCP != t.UpstreamMCP {
			return AdminTarget{}, ErrStaticValueRequired
		}
		if t.StaticHeaders, err = s.openStatic(cur); err != nil {
			slog.Warn("the stored static value cannot be read", "target", key.Name, "err", err)
			return AdminTarget{}, &InvalidTargetError{errors.New("Static headers: the stored value cannot be read, so enter a new one.")}
		}
	}
	if err := s.checkAdminTarget(t); err != nil {
		return AdminTarget{}, &InvalidTargetError{err}
	}

	t.Generation = cur.Target.Generation
	if t.Stamp() != cur.StoredStamp {
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&t.Generation); err != nil {
			return AdminTarget{}, err
		}
	}
	sealedStatic, userFields, err := s.sealedFor(t, cur.RowID)
	if err != nil {
		return AdminTarget{}, err
	}
	a, err := scanAdminTarget(tx.QueryRow(ctx,
		`UPDATE targets SET display_name=$4, upstream_mcp=$5, mode=$6, generation=$7::uuid, stamp=$8,
		        sealed_static=$9, user_fields=$10, allowed_groups=$11,
		        revision=revision+1, updated_at=now(), updated_by=$12
		 WHERE name=$1 AND row_id=$2::uuid AND revision=$3
		 RETURNING `+adminColumns,
		key.Name, key.RowID, key.Revision, t.DisplayName, t.UpstreamMCP, string(t.Mode), t.Generation, t.Stamp(),
		sealedStatic, userFields, nonNil(t.AllowedGroups), by))
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminTarget{}, ErrTargetChanged
	}
	if err != nil {
		return AdminTarget{}, err
	}
	if err := bumpTargetsVersion(ctx, tx); err != nil {
		return AdminTarget{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AdminTarget{}, err
	}
	// Only a replacement leaves rows behind, and they are deleted after the
	// commit so the purge sees the new stamp.
	if a.StoredStamp != cur.StoredStamp {
		s.purgeAfterChange(ctx, key.Name)
	}
	return a, nil
}

// DeleteTarget removes a target, checked against key in its own transaction. The
// row's stamp then matches nothing, so everything issued under it is refused.
func (s *Store) DeleteTarget(ctx context.Context, key TargetKey) error {
	if s.admin == nil {
		return errors.New("admin targets are not enabled")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `DELETE FROM targets WHERE name=$1 AND row_id=$2::uuid AND revision=$3`,
		key.Name, key.RowID, key.Revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTargetChanged
	}
	if err := bumpTargetsVersion(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.purgeAfterChange(ctx, key.Name)
	return nil
}
