package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TakeRefreshToken takes a refresh token outside a grant. Production always
// takes it inside one, so this lives with the tests.
func (s *Store) TakeRefreshToken(ctx context.Context, token, clientID string) (sessionID string, err error) {
	ref, err := s.takeRefreshToken(ctx, s.pool, token, clientID)
	return ref.ID, err
}

// newTestStore connects to the database named by TEST_DATABASE_URL and clears
// it. Without that variable the database-backed tests skip, so `go test ./...`
// still works on a machine with no Postgres. Under CI they fail instead: a
// green run that exercised none of the OAuth, proxy or settings tests is how
// two "passing" fixes shipped broken.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is not set under CI; the database-backed tests would be skipped")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping the database-backed tests")
	}

	ctx := context.Background()
	s, err := NewStore(ctx, url, 30*24*time.Hour, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)

	// Sessions cascade into codes and tokens, so these few deletes clear
	// everything. user_credentials is NOT among the cascades: it deliberately has
	// no foreign key to sessions, so it survives one and has to be cleared here
	// or an enrolment leaks into the next test and makes "not enrolled" pass.
	for _, table := range []string{"sessions", "flows", "settings_flows", "user_credentials", "stamp_seen", "targets", "clients"} {
		if _, err := s.pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("clearing %s: %v", table, err)
		}
	}
	return s
}

func mustSession(t *testing.T, s *Store) string {
	t.Helper()
	id := newSecret()
	if err := s.CreateSession(context.Background(), id, "test-subject", "https://proxy.example/mcp", "test", "config:test", []byte("sealed"), nil); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return id
}

func TestAuthCodeIsSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	code := newSecret()
	rec := AuthCode{SessionID: session, ClientID: "c1", RedirectURI: "https://app/cb", CodeChallenge: "chal"}
	if err := s.CreateAuthCode(ctx, code, rec); err != nil {
		t.Fatal(err)
	}

	got, err := s.TakeAuthCode(ctx, code)
	if err != nil {
		t.Fatalf("first TakeAuthCode: %v", err)
	}
	if got.SessionID != session || got.CodeChallenge != "chal" {
		t.Fatalf("TakeAuthCode returned %+v", got)
	}

	if _, err := s.TakeAuthCode(ctx, code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second TakeAuthCode: err = %v, want ErrNotFound", err)
	}
}

func TestAuthCodeStoredHashedNotPlain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	code := newSecret()
	if err := s.CreateAuthCode(ctx, code, AuthCode{SessionID: session, ClientID: "c1"}); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM auth_codes WHERE code_hash = $1::bytea`, []byte(code)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the authorization code is recoverable from the database in plain form")
	}
}

func TestRefreshTokenRotatesAndDetectsReuse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	first := newSecret()
	if err := s.CreateRefreshToken(ctx, first, session, "c1"); err != nil {
		t.Fatal(err)
	}

	gotSession, err := s.TakeRefreshToken(ctx, first, "c1")
	if err != nil {
		t.Fatalf("first use: %v", err)
	}
	if gotSession != session {
		t.Fatalf("first use returned %q, want %q", gotSession, session)
	}

	// Replaying it is the signature of a stolen token.
	_, err = s.TakeRefreshToken(ctx, first, "c1")
	if !errors.Is(err, ErrTokenReused) {
		t.Fatalf("replay: err = %v, want ErrTokenReused", err)
	}

	// An unknown token is a different answer, so the caller does not revoke a
	// session over a typo.
	if _, err := s.TakeRefreshToken(ctx, newSecret(), "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: err = %v, want ErrNotFound", err)
	}
}

func TestRevokeSessionKillsEveryCredential(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	access, refresh, code := newSecret(), newSecret(), newSecret()
	if err := s.CreateAccessToken(ctx, access, session, "c1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRefreshToken(ctx, refresh, session, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthCode(ctx, code, AuthCode{SessionID: session, ClientID: "c1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.LookupAccessToken(ctx, access); err != nil {
		t.Fatalf("access token should work before revocation: %v", err)
	}

	if err := s.RevokeSession(ctx, session); err != nil {
		t.Fatal(err)
	}

	if _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("access token after revocation: err = %v, want ErrNotFound", err)
	}
	if _, err := s.TakeRefreshToken(ctx, refresh, "c1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refresh token after revocation: err = %v, want ErrNotFound", err)
	}
	if _, err := s.TakeAuthCode(ctx, code); !errors.Is(err, ErrNotFound) {
		t.Errorf("auth code after revocation: err = %v, want ErrNotFound", err)
	}
	if _, err := s.SessionToken(ctx, session, "config:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("session after revocation: err = %v, want ErrNotFound", err)
	}
}

func TestFlowMustBeApprovedBeforeItCanBeRedeemed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	browser := newSecret()
	f := Flow{
		ID: newSecret(), ClientID: "c1", RedirectURI: "https://app/cb",
		ClientState: "st", CodeChallenge: "chal", UpstreamVerifier: newSecret(),
		BrowserSecret: browser,
	}
	if err := s.CreateFlow(ctx, f); err != nil {
		t.Fatal(err)
	}

	// This is the callback's view. Without consent there is nothing to redeem.
	if _, err := s.TakeApprovedFlow(ctx, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unapproved flow was redeemable: err = %v, want ErrNotFound", err)
	}

	// Knowing the flow id is not enough. Anyone can call /authorize and read one
	// out of the page, so approval needs the secret only that browser holds.
	if _, err := s.ApproveFlow(ctx, f.ID, newSecret()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ApproveFlow with the wrong browser secret: err = %v, want ErrNotFound", err)
	}
	if _, err := s.ApproveFlow(ctx, f.ID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ApproveFlow with no browser secret: err = %v, want ErrNotFound", err)
	}

	if _, err := s.ApproveFlow(ctx, f.ID, browser); err != nil {
		t.Fatalf("ApproveFlow: %v", err)
	}
	// Approving twice must not work either, so a resubmitted consent form cannot
	// start a second authorization.
	if _, err := s.ApproveFlow(ctx, f.ID, browser); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second ApproveFlow: err = %v, want ErrNotFound", err)
	}

	got, err := s.TakeApprovedFlow(ctx, f.ID)
	if err != nil {
		t.Fatalf("TakeApprovedFlow after approval: %v", err)
	}
	if got.UpstreamVerifier != f.UpstreamVerifier {
		t.Error("TakeApprovedFlow returned the wrong verifier")
	}

	// And the callback is single use.
	if _, err := s.TakeApprovedFlow(ctx, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed callback: err = %v, want ErrNotFound", err)
	}
}

func TestExpiredCredentialsAreRefused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	access := newSecret()
	if err := s.CreateAccessToken(ctx, access, session, "c1", -time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired access token: err = %v, want ErrNotFound", err)
	}

	code := newSecret()
	if err := s.CreateAuthCode(ctx, code, AuthCode{SessionID: session, ClientID: "c1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE auth_codes SET created_at = now() - INTERVAL '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeAuthCode(ctx, code); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired auth code: err = %v, want ErrNotFound", err)
	}
}

func TestSessionLifetimeOutranksTokenLifetime(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	access, refresh := newSecret(), newSecret()
	if err := s.CreateAccessToken(ctx, access, session, "c1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRefreshToken(ctx, refresh, session, "c1"); err != nil {
		t.Fatal(err)
	}

	// Age the session past its absolute lifetime while both tokens stay young.
	if _, err := s.pool.Exec(ctx,
		`UPDATE sessions SET created_at = now() - INTERVAL '100 days' WHERE id = $1`, session); err != nil {
		t.Fatal(err)
	}

	if _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("access token outlived its session: err = %v, want ErrNotFound", err)
	}
	if _, err := s.TakeRefreshToken(ctx, refresh, "c1"); errors.Is(err, nil) {
		t.Error("refresh succeeded against a session past its absolute lifetime")
	}
	if _, err := s.SessionToken(ctx, session, "config:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SessionToken on an over-age session: err = %v, want ErrNotFound", err)
	}
}

func TestRefreshTokenExpires(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	refresh := newSecret()
	if err := s.CreateRefreshToken(ctx, refresh, session, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET created_at = now() - INTERVAL '31 days'`); err != nil {
		t.Fatal(err)
	}

	if _, err := s.TakeRefreshToken(ctx, refresh, "c1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired refresh token: err = %v, want ErrNotFound", err)
	}
}

func TestSweepClearsAbandonedSessionsAndClients(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// A session whose authorization code was never redeemed. It holds a live
	// upstream token that nothing can reach.
	abandoned := mustSession(t, s)
	// A session with a live token, which must survive.
	live := mustSession(t, s)
	if err := s.CreateAccessToken(ctx, newSecret(), live, "c1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE sessions SET created_at = now() - INTERVAL '2 hours'`); err != nil {
		t.Fatal(err)
	}

	unused := Client{ID: newSecret(), Name: "never used", RedirectURIs: []string{"https://a/cb"}}
	if err := s.CreateClient(ctx, unused); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE clients SET created_at = now() - INTERVAL '31 days'`); err != nil {
		t.Fatal(err)
	}

	if err := s.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if _, err := s.SessionToken(ctx, abandoned, "config:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("abandoned session survived the sweep: err = %v", err)
	}
	if _, err := s.SessionToken(ctx, live, "config:test"); err != nil {
		t.Errorf("session with a live token was swept: %v", err)
	}
	if _, err := s.GetClient(ctx, unused.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("unused client survived the sweep: err = %v", err)
	}
}

func TestEmptyStampSessionsAreRefused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	id := newSecret()
	if err := s.CreateSession(ctx, id, "sub", "https://p/mcp", "", "", []byte("sealed"), nil); err != nil {
		t.Fatal(err)
	}
	access := newSecret()
	if err := s.CreateAccessToken(ctx, access, id, "client", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty-stamp session was honoured: %v", err)
	}
	if _, err := s.SessionToken(ctx, id, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty stamp read a token: %v", err)
	}
}

func TestSessionTokenRequiresTheSessionsStamp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := newSecret()
	if err := s.CreateSession(ctx, id, "sub", "r", "plane", "config:a", []byte("sealed"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionToken(ctx, id, "config:a"); err != nil {
		t.Fatalf("matching stamp: %v", err)
	}
	if _, err := s.SessionToken(ctx, id, "config:b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a different stamp read the token: %v", err)
	}
	if err := s.UpdateSessionToken(ctx, id, "config:b", []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a different stamp wrote the token: %v", err)
	}
}

func TestUpdateSessionTokenReportsAVanishedSession(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	if err := s.UpdateSessionToken(ctx, session, "config:test", []byte("still here")); err != nil {
		t.Fatalf("update on a live session: %v", err)
	}

	// A revoked session must not accept a write. Postgres does not call an
	// UPDATE that matches nothing an error, so this has to be checked explicitly
	// or a refresh racing a revocation looks like it succeeded.
	if err := s.RevokeSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSessionToken(ctx, session, "config:test", []byte("gone")); !errors.Is(err, ErrNotFound) {
		t.Errorf("update on a revoked session: err = %v, want ErrNotFound", err)
	}
}

// TestMigrateUpgradesAnOlderSchema runs the migration against a database shaped
// like the previous version's: a resource column that is now unused, and none
// of the columns the consent gate and reuse detection need. Migration runs on
// every boot, so an existing deployment takes this path rather than the
// CREATE TABLE one, and it is the path least likely to be exercised by hand.
func TestMigrateUpgradesAnOlderSchema(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Rebuild the old shape: drop what this version added, put back what it
	// removed.
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS auth_codes, access_tokens, refresh_tokens, flows, sessions, clients CASCADE`,
		`CREATE TABLE clients (
			client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL DEFAULT '',
			redirect_uris TEXT[] NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE TABLE sessions (
			id TEXT PRIMARY KEY, subject TEXT NOT NULL DEFAULT '',
			upstream_token BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE TABLE flows (
			id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
			client_state TEXT NOT NULL DEFAULT '', code_challenge TEXT NOT NULL,
			upstream_verifier TEXT NOT NULL, resource TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE TABLE auth_codes (
			code_hash BYTEA PRIMARY KEY,
			session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL, resource TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE TABLE access_tokens (
			token_hash BYTEA PRIMARY KEY,
			session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			client_id TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL)`,
		`CREATE TABLE refresh_tokens (
			token_hash BYTEA PRIMARY KEY,
			session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			client_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
	} {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("building the old schema: %v", err)
		}
	}

	if err := s.migrate(ctx); err != nil {
		t.Fatalf("migrate against an older schema: %v", err)
	}

	hasColumn := func(table, column string) bool {
		var n int
		if err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.columns
			 WHERE table_name = $1 AND column_name = $2`, table, column).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	// auth_codes.resource stays dropped. The audience belongs to the session, not
	// to each credential minted against it, so threading it through the code adds
	// a second place for the same fact to be wrong.
	if hasColumn("auth_codes", "resource") {
		t.Error("auth_codes still carries the unused resource column after migrating")
	}
	for _, c := range []struct{ table, column string }{
		{"flows", "approved"},
		{"flows", "browser_hash"},
		// resource is back on flows, and new on sessions. It carries the chosen
		// target from /authorize to /callback and then bounds what the resulting
		// token may be used against, so an upgraded database must gain both.
		{"flows", "resource"},
		{"sessions", "resource"},
		{"refresh_tokens", "used"},
		{"refresh_tokens", "used_at"},
	} {
		if !hasColumn(c.table, c.column) {
			t.Errorf("migrate did not add %s.%s", c.table, c.column)
		}
	}

	// The upgraded schema must actually work, not merely have the right columns.
	browser := newSecret()
	f := Flow{
		ID: newSecret(), ClientID: "c1", RedirectURI: "https://app/cb",
		CodeChallenge: "chal", UpstreamVerifier: newSecret(), BrowserSecret: browser,
	}
	if err := s.CreateFlow(ctx, f); err != nil {
		t.Fatalf("CreateFlow on the upgraded schema: %v", err)
	}
	if _, err := s.ApproveFlow(ctx, f.ID, browser); err != nil {
		t.Fatalf("ApproveFlow on the upgraded schema: %v", err)
	}
	if _, err := s.TakeApprovedFlow(ctx, f.ID); err != nil {
		t.Fatalf("TakeApprovedFlow on the upgraded schema: %v", err)
	}

	// Migration runs on every boot, so it has to be safe to repeat.
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("migrate is not idempotent: %v", err)
	}
}

// TestSweepKeepsClientsWithAnOutstandingCode covers the window between
// /callback and /token, where a client is referenced only by its authorization
// code. Sweeping it there let the token exchange succeed while the next
// /authorize failed with "unknown client_id", forcing a surprise re-registration.
func TestSweepKeepsClientsWithAnOutstandingCode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	// A long-idle client that has just reached /callback: its flow is consumed,
	// an authorization code exists, and no tokens have been issued yet.
	pending := Client{ID: newSecret(), Name: "mid-exchange", RedirectURIs: []string{"https://a/cb"}}
	if err := s.CreateClient(ctx, pending); err != nil {
		t.Fatal(err)
	}
	code := newSecret()
	if err := s.CreateAuthCode(ctx, code, AuthCode{SessionID: session, ClientID: pending.ID}); err != nil {
		t.Fatal(err)
	}

	// A client that really is abandoned: nothing refers to it at all.
	abandoned := Client{ID: newSecret(), Name: "abandoned", RedirectURIs: []string{"https://b/cb"}}
	if err := s.CreateClient(ctx, abandoned); err != nil {
		t.Fatal(err)
	}

	if _, err := s.pool.Exec(ctx, `UPDATE clients SET created_at = now() - INTERVAL '31 days'`); err != nil {
		t.Fatal(err)
	}

	if err := s.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if _, err := s.GetClient(ctx, pending.ID); err != nil {
		t.Errorf("a client mid-exchange was swept: %v", err)
	}
	if _, err := s.GetClient(ctx, abandoned.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("an abandoned client survived the sweep: err = %v", err)
	}
}

// TestSweepBoundsRegistrationsThatNeverFinished pins unusedClientTTL to a day.
// /register admits 20 registrations a minute per address and each may carry
// 32 KB of redirect URIs; at the old 30-day TTL that grew by 27 GB per address
// before the sweep freed anything. A registration that got as far as a token
// is held by its refresh token row and is unaffected.
func TestSweepBoundsRegistrationsThatNeverFinished(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	mkClient := func(name string) Client {
		c := Client{ID: newSecret(), Name: name, RedirectURIs: []string{"https://a/cb"}}
		if err := s.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	stale := mkClient("never finished, a day ago")
	fresh := mkClient("never finished, this hour")
	authorized := mkClient("finished, a day ago")
	if err := s.CreateRefreshToken(ctx, newSecret(), mustSession(t, s), authorized.ID); err != nil {
		t.Fatal(err)
	}
	// Past the TTL, though not by the 30 days the sweep used to wait.
	if _, err := s.pool.Exec(ctx,
		`UPDATE clients SET created_at = now() - INTERVAL '25 hours' WHERE client_id <> $1`, fresh.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if _, err := s.GetClient(ctx, stale.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a registration that never finished survived a day: err = %v", err)
	}
	if _, err := s.GetClient(ctx, fresh.ID); err != nil {
		t.Errorf("a registration made this hour was swept: %v", err)
	}
	if _, err := s.GetClient(ctx, authorized.ID); err != nil {
		t.Errorf("a client holding a refresh token was swept: %v", err)
	}
}

// TestSweepRunsAtStartup pins the first pass to process start. The loop used to
// wait a full interval before its first sweep, so a deployment that rolls or
// crash-loops more often than that never swept at all, and expired sessions
// kept their encrypted provider token indefinitely.
func TestSweepRunsAtStartup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stale := mustSession(t, s)
	if _, err := s.pool.Exec(ctx,
		`UPDATE sessions SET created_at = now() - INTERVAL '100 days' WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}

	srv := &Server{store: s, cfg: &Config{}, reg: testRegistry(t, Target{Name: "plane", UpstreamMCP: "https://plane.example/mcp"})}
	swept, cancel := context.WithCancel(ctx)
	go srv.sweep(swept)

	// Poll the row itself, not SessionToken: that already filters on the session
	// lifetime, so it reports "not found" for this session whether or not the
	// sweep ever ran. The point here is that the row, and the encrypted provider
	// token in it, is actually gone.
	rows := func() int {
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = $1`, stale).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	deadline := time.Now().Add(10 * time.Second)
	for rows() != 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the session past its lifetime survived; the sweep did not run at startup (interval is %s)", sweepInterval)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
}

func TestCredentialKeyMigratesInPlace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Put the table back in the shape the previous release created.
	if _, err := s.pool.Exec(ctx, `
DROP TABLE user_credentials;
CREATE TABLE user_credentials (
    subject TEXT NOT NULL, target TEXT NOT NULL, sealed_headers BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (subject, target));
INSERT INTO user_credentials (subject, target, sealed_headers) VALUES ('u', 'plane', '\x01');`); err != nil {
		t.Fatal(err)
	}

	for range 2 { // the second run must be a no-op
		if err := s.migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}

	var stamp string
	if err := s.pool.QueryRow(ctx, `SELECT stamp FROM user_credentials WHERE subject='u' AND target='plane'`).Scan(&stamp); err != nil || stamp != "" {
		t.Fatalf("existing row: stamp %q, err %v", stamp, err)
	}
	if err := s.PutUserCredential(ctx, "u", "plane", "config:a", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUserCredential(ctx, "u", "plane", "config:b", []byte("b")); err != nil {
		t.Fatalf("a second stamp for the same user and target must coexist: %v", err)
	}
}

func TestCredentialsUnderDifferentStampsCoexist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutUserCredential(ctx, "u", "plane", "config:a", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUserCredential(ctx, "u", "plane", "config:b", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUserCredential(ctx, "u", "plane", "config:a", []byte("A2")); err != nil { // replaces its own
		t.Fatal(err)
	}

	if err := s.DeleteUserCredential(ctx, "u", "plane", "config:a"); err != nil {
		t.Fatal(err)
	}
	got, err := s.EnrolledTargets(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[StampedName{"plane", "config:a"}]; ok {
		t.Error("clear for one stamp left its own row")
	}
	if _, ok := got[StampedName{"plane", "config:b"}]; !ok {
		t.Error("clear for one stamp removed another stamp's row")
	}
}

func TestCredentialIsReadOnlyThroughASessionWithTheSameStamp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := newSecret()
	if err := s.CreateSession(ctx, id, "u", "r", "plane", "config:a", []byte("tok"), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUserCredential(ctx, "u", "plane", "config:b", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UserCredentialForSession(ctx, id, "plane"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a credential for another stamp was returned: %v", err)
	}
	if err := s.PutUserCredential(ctx, "u", "plane", "config:a", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if b, _, err := s.UserCredentialForSession(ctx, id, "plane"); err != nil || string(b) != "A" {
		t.Errorf("got %q, %v; want the credential for the session's own stamp", b, err)
	}
}

func TestEmptyStampCredentialIsRefused(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutUserCredential(context.Background(), "u", "plane", "", []byte("x")); err == nil {
		t.Error("stored a credential with no stamp")
	}
}

func TestCredentialKeyMigrationOnAFreshDatabase(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `DROP TABLE user_credentials`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	for _, stamp := range []string{"config:a", "config:b"} {
		if err := s.PutUserCredential(ctx, "u", "plane", stamp, []byte("x")); err != nil {
			t.Fatalf("stamp %s: %v", stamp, err)
		}
	}
}

func TestSweepRemovesEmptyStampRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	empty, kept := newSecret(), newSecret()
	for _, c := range []struct{ id, stamp string }{{empty, ""}, {kept, "config:a"}} {
		if err := s.CreateSession(ctx, c.id, "u", "r", "plane", c.stamp, []byte("x"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO user_credentials (subject,target,stamp,sealed_headers) VALUES ('u','plane','','\x01')`); err != nil {
		t.Fatal(err)
	}
	emptyFlow, keptFlow := newSecret(), newSecret()
	for _, c := range []struct{ id, stamp string }{{emptyFlow, ""}, {keptFlow, "config:a"}} {
		if err := s.CreateFlow(ctx, Flow{ID: c.id, ClientID: "c", RedirectURI: "r", CodeChallenge: "x", UpstreamVerifier: "v", Target: "plane", Stamp: c.stamp, BrowserSecret: "b"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM flows WHERE id=$1`, emptyFlow).Scan(&n)
	if n != 0 {
		t.Error("empty-stamp flow survived")
	}
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM flows WHERE id=$1`, keptFlow).Scan(&n)
	if n != 1 {
		t.Error("stamped flow was swept")
	}
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=$1`, empty).Scan(&n)
	if n != 0 {
		t.Error("empty-stamp session survived")
	}
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=$1`, kept).Scan(&n)
	if n != 1 {
		t.Error("stamped session was swept")
	}
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM user_credentials WHERE stamp=''`).Scan(&n)
	if n != 0 {
		t.Error("empty-stamp credential survived")
	}
}

func TestSweepStrayCredentials(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saved14d, saved8d, now := `now() - INTERVAL '14 days'`, `now() - INTERVAL '8 days'`, `now()`
	cases := []struct {
		target, stamp, saved string
		survives             bool
	}{
		{"plane", "config:live", saved14d, true},        // this process serves it: seen now
		{"plane", "config:seen-1d", saved14d, true},     // another pod served it yesterday
		{"plane", "config:never-seen", saved14d, false}, // old and nobody has served it
		{"plane", "config:seen-8d", saved14d, false},    // last served more than a week ago
		{"plane", "config:recent", now, true},           // saved just now, never seen: protected by updated_at
		{"plane", "admin:x", saved14d, true},            // not a config stamp: not this sweep's to delete
		{"other", "config:live", saved8d, false},        // only ("plane", "config:live") was served, not this name
	}
	for _, c := range cases {
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO user_credentials (subject,target,stamp,sealed_headers,updated_at) VALUES ('u',$1,$2,'\x01',`+c.saved+`)`,
			c.target, c.stamp); err != nil {
			t.Fatal(err)
		}
	}
	for stamp, ago := range map[string]string{"config:seen-1d": "1 day", "config:seen-8d": "8 days"} {
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO stamp_seen (target,stamp,seen_at) VALUES ('plane',$1, now() - $2::interval)`, stamp, ago); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordServedStamps(ctx, []StampedName{{"plane", "config:live"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SweepStrayCredentials(ctx); err != nil {
		t.Fatal(err)
	}

	got, _ := s.EnrolledTargets(ctx, "u")
	for _, c := range cases {
		if _, present := got[StampedName{c.target, c.stamp}]; present != c.survives {
			t.Errorf("%s/%s: present=%v, want %v", c.target, c.stamp, present, c.survives)
		}
	}
}

func TestRecordServedStampsRefreshesAndToleratesEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordServedStamps(ctx, nil); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO stamp_seen (target,stamp,seen_at) VALUES ('plane','config:a', now() - INTERVAL '3 days')`); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordServedStamps(ctx, []StampedName{{"plane", "config:a"}, {"plane", "config:b"}}); err != nil {
		t.Fatal(err)
	}
	var fresh int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM stamp_seen WHERE seen_at > now() - INTERVAL '1 minute'`).Scan(&fresh); err != nil || fresh != 2 {
		t.Fatalf("fresh rows = %d, err %v; want both pairs recorded and the old one refreshed", fresh, err)
	}
}

func TestSweepRemovesOldStampSeenRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for stamp, ago := range map[string]string{"config:old": "31 days", "config:kept": "29 days"} {
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO stamp_seen (target,stamp,seen_at) VALUES ('plane',$1, now() - $2::interval)`, stamp, ago); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var old, kept int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM stamp_seen WHERE stamp='config:old'`).Scan(&old)
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM stamp_seen WHERE stamp='config:kept'`).Scan(&kept)
	if old != 0 || kept != 1 {
		t.Errorf("old=%d kept=%d; want the 31 day row removed and the 29 day row kept", old, kept)
	}
}

// When recording the served stamps fails, the stray sweep must not run: the
// credential below is old and stamp_seen has no row for it, so a sweep would
// delete a definition this process is serving.
func TestSweepOnceSkipsStraySweepWhenRecordingFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	plane := Target{Name: "plane", UpstreamMCP: "https://plane.example/mcp"}
	srv := &Server{store: s, cfg: &Config{Targets: []Target{plane}}, reg: testRegistry(t, plane)}
	stamp := plane.Stamp()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO user_credentials (subject,target,stamp,sealed_headers,updated_at) VALUES ('u','plane',$1,'\x01', now() - INTERVAL '14 days')`, stamp); err != nil {
		t.Fatal(err)
	}

	// A trigger that rejects inserts makes RecordServedStamps fail while the
	// stray sweep, which only reads stamp_seen, would still succeed.
	if _, err := s.pool.Exec(ctx, `
CREATE FUNCTION reject_stamp_seen() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'rejected'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER reject_stamp_seen BEFORE INSERT ON stamp_seen FOR EACH ROW EXECUTE FUNCTION reject_stamp_seen();`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DROP TRIGGER reject_stamp_seen ON stamp_seen; DROP FUNCTION reject_stamp_seen();`)
	})

	srv.sweepOnce(ctx)

	got, _ := s.EnrolledTargets(ctx, "u")
	if _, present := got[StampedName{"plane", stamp}]; !present {
		t.Error("credential for a served definition was deleted after recording failed")
	}
}

// legacyCredentialsTable puts user_credentials back in the shape the previous
// release created, in the default schema.
func legacyCredentialsTable(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `
DROP TABLE user_credentials;
CREATE TABLE user_credentials (
    subject TEXT NOT NULL, target TEXT NOT NULL, sealed_headers BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (subject, target));
INSERT INTO user_credentials (subject, target, sealed_headers) VALUES ('u', 'plane', '\x01');`); err != nil {
		t.Fatal(err)
	}
}

// storeWithSearchPath opens a second store on the same database whose
// connections resolve unqualified names through an empty schema first.
func storeWithSearchPath(t *testing.T, s *Store, emptySchema string) *Store {
	t.Helper()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+emptySchema+` CASCADE; CREATE SCHEMA `+emptySchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+emptySchema+` CASCADE`) })

	cfg := s.pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["search_path"] = emptySchema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool, refreshTTL: s.refreshTTL, sessionTTL: s.sessionTTL}
}

func TestCredentialKeyMigrationFindsTheTableThroughSearchPath(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	legacyCredentialsTable(t, s)
	other := storeWithSearchPath(t, s, "mop_empty")

	// The block that rewrites the key, on its own: the rest of migrate would
	// create fresh tables in the empty schema and hide a wrong lookup. The stamp
	// column is the step migrate takes just before it.
	if _, err := s.pool.Exec(ctx, `ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS stamp TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.pool.Exec(ctx, credentialKeyMigration); err != nil {
		t.Fatal(err)
	}
	for _, stamp := range []string{"config:a", "config:b"} {
		if err := s.PutUserCredential(ctx, "u", "plane", stamp, []byte("x")); err != nil {
			t.Fatalf("stamp %s: %v", stamp, err)
		}
	}
}

func TestMigrateWithAnEmptySchemaFirstOnTheSearchPath(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	legacyCredentialsTable(t, s)
	other := storeWithSearchPath(t, s, "mop_empty2")

	for range 2 {
		if err := other.migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	if err := other.PutUserCredential(ctx, "u", "plane", "config:a", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := other.PutUserCredential(ctx, "u", "plane", "config:b", []byte("b")); err != nil {
		t.Fatalf("a second stamp for the same user and target must coexist: %v", err)
	}
}
