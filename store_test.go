package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// newTestStore connects to the database named by TEST_DATABASE_URL and clears
// it. Without that variable the database-backed tests skip, so `go test ./...`
// still works on a machine with no Postgres.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping the database-backed tests")
	}

	ctx := context.Background()
	s, err := NewStore(ctx, url, 30*24*time.Hour, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)

	// Sessions cascade into codes and tokens, so two deletes clear everything.
	for _, table := range []string{"sessions", "flows", "clients"} {
		if _, err := s.pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("clearing %s: %v", table, err)
		}
	}
	return s
}

func mustSession(t *testing.T, s *Store) string {
	t.Helper()
	id := newSecret()
	if err := s.CreateSession(context.Background(), id, "test-subject", "https://proxy.example/mcp", []byte("sealed")); err != nil {
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

	gotSession, gotClient, err := s.TakeRefreshToken(ctx, first)
	if err != nil {
		t.Fatalf("first use: %v", err)
	}
	if gotSession != session || gotClient != "c1" {
		t.Fatalf("first use returned (%q, %q), want (%q, %q)", gotSession, gotClient, session, "c1")
	}

	// Replaying it is the signature of a stolen token.
	_, _, err = s.TakeRefreshToken(ctx, first)
	if !errors.Is(err, ErrTokenReused) {
		t.Fatalf("replay: err = %v, want ErrTokenReused", err)
	}

	// An unknown token is a different answer, so the caller does not revoke a
	// session over a typo.
	if _, _, err := s.TakeRefreshToken(ctx, newSecret()); !errors.Is(err, ErrNotFound) {
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

	if _, _, err := s.LookupAccessToken(ctx, access); err != nil {
		t.Fatalf("access token should work before revocation: %v", err)
	}

	if err := s.RevokeSession(ctx, session); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("access token after revocation: err = %v, want ErrNotFound", err)
	}
	if _, _, err := s.TakeRefreshToken(ctx, refresh); !errors.Is(err, ErrNotFound) {
		t.Errorf("refresh token after revocation: err = %v, want ErrNotFound", err)
	}
	if _, err := s.TakeAuthCode(ctx, code); !errors.Is(err, ErrNotFound) {
		t.Errorf("auth code after revocation: err = %v, want ErrNotFound", err)
	}
	if _, err := s.SessionToken(ctx, session); !errors.Is(err, ErrNotFound) {
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
	if _, _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
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

	if _, _, err := s.LookupAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("access token outlived its session: err = %v, want ErrNotFound", err)
	}
	if _, _, err := s.TakeRefreshToken(ctx, refresh); errors.Is(err, nil) {
		t.Error("refresh succeeded against a session past its absolute lifetime")
	}
	if _, err := s.SessionToken(ctx, session); !errors.Is(err, ErrNotFound) {
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

	if _, _, err := s.TakeRefreshToken(ctx, refresh); !errors.Is(err, ErrNotFound) {
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

	if _, err := s.SessionToken(ctx, abandoned); !errors.Is(err, ErrNotFound) {
		t.Errorf("abandoned session survived the sweep: err = %v", err)
	}
	if _, err := s.SessionToken(ctx, live); err != nil {
		t.Errorf("session with a live token was swept: %v", err)
	}
	if _, err := s.GetClient(ctx, unused.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("unused client survived the sweep: err = %v", err)
	}
}

func TestUpdateSessionTokenReportsAVanishedSession(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	session := mustSession(t, s)

	if err := s.UpdateSessionToken(ctx, session, []byte("still here")); err != nil {
		t.Fatalf("update on a live session: %v", err)
	}

	// A revoked session must not accept a write. Postgres does not call an
	// UPDATE that matches nothing an error, so this has to be checked explicitly
	// or a refresh racing a revocation looks like it succeeded.
	if err := s.RevokeSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSessionToken(ctx, session, []byte("gone")); !errors.Is(err, ErrNotFound) {
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

	srv := &Server{store: s}
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
