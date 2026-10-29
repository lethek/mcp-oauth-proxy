package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The races below are forced, not hoped for. An "edit" is a transaction the test
// holds open on its own connection: it has replaced the target's stamp and not
// committed, so it holds the row lock a real edit holds. The code under test
// runs on another connection, the test waits until Postgres reports it blocked
// on that lock (or finished), and only then commits the edit. Every wait is
// bounded, and the edit is rolled back in a defer so a failing test cannot leave
// anything blocked.

const raceWait = 10 * time.Second

// holdEdit replaces the stamp of the named admin target inside a transaction it
// does not commit. The caller must defer release.
func holdEdit(t *testing.T, s *Store, name string) (tx pgx.Tx, release func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), raceWait)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE targets SET stamp='admin:held-edit', revision=revision+1 WHERE name=$1`, name); err != nil {
		_ = tx.Rollback(ctx)
		cancel()
		t.Fatal(err)
	}
	return tx, func() { _ = tx.Rollback(ctx); cancel() }
}

// blockedOn reports whether some backend is waiting on a lock while running a
// statement that matches like, polling for up to raceWait.
func blockedOn(s *Store, like string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), raceWait)
	defer cancel()
	for {
		var n int
		err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity
			  WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE $1`, like).Scan(&n)
		if err == nil && n > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// commitAfterBlocked commits the held edit once the code under test is either
// waiting on its lock or already past it. It returns whether it was waiting.
// done reports the code under test finishing.
func commitAfterBlocked(t *testing.T, s *Store, tx pgx.Tx, like string, done <-chan struct{}) (waited bool) {
	t.Helper()
	waiting := make(chan bool, 1)
	go func() { waiting <- blockedOn(s, like) }()
	select {
	case waited = <-waiting:
	case <-done:
		waited = false
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return waited
}

func (h *harness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.srv.store.pool.QueryRow(h.t.Context(), query, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// approvedCallbackURL takes a flow through consent and the provider's redirect
// and returns the /callback URL, without following it.
func (h *harness) approvedCallbackURL(clientID, redirect, resource string) string {
	h.t.Helper()
	flowID := h.consentFlowID(h.get(h.authorizeURLFor(clientID, redirect, s256(newSecret()), resource)))
	consent := h.postForm("/consent", url.Values{"flow_id": {flowID}, "decision": {"approve"}})
	consent.Body.Close()
	toProvider := h.get(consent.Header.Get("Location"))
	toProvider.Body.Close()
	return toProvider.Header.Get("Location")
}

// callbackOutcome follows the callback and returns the error the client is sent
// back with, or "" when it was sent a code.
// It returns errors rather than failing the test, so it is safe off the test
// goroutine.
func callbackOutcome(h *harness, callbackURL string) (errCode string, err error) {
	resp, err := h.client.Get(callbackURL)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", err
	}
	return back.Query().Get("error"), nil
}

// A callback that took its approved flow before an admin edit cannot create a
// session after it. The edit is held open, so the fenced insert has to wait for
// it; a plain read of the stamp would not wait, and would insert.
func TestCallbackThatTookItsFlowBeforeAnEditCannotCreateASession(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.srv.store.skipCleanup = true // the fence is under test, not the purge
	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()

	clientID := h.register(testRedirect)
	callbackURL := h.approvedCallbackURL(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")

	tx, release := holdEdit(t, h.srv.store, "gamma")
	defer release()

	type outcome struct {
		code string
		err  error
	}
	result := make(chan outcome, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		code, err := callbackOutcome(h, callbackURL)
		result <- outcome{code, err}
	}()
	if !commitAfterBlocked(t, h.srv.store, tx, "%FOR SHARE%", finished) {
		t.Error("the insert did not wait for the edit's row lock")
	}

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.code != "temporarily_unavailable" {
			t.Errorf("callback error = %q, want temporarily_unavailable", got.code)
		}
	case <-time.After(raceWait):
		t.Fatal("the callback never finished")
	}
	if n := h.count(`SELECT count(*) FROM sessions`); n != 0 {
		t.Errorf("%d session(s) exist, want none", n)
	}
}

// A replica that has not seen an allowed_groups change still holds the old
// groups in its snapshot. The callback judges the user against the groups the
// fence reads, so it refuses someone the target no longer admits.
func TestCallbackOnALaggingReplicaRefusesAUserTheNewGroupsExclude(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	in := h.adminTarget("gamma", "/alpha-upstream")
	in.AllowedGroups = []string{"staff"}
	created := h.createAdmin(in)
	h.rebuild()
	groups := []string{"staff"}
	h.groups.Store(&groups)

	clientID := h.register(testRedirect)
	callbackURL := h.approvedCallbackURL(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")

	h.holdRebuilds()
	in.AllowedGroups = []string{"contractors"}
	next, err := h.srv.store.UpdateTarget(t.Context(), TargetKey{"gamma", created.RowID, created.Revision}, in, "root")
	if err != nil {
		t.Fatal(err)
	}
	if next.StoredStamp != created.StoredStamp {
		t.Fatal("changing allowed_groups moved the stamp, so this is not the lagging case")
	}
	if got := h.srv.reg.Load().byName["gamma"].Target.AllowedGroups; len(got) != 1 || got[0] != "staff" {
		t.Fatalf("the replica's snapshot has %v; it should still lag", got)
	}

	if got, err := callbackOutcome(h, callbackURL); err != nil || got != "access_denied" {
		t.Errorf("callback error = %q (err %v), want access_denied", got, err)
	}
	if n := h.count(`SELECT count(*) FROM sessions`); n != 0 {
		t.Errorf("%d session(s) exist, want none", n)
	}
}

// A settings save that starts before an admin edit and commits after it stores
// nothing, and the page asks for a reload instead of saying "Credential saved".
func TestSettingsSaveStraddlingAnEditStoresNothing(t *testing.T) {
	h := newHarnessWith(t, adminPerUserTargets)
	h.srv.store.skipCleanup = true
	h.createAdmin(Target{
		Name: "gamma", DisplayName: "Gamma", UpstreamMCP: h.provider.URL + "/alpha-upstream", Mode: CredPerUser,
		UserFields: []UserHeaderField{{Header: "Authorization", Label: "Token", Prefix: "Bearer "}},
	})
	h.rebuild()
	h.signIntoSettings()
	stamp := h.srv.reg.Load().byName["gamma"].Stamp

	tx, release := holdEdit(t, h.srv.store, "gamma")
	defer release()

	type reply struct {
		status int
		body   string
		err    error
	}
	result := make(chan reply, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		resp, err := h.client.PostForm(h.proxy.URL+"/settings", url.Values{
			"target": {"gamma"}, "stamp": {stamp}, "action": {"save"}, "field_Authorization": {"typed-for-the-old-definition"},
		})
		if err != nil {
			result <- reply{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		result <- reply{status: resp.StatusCode, body: string(b)}
	}()
	if !commitAfterBlocked(t, h.srv.store, tx, "%FOR SHARE%", finished) {
		t.Error("the write did not wait for the edit's row lock")
	}

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.status != http.StatusConflict || !strings.Contains(got.body, "Settings changed") {
			t.Errorf("status %d, body %q; want 409 and a reload prompt", got.status, got.body)
		}
	case <-time.After(raceWait):
		t.Fatal("the save never finished")
	}
	if n := h.count(`SELECT count(*) FROM user_credentials`); n != 0 {
		t.Errorf("%d credential(s) stored, want none", n)
	}
}

// A provider refresh that straddles a replacement writes nothing to the
// session. The session keeps its own (old) stamp, so only the fence can refuse.
func TestProviderRefreshStraddlingAReplacementWritesNothing(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.srv.store.skipCleanup = true
	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()
	gamma := h.srv.reg.Load().byName["gamma"].Target

	sessionID := newSecret()
	old := UpstreamToken{AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Hour)}
	if err := h.srv.createSession(t.Context(), sessionID, "subject", gamma.Resource, gamma, old, nil); err != nil {
		t.Fatal(err)
	}
	sealedBefore, err := h.srv.store.SessionToken(t.Context(), sessionID, gamma.Stamp())
	if err != nil {
		t.Fatal(err)
	}

	tx, release := holdEdit(t, h.srv.store, "gamma")
	defer release()

	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ctx, cancel := context.WithTimeout(context.Background(), raceWait)
		defer cancel()
		result <- h.srv.persistRefreshed(ctx, sessionID, gamma.Stamp(),
			UpstreamToken{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresAt: time.Now().Add(time.Hour)})
	}()
	if !commitAfterBlocked(t, h.srv.store, tx, "%FOR SHARE%", finished) {
		t.Error("the write-back did not wait for the edit's row lock")
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrStaleTarget) {
			t.Errorf("err = %v, want ErrStaleTarget", err)
		}
	case <-time.After(raceWait):
		t.Fatal("the write-back never finished")
	}
	var sealedAfter []byte
	err = h.srv.store.pool.QueryRow(t.Context(), `SELECT upstream_token FROM sessions WHERE id=$1`, sessionID).Scan(&sealedAfter)
	if err != nil {
		t.Fatal(err)
	}
	if string(sealedAfter) != string(sealedBefore) {
		t.Error("the refreshed token was written to a session of the replaced definition")
	}
}

// Removing a target and adding the name again resurrects nothing, and a form for
// the old row cannot apply to the new one even though both are at revision 1.
func TestRemoveThenReAddResurrectsNothing(t *testing.T) {
	h := newHarnessWith(t, adminPerUserTargets)
	store := h.srv.store
	ctx := t.Context()
	in := Target{
		Name: "gamma", DisplayName: "Gamma", UpstreamMCP: h.provider.URL + "/alpha-upstream", Mode: CredPerUser,
		UserFields: []UserHeaderField{{Header: "Authorization", Label: "Token", Prefix: "Bearer "}},
	}
	first := h.createAdmin(in)
	oldStamp := first.StoredStamp

	sessionID := newSecret()
	if err := store.CreateSession(ctx, sessionID, "user-42", "", "gamma", oldStamp, []byte("s"), nil); err != nil {
		t.Fatal(err)
	}
	if err := store.PutUserCredential(ctx, "user-42", "gamma", oldStamp, []byte("c")); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateFlow(ctx, Flow{ID: newSecret(), ClientID: "c", RedirectURI: "r", Target: "gamma", Stamp: oldStamp}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteTarget(ctx, TargetKey{"gamma", first.RowID, first.Revision}); err != nil {
		t.Fatal(err)
	}
	again := h.createAdmin(in)
	if again.Revision != first.Revision {
		t.Fatalf("revisions %d and %d differ, so this is not the revision-1 case", first.Revision, again.Revision)
	}

	for _, table := range []string{"sessions", "user_credentials", "flows"} {
		if n := h.count(`SELECT count(*) FROM ` + table + ` WHERE target='gamma'`); n != 0 {
			t.Errorf("%d %s row(s) survived the removal", n, table)
		}
	}
	// Late writes for the old definition are refused, not accepted and left
	// for a purge.
	if err := store.CreateSession(ctx, newSecret(), "user-42", "", "gamma", oldStamp, []byte("s"), nil); !errors.Is(err, ErrStaleTarget) {
		t.Errorf("session under the old stamp: err = %v, want ErrStaleTarget", err)
	}
	if err := store.PutUserCredential(ctx, "user-42", "gamma", oldStamp, []byte("c")); !errors.Is(err, ErrStaleTarget) {
		t.Errorf("credential under the old stamp: err = %v, want ErrStaleTarget", err)
	}
	if enrolled, err := store.EnrolledTargets(ctx, "user-42"); err != nil || len(enrolled) != 0 {
		t.Errorf("enrolled = %v, err = %v; want nothing", enrolled, err)
	}
	if _, err := store.UpdateTarget(ctx, TargetKey{"gamma", first.RowID, first.Revision}, in, "root"); !errors.Is(err, ErrTargetChanged) {
		t.Errorf("update with the old row's form: err = %v, want ErrTargetChanged", err)
	}
	if err := store.DeleteTarget(ctx, TargetKey{"gamma", first.RowID, first.Revision}); !errors.Is(err, ErrTargetChanged) {
		t.Errorf("delete with the old row's form: err = %v, want ErrTargetChanged", err)
	}
}

// seedStamped writes one flow, session and credential under a stamp, directly,
// so a test can place rows the fences would refuse.
func (h *harness) seedStamped(name, stamp, subject string) {
	h.t.Helper()
	ctx := h.t.Context()
	pool := h.srv.store.pool
	if err := h.srv.store.CreateFlow(ctx, Flow{ID: newSecret(), ClientID: "c", RedirectURI: "r", Target: name, Stamp: stamp}); err != nil {
		h.t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sessions (id, subject, resource, target, stamp, upstream_token) VALUES ($1,$2,'',$3,$4,'\x00')`, []any{newSecret(), subject, name, stamp}},
		{`INSERT INTO user_credentials (subject, target, stamp, sealed_headers) VALUES ($1,$2,$3,'\x00')`, []any{subject, name, stamp}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			h.t.Fatal(err)
		}
	}
}

// Cleanup is checked by the rows that remain, not by a refusal the stamp check
// would give anyway.
func TestCleanupRemovesStaleAdminRowsByCount(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	store := h.srv.store
	ctx := t.Context()
	rows := func(stampLike string) int {
		n := 0
		for _, table := range []string{"flows", "sessions", "user_credentials"} {
			n += h.count(`SELECT count(*) FROM `+table+` WHERE stamp LIKE $1`, stampLike)
		}
		return n
	}

	gamma := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	delta := h.createAdmin(h.adminTarget("delta", "/beta-upstream"))
	h.seedStamped("gamma", gamma.StoredStamp, "u")
	h.seedStamped("delta", delta.StoredStamp, "u")
	h.seedStamped("alpha", "config:keep", "u")
	if got := rows("admin:%"); got != 6 {
		t.Fatalf("seeded %d admin rows, want 6", got)
	}

	// A replacement purges that name's old rows as soon as it commits, and only
	// that name's.
	next, err := store.UpdateTarget(ctx, TargetKey{"gamma", gamma.RowID, gamma.Revision}, h.adminTarget("gamma", "/beta-upstream"), "root")
	if err != nil {
		t.Fatal(err)
	}
	if got := h.count(`SELECT count(*) FROM sessions WHERE target='gamma'`) +
		h.count(`SELECT count(*) FROM flows WHERE target='gamma'`) +
		h.count(`SELECT count(*) FROM user_credentials WHERE target='gamma'`); got != 0 {
		t.Errorf("%d row(s) for the replaced definition survived", got)
	}
	if got := rows(delta.StoredStamp); got != 3 {
		t.Errorf("%d row(s) left for the untouched target, want 3", got)
	}

	// An edit that keeps the stamp deletes nothing.
	h.seedStamped("gamma", next.StoredStamp, "u")
	in := h.adminTarget("gamma", "/beta-upstream")
	in.DisplayName = "Renamed"
	if _, err := store.UpdateTarget(ctx, TargetKey{"gamma", next.RowID, next.Revision}, in, "root"); err != nil {
		t.Fatal(err)
	}
	if got := rows(next.StoredStamp); got != 3 {
		t.Errorf("a same-stamp edit left %d row(s) of its definition, want 3", got)
	}

	// The sweep catches rows no edit path saw, such as another replica's late
	// write for a name that has since gone, and leaves config stamps alone.
	h.seedStamped("ghost", "admin:orphan", "u")
	if err := store.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rows("admin:orphan"); got != 0 {
		t.Errorf("the sweep left %d orphaned row(s)", got)
	}
	if got := rows("config:keep"); got != 3 {
		t.Errorf("the sweep touched config rows: %d left, want 3", got)
	}

	// Removal purges the rest.
	cur, _, err := store.LoadAdminTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cur {
		if a.Target.Name == "delta" {
			if err := store.DeleteTarget(ctx, TargetKey{"delta", a.RowID, a.Revision}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := rows(delta.StoredStamp); got != 0 {
		t.Errorf("%d row(s) survived the removal", got)
	}
}

// A purge that loses a deadlock against a refresh or /revoke fails without
// undoing the edit, and the next sweep finishes the job. The held transaction
// stands in for the refresh or revoke: it holds the second of two stale
// sessions, then reaches for the first, which the purge has by then deleted.
func TestDeadlockedPurgeIsRepairedByTheNextSweep(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	store := h.srv.store
	ctx := t.Context()

	gamma := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.seedStamped("gamma", gamma.StoredStamp, "u1")
	h.seedStamped("gamma", gamma.StoredStamp, "u2")

	// The purge deletes in scan order, so lock the row it will reach last.
	rows, err := store.pool.Query(ctx, `SELECT id FROM sessions WHERE target='gamma' ORDER BY ctid`)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 2 {
		t.Fatalf("%d sessions, want 2", len(ids))
	}

	lockCtx, cancel := context.WithTimeout(context.Background(), 2*raceWait)
	defer cancel()
	tx, err := store.pool.Begin(lockCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(lockCtx) }()
	if _, err := tx.Exec(lockCtx, `SELECT 1 FROM sessions WHERE id=$1 FOR UPDATE`, ids[1]); err != nil {
		t.Fatal(err)
	}

	edit := make(chan error, 1)
	go func() {
		_, err := store.UpdateTarget(lockCtx, TargetKey{"gamma", gamma.RowID, gamma.Revision}, h.adminTarget("gamma", "/beta-upstream"), "root")
		edit <- err
	}()
	if !blockedOn(store, "DELETE FROM sessions%") {
		t.Fatal("the purge never reached the held row")
	}
	// The purge is waiting on ids[1] having deleted ids[0]. Reaching for ids[0]
	// closes the cycle; the purge started waiting first, so it is the victim.
	_, lockErr := tx.Exec(lockCtx, `SELECT 1 FROM sessions WHERE id=$1 FOR UPDATE`, ids[0])
	if lockErr != nil {
		t.Fatalf("the refresh lost the deadlock, so the purge was not the victim: %v", lockErr)
	}
	if err := tx.Commit(lockCtx); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-edit:
		if err != nil {
			t.Errorf("the edit failed because its purge did: %v", err)
		}
	case <-time.After(raceWait):
		t.Fatal("the edit never returned")
	}
	if n := h.count(`SELECT count(*) FROM targets WHERE name='gamma' AND revision=2`); n != 1 {
		t.Error("the edit did not commit")
	}
	if n := h.count(`SELECT count(*) FROM sessions WHERE target='gamma'`); n != 2 {
		t.Fatalf("%d stale session(s) after the failed purge, want 2", n)
	}

	if err := store.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT count(*) FROM sessions WHERE target='gamma'`); n != 0 {
		t.Errorf("%d stale session(s) after the next sweep, want 0", n)
	}
}
