package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// adminOn switches the feature on the way the environment does, allowing the
// stub upstream the harness serves. The stub listens on loopback over plain
// http, which an admin target may reach only through the networks list.
func adminOn(cfg *Config, upstreamURL string) {
	u, _ := url.Parse(upstreamURL)
	cfg.AdminSubjects = []string{"root"}
	cfg.AllowedUpstreamHosts = []hostPattern{{Host: u.Hostname(), Port: u.Port()}}
	cfg.AllowedUpstreamNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
}

func adminTwoTargets(cfg *Config, upstreamURL string) []Target {
	adminOn(cfg, upstreamURL)
	return twoTargets(cfg, upstreamURL)
}

func adminPerUserTargets(cfg *Config, upstreamURL string) []Target {
	adminOn(cfg, upstreamURL)
	return perUserTargets(cfg, upstreamURL)
}

// adminTarget is a provider_token admin target at one of the stub's paths.
func (h *harness) adminTarget(name, path string) Target {
	return Target{Name: name, DisplayName: strings.ToUpper(name[:1]) + name[1:], UpstreamMCP: h.provider.URL + path, Mode: CredProviderToken}
}

func (h *harness) createAdmin(t Target) AdminTarget {
	h.t.Helper()
	a, err := h.srv.store.CreateTarget(h.t.Context(), t, "root")
	if err != nil {
		h.t.Fatalf("CreateTarget(%s): %v", t.Name, err)
	}
	return a
}

func (h *harness) rebuild() {
	h.t.Helper()
	if err := h.srv.reg.Rebuild(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
}

// eventually bounds every wait, so a regression fails the test instead of
// hanging it.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// holdRebuilds makes RequestRebuild a no-op by pretending one has just run.
func (h *harness) holdRebuilds() {
	h.srv.reg.lastRequest.Store(time.Now().Add(time.Hour).UnixNano())
}

func (h *harness) mcpStatus(path, token string) (int, http.Header) {
	h.t.Helper()
	resp := h.mcpRequest(path, token)
	resp.Body.Close()
	return resp.StatusCode, resp.Header
}

func (h *harness) refresh(clientID, refresh string) (int, string) {
	h.t.Helper()
	resp := h.postForm("/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh},
	})
	defer resp.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Error
}

const testRedirect = "https://client.example/callback"

// A replica still serving a config target must stop serving it the moment an
// admin target takes the name, even though it has not rebuilt.
func TestConfigReplicaAnswers503OnceAdminTargetTakesTheName(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.Targets[0].Resource)

	if status, _ := h.mcpStatus("/alpha/mcp", access); status != http.StatusOK {
		t.Fatalf("before the admin target: status %d, want 200", status)
	}
	hits := h.alphaHits.Load()

	h.createAdmin(h.adminTarget("alpha", "/beta-upstream"))

	status, header := h.mcpStatus("/alpha/mcp", access)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 from a replica behind the database", status)
	}
	if header.Get("Retry-After") == "" {
		t.Error("the 503 carried no Retry-After")
	}
	if h.alphaHits.Load() != hits || h.betaHits.Load() != 0 {
		t.Error("a request reached an upstream while the replica was behind")
	}

	// The refusal started a rebuild. Once it lands the session, issued under the
	// config definition, is simply unknown.
	eventually(t, "the rebuild to land", func() bool {
		status, _ := h.mcpStatus("/alpha/mcp", access)
		return status == http.StatusUnauthorized
	})
	if h.alphaHits.Load() != hits || h.betaHits.Load() != 0 {
		t.Error("the old session reached an upstream after the admin target took over")
	}
}

// A replica whose snapshot predates a replacement refuses with 503, and /token
// does so without consuming the client's refresh token.
func TestReplicaBehindAReplacementAnswers503AndKeepsRefreshToken(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.srv.store.skipCleanup = true // the freshness check is under test, not the purge
	created := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()

	clientID := h.register(testRedirect)
	access, refresh := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")
	if status, _ := h.mcpStatus("/gamma/mcp", access); status != http.StatusOK {
		t.Fatalf("before the edit: status %d, want 200", status)
	}

	// A replacement committed elsewhere: this replica is not told, and the
	// background rebuild a refusal starts is held off so the test sees the
	// replica while it is still behind.
	h.holdRebuilds()
	moved := h.adminTarget("gamma", "/beta-upstream")
	if _, err := h.srv.store.UpdateTarget(h.t.Context(), TargetKey{"gamma", created.RowID, created.Revision}, moved, "root"); err != nil {
		t.Fatal(err)
	}

	if status, _ := h.mcpStatus("/gamma/mcp", access); status != http.StatusServiceUnavailable {
		t.Errorf("mcp: status %d, want 503", status)
	}
	status, code := h.refresh(clientID, refresh)
	if status != http.StatusServiceUnavailable || code != "temporarily_unavailable" {
		t.Errorf("/token: %d %q, want 503 temporarily_unavailable", status, code)
	}

	var used bool
	err := h.srv.store.pool.QueryRow(h.t.Context(),
		`SELECT used FROM refresh_tokens WHERE token_hash=$1`, hashToken(refresh)).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Error("the refresh token was consumed by a refusal the client should retry")
	}
	if h.betaHits.Load() != 0 {
		t.Error("a request reached the new upstream under the old session")
	}
}

// An edit that leaves the stamp alone, such as a new display name, does not make
// a replica behind, so it keeps serving without waiting for the poll.
func TestEditThatKeepsTheStampDoesNotRefuse(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	created := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()
	h.holdRebuilds()
	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")

	renamed := h.adminTarget("gamma", "/alpha-upstream")
	renamed.DisplayName = "Renamed"
	updated, err := h.srv.store.UpdateTarget(h.t.Context(), TargetKey{"gamma", created.RowID, created.Revision}, renamed, "root")
	if err != nil {
		t.Fatal(err)
	}
	if updated.StoredStamp != created.StoredStamp {
		t.Fatal("a display name change moved the stamp")
	}
	if status, _ := h.mcpStatus("/gamma/mcp", access); status != http.StatusOK {
		t.Errorf("status %d, want 200", status)
	}
}

// The freshness rules for a per_user target hold at the credential read too.
func TestPerUserCredentialReadRefusesWhenBehind(t *testing.T) {
	h := newHarnessWith(t, adminPerUserTargets)
	h.srv.store.skipCleanup = true // the freshness check is under test, not the purge
	fields := []UserHeaderField{{Header: "Authorization", Label: "Token", Prefix: "Bearer "}}
	in := Target{Name: "gamma", DisplayName: "Gamma", UpstreamMCP: h.provider.URL + "/alpha-upstream", Mode: CredPerUser, UserFields: fields}
	created := h.createAdmin(in)
	h.rebuild()

	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")
	e := h.srv.reg.Load().byName["gamma"]
	sealed, err := h.srv.sealer.seal(boundPurpose(purposeUserCredential, e.Stamp), []byte(`{"Authorization":"Bearer u"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.store.PutUserCredential(h.t.Context(), "user-42", "gamma", e.Stamp, sealed); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.mcpStatus("/gamma/mcp", access); status != http.StatusOK {
		t.Fatalf("before the edit: status %d, want 200", status)
	}

	h.holdRebuilds()
	in.UserFields = []UserHeaderField{{Header: "X-Other", Label: "Token"}}
	if _, err := h.srv.store.UpdateTarget(h.t.Context(), TargetKey{"gamma", created.RowID, created.Revision}, in, "root"); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.mcpStatus("/gamma/mcp", access); status != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", status)
	}
}

// A rebuild that races an edit reads the version and the rows from one
// snapshot, so it can never publish the old URL under the new stamp, or the new
// definition under the old version.
func TestRebuildRacingAnEditPublishesOneConsistentState(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	old := h.adminTarget("gamma", "/alpha-upstream")
	created := h.createAdmin(old)
	h.rebuild()
	before := h.srv.reg.Load().version

	// The edit commits between the rebuild's read of the version and its read of
	// the rows.
	next := h.adminTarget("gamma", "/beta-upstream")
	var updated AdminTarget
	h.srv.store.afterVersionRead = func() {
		h.srv.store.afterVersionRead = nil
		var err error
		updated, err = h.srv.store.UpdateTarget(h.t.Context(), TargetKey{"gamma", created.RowID, created.Revision}, next, "root")
		if err != nil {
			t.Error(err)
		}
	}
	h.rebuild()

	snap := h.srv.reg.Load()
	e := snap.byName["gamma"]
	if snap.version != before {
		t.Fatalf("version = %d, want the %d read before the edit", snap.version, before)
	}
	if e.Target.UpstreamMCP != old.UpstreamMCP || e.Stamp != created.StoredStamp {
		t.Errorf("published %q with stamp %q; want the old URL with the old stamp", e.Target.UpstreamMCP, e.Stamp)
	}

	h.rebuild()
	e = h.srv.reg.Load().byName["gamma"]
	if e.Target.UpstreamMCP != next.UpstreamMCP || e.Stamp != updated.StoredStamp {
		t.Errorf("after the next rebuild: %q with stamp %q; want the new state", e.Target.UpstreamMCP, e.Stamp)
	}
}

// Once this replica has caught up, a refresh for a session issued under a
// replaced definition, or for a target that is gone, is invalid_grant. Neither
// consumes the refresh token, so the answer does not turn into a reuse alarm.
func TestRefreshForReplacedOrRemovedTargetIsInvalidGrant(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.srv.store.skipCleanup = true // the stamp check is under test, not the purge
	created := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()
	clientID := h.register(testRedirect)
	_, refresh := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")

	unused := func() {
		t.Helper()
		var used bool
		err := h.srv.store.pool.QueryRow(t.Context(),
			`SELECT used FROM refresh_tokens WHERE token_hash=$1`, hashToken(refresh)).Scan(&used)
		if err != nil || used {
			t.Fatalf("used = %v, err = %v; want the refresh token left unused", used, err)
		}
	}

	next, err := h.srv.store.UpdateTarget(t.Context(), TargetKey{"gamma", created.RowID, created.Revision},
		h.adminTarget("gamma", "/beta-upstream"), "root")
	if err != nil {
		t.Fatal(err)
	}
	h.rebuild()
	if status, code := h.refresh(clientID, refresh); status != http.StatusBadRequest || code != "invalid_grant" {
		t.Errorf("replaced: %d %q, want 400 invalid_grant", status, code)
	}
	unused()

	if err := h.srv.store.DeleteTarget(t.Context(), TargetKey{"gamma", next.RowID, next.Revision}); err != nil {
		t.Fatal(err)
	}
	h.rebuild()
	if status, code := h.refresh(clientID, refresh); status != http.StatusBadRequest || code != "invalid_grant" {
		t.Errorf("removed: %d %q, want 400 invalid_grant", status, code)
	}
	unused()
}

// secondReplica is another registry over the same database with its own store,
// standing in for another pod.
func (h *harness) secondReplica() (*registry, *Store) {
	h.t.Helper()
	s, err := NewStore(h.t.Context(), os.Getenv("TEST_DATABASE_URL"), 30*24*time.Hour, 90*24*time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(s.Close)
	cfg := h.srv.cfg
	s.EnableAdminTargets(h.srv.sealer, cfg.AllowedUpstreamHosts, cfg.AllowedUpstreamNetworks)
	ctx, cancel := context.WithCancel(h.t.Context())
	h.t.Cleanup(cancel)
	reg := newAdminRegistry(ctx, cfg, s)
	if err := reg.Rebuild(ctx); err != nil {
		h.t.Fatal(err)
	}
	return reg, s
}

func TestTwoRegistriesConvergeAfterASave(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	other, _ := h.secondReplica()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); other.Poll(ctx, 20*time.Millisecond) }()

	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild() // the saving replica does not wait for a poll
	if h.srv.reg.Load().byName["gamma"] == nil {
		t.Fatal("the saving replica did not rebuild at once")
	}
	eventually(t, "the other replica to poll the change", func() bool { return other.Load().byName["gamma"] != nil })

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the poller did not stop when its context ended")
	}
}

func TestFailedPollKeepsTheCurrentSnapshot(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	other, otherStore := h.secondReplica()
	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	other.pollOnce(t.Context())
	kept := other.Load()
	if kept.byName["gamma"] == nil {
		t.Fatal("the poll did not pick up the change")
	}

	h.createAdmin(h.adminTarget("delta", "/beta-upstream"))
	otherStore.Close() // the database is unreachable from this replica
	other.pollOnce(t.Context())
	if other.Load() != kept {
		t.Error("a failed poll replaced the snapshot")
	}
}

// A config entry that an admin target outranks is left out without stopping a
// boot, and removing the admin target hands the name back with none of the
// admin target's sessions.
func TestConfigEntryClashingWithAdminTargetIsLeftOut(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	created := h.createAdmin(h.adminTarget("alpha", "/beta-upstream"))

	// A fresh replica boots over a database that already holds the clash.
	booted, _ := h.secondReplica()
	snap := booted.Load()
	if e := snap.byName["alpha"]; e == nil || e.Target.Source != SourceAdmin {
		t.Fatal("the admin target does not hold the name")
	}
	if len(snap.ignored) != 1 || snap.ignored[0].Name != "alpha" {
		t.Errorf("ignored = %+v, want the config alpha", snap.ignored)
	}
	if snap.byName["beta"] == nil || snap.byName["beta"].Target.Source == SourceAdmin {
		t.Error("the unrelated config target is not served")
	}

	h.rebuild()
	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/alpha/mcp")
	if status, _ := h.mcpStatus("/alpha/mcp", access); status != http.StatusOK {
		t.Fatalf("admin target: status %d, want 200", status)
	}
	betaHits := h.betaHits.Load()

	if err := h.srv.store.DeleteTarget(h.t.Context(), TargetKey{"alpha", created.RowID, created.Revision}); err != nil {
		t.Fatal(err)
	}
	h.rebuild()
	snap = h.srv.reg.Load()
	if e := snap.byName["alpha"]; e == nil || e.Target.Source == SourceAdmin {
		t.Fatal("the config target did not take the name back")
	}
	if len(snap.ignored) != 0 {
		t.Errorf("ignored = %+v, want none", snap.ignored)
	}
	if status, _ := h.mcpStatus("/alpha/mcp", access); status != http.StatusUnauthorized {
		t.Errorf("an admin session on the config target: status %d, want 401", status)
	}
	if h.alphaHits.Load() != 0 || h.betaHits.Load() != betaHits {
		t.Error("the old session reached an upstream")
	}
}

// Rows the registry cannot vouch for are left out and never served with
// whatever is left over.
func TestRegistryLeavesOutRowsItCannotVouchFor(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.createAdmin(h.adminTarget("good", "/alpha-upstream"))
	h.createAdmin(h.adminTarget("moved", "/alpha-upstream"))
	static := h.adminTarget("vault", "/alpha-upstream")
	static.Mode, static.StaticHeaders = CredStatic, map[string]string{"X-Api-Key": "secret"}
	h.createAdmin(static)
	other := static
	other.Name = "copy"
	h.createAdmin(other)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.srv.store.pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Written by different code: the stored stamp is not the definition's.
	exec(`UPDATE targets SET upstream_mcp = upstream_mcp || '/elsewhere' WHERE name = 'moved'`)
	// A sealed value copied from another row.
	exec(`UPDATE targets SET sealed_static = (SELECT sealed_static FROM targets WHERE name = 'vault') WHERE name = 'copy'`)

	h.rebuild()
	snap := h.srv.reg.Load()
	for _, name := range []string{"moved", "copy"} {
		if snap.byName[name] != nil {
			t.Errorf("%s is served", name)
		}
	}
	for _, name := range []string{"good", "vault"} {
		if snap.byName[name] == nil {
			t.Errorf("%s is not served", name)
		}
	}
	if got := snap.byName["vault"].Target.StaticHeaders["X-Api-Key"]; got != "secret" {
		t.Errorf("vault headers = %q", got)
	}

	// The policy tightened after the rows were saved: the host list is applied
	// again when a snapshot is built, not only when a row is written.
	narrowed := *h.srv.cfg
	narrowed.AllowedUpstreamHosts = []hostPattern{{Host: "other.example", Port: "443"}}
	reg := newAdminRegistry(t.Context(), &narrowed, h.srv.store)
	if err := reg.Rebuild(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reg.Load().byName["good"] != nil {
		t.Error("a target whose host left ALLOWED_UPSTREAM_HOSTS is still served")
	}
}

// A static value that will not unseal, as after a key rotation, is not served,
// and the provider token is never forwarded in its place.
func TestUnsealableStaticTargetIsNotServed(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	static := h.adminTarget("vault", "/alpha-upstream")
	static.Mode, static.StaticHeaders = CredStatic, map[string]string{"X-Api-Key": "secret"}
	h.createAdmin(static)

	rotated, err := newSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	other, otherStore := h.secondReplica()
	otherStore.admin.sealer = rotated
	if err := other.Rebuild(t.Context()); err != nil {
		t.Fatal(err)
	}
	if other.Load().byName["vault"] != nil {
		t.Fatal("a target whose static value does not unseal is served")
	}
	if other.Load().byName["alpha"] == nil {
		t.Error("an unrelated target went with it")
	}
}

// With the feature off the targets table is neither read nor written. The table
// is renamed away for the test, so any statement that mentions it fails.
func TestDisabledFeatureNeverTouchesTargets(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	pool := h.srv.store.pool
	if _, err := pool.Exec(t.Context(), `ALTER TABLE targets RENAME TO targets_hidden`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `ALTER TABLE targets_hidden RENAME TO targets`); err != nil {
			t.Error(err)
		}
	})

	clientID := h.register(testRedirect)
	access, refresh := h.tokensFor(clientID, testRedirect, h.srv.cfg.Targets[0].Resource)
	h.enrol("user-42", "alpha", map[string]string{"Authorization": "Bearer alices"})
	if status, _ := h.mcpStatus("/alpha/mcp", access); status != http.StatusOK {
		t.Errorf("per_user request: status %d, want 200", status)
	}
	if status, code := h.refresh(clientID, refresh); status != http.StatusOK {
		t.Errorf("refresh: %d %q, want 200", status, code)
	}
	if _, err := h.srv.store.LookupAccessToken(t.Context(), access); err != nil {
		t.Errorf("LookupAccessToken: %v", err)
	}
}

// Plain http carries a credential in the clear, so the address dialled must be
// in the allowed networks on every connection. A name that resolves anywhere
// else is refused at dial, whatever it resolved to when it was saved.
func TestAdminTransportDialGuard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	byName := "http://localhost:" + u.Port() + "/"

	get := func(rt http.RoundTripper, target string) error {
		client := &http.Client{Transport: rt, Timeout: 5 * time.Second}
		resp, err := client.Get(target)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	elsewhere := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	if err := get(newAdminTransport(loopback, true), byName); err != nil {
		t.Errorf("a name resolving into the allowed networks: %v", err)
	}
	err := get(newAdminTransport(elsewhere, true), byName)
	if err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Errorf("a name resolving outside the allowed networks: err = %v, want a plain http refusal", err)
	}
	// Over https a private address needs a listing too.
	err = get(newAdminTransport(nil, false), "https://localhost:"+u.Port()+"/")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("a private address over https with no networks: err = %v, want a refusal", err)
	}
	if newAdminTransport(nil, false).Proxy != nil {
		t.Error("the admin transport consults the proxy environment")
	}
}

// Every rule an admin definition must meet is applied by the store, so no caller
// can forget one, and a change is checked against the exact row it was made for.
func TestAdminTargetStoreRules(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	store := h.srv.store
	ctx := t.Context()

	t.Run("refuses what validation refuses", func(t *testing.T) {
		bad := map[string]Target{
			"reserved admin":    h.adminTarget("admin", "/alpha-upstream"),
			"reserved settings": h.adminTarget("settings", "/alpha-upstream"),
			"bad name":          h.adminTarget("Bad_Name", "/alpha-upstream"),
			"no name":           {DisplayName: "X", UpstreamMCP: h.provider.URL, Mode: CredProviderToken},
			"host not listed":   {Name: "x", DisplayName: "X", UpstreamMCP: "https://evil.example/mcp", Mode: CredProviderToken},
			"userinfo":          {Name: "x", DisplayName: "X", UpstreamMCP: "http://u:p@" + strings.TrimPrefix(h.provider.URL, "http://"), Mode: CredProviderToken},
			"static no value":   {Name: "x", DisplayName: "X", UpstreamMCP: h.provider.URL, Mode: CredStatic},
		}
		for name, tgt := range bad {
			if _, err := store.CreateTarget(ctx, tgt, "root"); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		if _, err := store.CreateTarget(ctx, h.adminTarget("ok", "/alpha-upstream"), ""); err == nil {
			t.Error("a change with no subject was accepted")
		}
	})

	created := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	key := TargetKey{"gamma", created.RowID, created.Revision}
	if created.UpdatedBy != "root" || created.Revision != 1 || created.Target.Generation == "" {
		t.Errorf("created = %+v", created)
	}

	t.Run("a name is taken once", func(t *testing.T) {
		if _, err := store.CreateTarget(ctx, h.adminTarget("gamma", "/alpha-upstream"), "root"); !errors.Is(err, ErrTargetExists) {
			t.Errorf("err = %v, want ErrTargetExists", err)
		}
	})

	t.Run("each change bumps the version", func(t *testing.T) {
		v1, _ := store.TargetsVersion(ctx)
		next, err := store.UpdateTarget(ctx, key, h.adminTarget("gamma", "/alpha-upstream"), "someone")
		if err != nil {
			t.Fatal(err)
		}
		if v2, _ := store.TargetsVersion(ctx); v2 != v1+1 {
			t.Errorf("version %d -> %d, want +1", v1, v2)
		}
		if next.Revision != 2 || next.UpdatedBy != "someone" {
			t.Errorf("updated = %+v", next)
		}
		key = TargetKey{"gamma", next.RowID, next.Revision}
		created = next
	})

	t.Run("a stale revision is refused", func(t *testing.T) {
		stale := TargetKey{"gamma", created.RowID, created.Revision - 1}
		if _, err := store.UpdateTarget(ctx, stale, h.adminTarget("gamma", "/alpha-upstream"), "root"); !errors.Is(err, ErrTargetChanged) {
			t.Errorf("err = %v, want ErrTargetChanged", err)
		}
		if err := store.DeleteTarget(ctx, stale); !errors.Is(err, ErrTargetChanged) {
			t.Errorf("delete: err = %v, want ErrTargetChanged", err)
		}
	})

	t.Run("a replacement re-rolls the generation and the stamp", func(t *testing.T) {
		moved := h.adminTarget("gamma", "/beta-upstream")
		next, err := store.UpdateTarget(ctx, key, moved, "root")
		if err != nil {
			t.Fatal(err)
		}
		if next.Target.Generation == created.Target.Generation || next.StoredStamp == created.StoredStamp {
			t.Error("a replacement kept its generation or stamp")
		}
		// Putting the old definition back is a new replacement, not a revival.
		back, err := store.UpdateTarget(ctx, TargetKey{"gamma", next.RowID, next.Revision}, h.adminTarget("gamma", "/alpha-upstream"), "root")
		if err != nil {
			t.Fatal(err)
		}
		if back.StoredStamp == created.StoredStamp {
			t.Error("an earlier definition put back revived its old stamp")
		}
		key, created = TargetKey{"gamma", back.RowID, back.Revision}, back
	})

	t.Run("remove then re-add is not the old row", func(t *testing.T) {
		if err := store.DeleteTarget(ctx, key); err != nil {
			t.Fatal(err)
		}
		again := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
		if again.Revision != created.Revision && again.Revision != 1 {
			t.Fatalf("revision = %d", again.Revision)
		}
		if again.StoredStamp == created.StoredStamp || again.RowID == created.RowID {
			t.Error("the re-added target shares an identity with its predecessor")
		}
		// A form rendered for the old row, even at a matching revision, cannot apply.
		old := TargetKey{"gamma", created.RowID, again.Revision}
		if _, err := store.UpdateTarget(ctx, old, h.adminTarget("gamma", "/beta-upstream"), "root"); !errors.Is(err, ErrTargetChanged) {
			t.Errorf("err = %v, want ErrTargetChanged", err)
		}
		if err := store.DeleteTarget(ctx, old); !errors.Is(err, ErrTargetChanged) {
			t.Errorf("delete: err = %v, want ErrTargetChanged", err)
		}
	})
}

func TestStaticTargetKeepsItsValueOnlyForTheSameServer(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	store := h.srv.store
	ctx := t.Context()

	in := h.adminTarget("vault", "/alpha-upstream")
	in.Mode, in.StaticHeaders = CredStatic, map[string]string{"X-Api-Key": "secret"}
	created := h.createAdmin(in)
	key := TargetKey{"vault", created.RowID, created.Revision}

	// The sealed value is not the plaintext, and is bound to its row.
	if strings.Contains(string(created.SealedStatic), "secret") {
		t.Error("the static value is stored in the clear")
	}

	// A new URL with no new value would send the old credential somewhere new.
	moved := in
	moved.StaticHeaders = nil
	moved.UpstreamMCP = h.provider.URL + "/beta-upstream"
	if _, err := store.UpdateTarget(ctx, key, moved, "root"); !errors.Is(err, ErrStaticValueRequired) {
		t.Fatalf("err = %v, want ErrStaticValueRequired", err)
	}
	moved.StaticHeaders = map[string]string{"X-Api-Key": "fresh"}
	next, err := store.UpdateTarget(ctx, key, moved, "root")
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.openStatic(next)
	if err != nil || got["X-Api-Key"] != "fresh" {
		t.Errorf("stored %v, %v; want the new value", got, err)
	}

	// The same server with no value keeps the stored one, and keeps the stamp.
	key = TargetKey{"vault", next.RowID, next.Revision}
	renamed := moved
	renamed.StaticHeaders, renamed.DisplayName = nil, "Vault 2"
	kept, err := store.UpdateTarget(ctx, key, renamed, "root")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := store.openStatic(kept); got["X-Api-Key"] != "fresh" {
		t.Errorf("the stored value was lost: %v", got)
	}
	if kept.StoredStamp != next.StoredStamp {
		t.Error("a display name change moved the stamp")
	}

	// Leaving static mode needs no value, and drops the stored one.
	key = TargetKey{"vault", kept.RowID, kept.Revision}
	plain := h.adminTarget("vault", "/beta-upstream")
	dropped, err := store.UpdateTarget(ctx, key, plain, "root")
	if err != nil {
		t.Fatal(err)
	}
	if dropped.SealedStatic != nil {
		t.Error("a static value outlived its mode")
	}
	// Coming back to static from another mode needs a value too.
	key = TargetKey{"vault", dropped.RowID, dropped.Revision}
	back := plain
	back.Mode = CredStatic
	if _, err := store.UpdateTarget(ctx, key, back, "root"); !errors.Is(err, ErrStaticValueRequired) {
		t.Errorf("err = %v, want ErrStaticValueRequired", err)
	}
}

// A row that cannot be decoded is left out and still holds its name. It does not
// stop a boot or hide the other admin targets.
func TestUndecodableRowIsLeftOutWithoutBlockingTheRest(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.createAdmin(h.adminTarget("alpha", "/beta-upstream"))
	if _, err := h.srv.store.pool.Exec(t.Context(), `UPDATE targets SET user_fields='"not a list"' WHERE name='alpha'`); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)

	booted, _ := h.secondReplica()
	snap := booted.Load()
	if snap.find("gamma") == nil {
		t.Error("the intact admin target is not served")
	}
	if e := snap.find("alpha"); e != nil {
		t.Errorf("the undecodable row is served (source %v), or the config target took its name", e.Target.Source)
	}
	if !strings.Contains(logs.String(), "admin target left out") {
		t.Error("the unusable row was not logged")
	}
	h.rebuild()
}

// The ignored notice is logged when a config target becomes ignored, not on
// every rebuild while the clash lasts.
func TestIgnoredConfigTargetIsLoggedOnce(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.createAdmin(h.adminTarget("alpha", "/beta-upstream"))
	logs := captureLogs(t)
	h.rebuild()
	h.rebuild()
	if n := strings.Count(logs.String(), "config target ignored"); n != 1 {
		t.Errorf("logged %d times over two rebuilds, want 1", n)
	}
}
