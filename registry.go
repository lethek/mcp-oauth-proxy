package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// entry is one served target with what is derived from it. The stamp is
// computed once here because every request compares against it.
type entry struct {
	Target Target
	Stamp  string
	Proxy  http.Handler
	// Transport is an admin target's own transport, kept so a rebuild that
	// replaces the entry can close its idle connections. Nil for config targets,
	// which share upstreamTransport.
	Transport *http.Transport
}

// ignoredTarget is a config target left out of a snapshot because an admin
// target holds its name. The admin page lists it with the reason.
type ignoredTarget struct {
	Name   string
	Reason string
}

// snapshot is an immutable view of the targets being served. A request loads
// one and uses it throughout, so a target cannot change definition between the
// audience check and the credential swap.
type snapshot struct {
	entries    []*entry
	byName     map[string]*entry
	byResource map[string]*entry

	// multi is fixed by configuration, not derived from entries, so a deployment
	// whose admin targets are all removed is still named and never indexes an
	// empty list.
	multi bool

	// version is the targets_version this snapshot was built from, so the poller
	// can tell whether the database has moved on. Zero for a config-only build.
	version int64

	// ignored are the config targets an admin target outranks.
	ignored []ignoredTarget
}

// registry hands out the current snapshot. Replacing it is a single atomic
// store, so readers never take a lock.
//
// With admin targets enabled it also rebuilds the snapshot from the database.
// The zero value is a plain holder, which is all a config-only deployment needs.
type registry struct {
	cur atomic.Pointer[snapshot]

	// Set by newAdminRegistry; nil store means the feature is off.
	cfg   *Config
	store *Store
	// bg bounds work started on behalf of a request and ends the poller.
	bg context.Context

	// buildMu serialises rebuilds so a slow one cannot publish over a newer one.
	buildMu sync.Mutex
	// lastRequest is when a request last triggered a rebuild, in unix nanos.
	lastRequest atomic.Int64
}

func (r *registry) Load() *snapshot   { return r.cur.Load() }
func (r *registry) Store(s *snapshot) { r.cur.Store(s) }

// enabled reports whether the freshness checks apply, which is exactly when the
// database can hold admin targets.
func (r *registry) enabled() bool { return r.store != nil }

// newSnapshot builds a snapshot from targets. An entry whose stamp matches one
// in prev keeps that entry's proxy, so its in-flight limit and connection pool
// survive a rebuild that did not change where it sends requests.
//
// Without admin targets there must be at least one, because the unnamed mode
// reads the first entry. A named deployment with admin targets may be empty.
func newSnapshot(targets []Target, cfg *Config, prev *snapshot) (*snapshot, error) {
	if len(targets) == 0 && !cfg.NamedMode() {
		return nil, errors.New("no targets to serve")
	}
	s := &snapshot{
		byName:     make(map[string]*entry, len(targets)),
		byResource: make(map[string]*entry, len(targets)),
		multi:      cfg.NamedMode(),
	}
	for _, t := range targets {
		e := &entry{Target: t, Stamp: t.Stamp()}
		if old := prev.find(t.Name); old != nil && old.Stamp == e.Stamp {
			e.Proxy, e.Transport = old.Proxy, old.Transport
		} else {
			u, err := url.Parse(t.UpstreamMCP)
			if err != nil {
				return nil, fmt.Errorf("target %q: %w", t.Name, err)
			}
			// Only a per_user target can produce an upstream 401 the user can act on.
			enrolURL := ""
			if t.Mode == CredPerUser {
				enrolURL = cfg.PublicURL + "/settings"
			}
			rt := http.RoundTripper(upstreamTransport)
			if t.FromAdmin() {
				// Plain http must also dial an address in the allowed networks, on
				// every connection, not only when the target was saved.
				e.Transport = newAdminTransport(cfg.AllowedUpstreamNetworks, u.Scheme == "http")
				rt = e.Transport
			}
			e.Proxy = newReverseProxyWith(rt, u, enrolURL)
		}
		s.entries = append(s.entries, e)
		s.byName[t.Name] = e
		s.byResource[t.Resource] = e
	}
	return s, nil
}

// find tolerates a nil snapshot so the first build needs no special case.
func (s *snapshot) find(name string) *entry {
	if s == nil {
		return nil
	}
	return s.byName[name]
}

// behind reports whether this replica may hold an older definition of the
// target than the database, given the stamp the database has under the name
// (nil when no row exists). An admin target must match the row exactly. A config
// target must have no row, because an admin target outranks it. A nil entry is a
// name this replica does not serve, which is behind only if a row exists.
func (e *entry) behind(current *string) bool {
	if e != nil && e.Target.FromAdmin() {
		return current == nil || *current != e.Stamp
	}
	return current != nil
}

// HasPerUserTargets reports whether the enrolment page has anything to offer.
func (s *snapshot) HasPerUserTargets() bool {
	for _, e := range s.entries {
		if e.Target.Mode == CredPerUser {
			return true
		}
	}
	return false
}

// MultiTarget reports whether this deployment serves named targets. It governs
// two behaviours: whether the `resource` parameter is required at /authorize,
// and whether a session carrying no resource may be used at all.
func (s *snapshot) MultiTarget() bool { return s.multi }

// TargetByResource finds the target a `resource` value names.
func (s *snapshot) TargetByResource(resource string) (Target, bool) {
	if e, ok := s.byResource[strings.TrimRight(resource, "/")]; ok {
		return e.Target, true
	}
	return Target{}, false
}

// ResourceList is every resource this proxy serves, for error messages.
func (s *snapshot) ResourceList() string {
	out := make([]string, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e.Target.Resource)
	}
	return strings.Join(out, ", ")
}

// ---------- admin targets ----------

// pollInterval is how often each replica checks targets_version. Polling needs
// no long-lived connection and survives a failover without reconnect logic.
const pollInterval = 5 * time.Second

// rebuildTimeout bounds a rebuild started on behalf of a request.
const rebuildTimeout = 10 * time.Second

// newAdminRegistry returns a registry that merges config and admin targets. The
// store must already have admin targets enabled. Nothing is served from the
// database until the first Rebuild.
func newAdminRegistry(ctx context.Context, cfg *Config, store *Store) *registry {
	return &registry{cfg: cfg, store: store, bg: ctx}
}

// reservedTargetNames would collide with the proxy's own pages.
var reservedTargetNames = []string{"admin", "settings"}

// Rebuild reads the admin targets and publishes a snapshot merged with the
// config targets. Rows and version come from one transaction, so an edit
// committing mid-read cannot produce a mixed result. On any error the current
// snapshot stays, so a database outage never empties the served list.
//
// The replica that handled a save calls it straight away; the others reach it
// through Poll.
func (r *registry) Rebuild(ctx context.Context) error {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	return r.rebuildLocked(ctx)
}

// rebuildIfBehind is Rebuild for callers that only want the snapshot current.
// The version is read after taking the lock, so a caller that queued behind a
// rebuild which already caught up returns after one cheap read instead of
// repeating the full one. It reports whether it rebuilt.
func (r *registry) rebuildIfBehind(ctx context.Context) (bool, error) {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	v, err := r.store.TargetsVersion(ctx)
	if err != nil || v == r.Load().version {
		return false, err
	}
	return true, r.rebuildLocked(ctx)
}

// rebuildLocked is the body of Rebuild; buildMu must be held.
func (r *registry) rebuildLocked(ctx context.Context) error {
	rows, version, err := r.store.LoadAdminTargets(ctx)
	if err != nil {
		return err
	}
	targets, ignored := r.merge(rows)
	snap, err := newSnapshot(targets, r.cfg, r.Load())
	if err != nil {
		return err
	}
	snap.version, snap.ignored = version, ignored
	prev := r.Load()
	// Logged when the set changes, not on every rebuild, or the poller would
	// repeat it for as long as the clash lasts.
	for _, ig := range ignored {
		if !prev.wasIgnored(ig.Name) {
			slog.Warn("config target ignored: name in use by an admin target", "target", ig.Name)
		}
	}
	r.Store(snap)
	// A replaced or removed admin target's pooled connections would otherwise
	// idle until their timeout. In-flight requests are unaffected.
	if prev != nil {
		for _, old := range prev.entries {
			if old.Transport != nil && !snap.find(old.Target.Name).sameProxy(old) {
				old.Transport.CloseIdleConnections()
			}
		}
	}
	return nil
}

// configHolds reports whether a config target has the name, whether it is served
// or left out behind an admin target.
func (s *snapshot) configHolds(name string) bool {
	if e := s.find(name); e != nil && !e.Target.FromAdmin() {
		return true
	}
	return s.wasIgnored(name)
}

// wasIgnored tolerates a nil snapshot, like find.
func (s *snapshot) wasIgnored(name string) bool {
	if s == nil {
		return false
	}
	return slices.ContainsFunc(s.ignored, func(i ignoredTarget) bool { return i.Name == name })
}

// sameProxy reports whether e carries the proxy o does, which is how a rebuild
// shows an entry was reused.
func (e *entry) sameProxy(o *entry) bool { return e != nil && e.Proxy == o.Proxy }

// merge lists the config targets and then the usable admin ones. A name belongs
// to one source at a time and the admin target holds it, so a config target of
// the same name is left out rather than fatal: refusing to boot would stop the
// operator opening the page that removes the admin target. A row that is not
// usable still holds its name, because serving the config target of that name
// would hand it a stamp the database says belongs to something else.
func (r *registry) merge(rows []AdminTarget) ([]Target, []ignoredTarget) {
	held := make(map[string]bool, len(rows))
	for _, row := range rows {
		held[row.Target.Name] = true
	}

	var targets []Target
	var ignored []ignoredTarget
	for _, t := range r.cfg.Targets {
		if held[t.Name] {
			ignored = append(ignored, ignoredTarget{t.Name, "name in use by an admin target"})
			continue
		}
		targets = append(targets, t)
	}
	for _, row := range rows {
		t, err := r.usable(row)
		if err != nil {
			slog.Error("admin target left out", "target", row.Target.Name, "err", err)
			continue
		}
		targets = append(targets, t)
	}
	return targets, ignored
}

// usable turns a stored row into a servable target, or says why it is not one.
// Every check is repeated here, after the save-time ones, because the row may
// have been written by different code, a different key or a different policy.
func (r *registry) usable(row AdminTarget) (Target, error) {
	t := row.Target
	t.Resource = r.cfg.PublicURL + "/" + t.Name + "/mcp"

	if row.DecodeErr != nil {
		return Target{}, row.DecodeErr
	}
	if t.Stamp() != row.StoredStamp {
		return Target{}, errors.New("the stored stamp does not match the definition")
	}
	if t.Mode == CredStatic {
		// A value that will not unseal, after a key rotation or with mixed keys
		// during a rolling deploy, is never served with empty headers.
		headers, err := r.store.openStatic(row)
		if err != nil {
			return Target{}, fmt.Errorf("the static value cannot be unsealed: %w", err)
		}
		t.StaticHeaders = headers
	}
	if err := checkAdminTarget(t, r.cfg.AllowedUpstreamHosts, r.cfg.AllowedUpstreamNetworks); err != nil {
		return Target{}, err
	}
	return t, nil
}

// Poll rebuilds whenever targets_version moves, until ctx ends. A failed poll
// keeps the current snapshot and tries again at the next tick.
func (r *registry) Poll(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.pollOnce(ctx)
		}
	}
}

func (r *registry) pollOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, rebuildTimeout)
	defer cancel()
	if _, err := r.rebuildIfBehind(ctx); err != nil {
		slog.Warn("polling for target changes failed; keeping the current targets", "err", err)
	}
}

// catchUpTimeout bounds the check a request waits on. It is much shorter than
// rebuildTimeout because a client is blocked on it.
const catchUpTimeout = 2 * time.Second

// allowCheck admits at most one database check a second per replica, shared by
// RequestRebuild and CatchUp so unauthenticated traffic cannot multiply them.
func (r *registry) allowCheck() bool {
	now := time.Now().UnixNano()
	last := r.lastRequest.Load()
	return now-last >= int64(time.Second) && r.lastRequest.CompareAndSwap(last, now)
}

// CatchUp is for a request that names a target this snapshot lacks, which on a
// replica that has not polled yet may be one created seconds ago. It rebuilds if
// the database is ahead and reports whether the snapshot changed. When the
// throttle suppresses the check it returns false and no error, so the caller
// answers as it would have. An error means the replica cannot tell whether the
// name exists.
func (r *registry) CatchUp(ctx context.Context) (bool, error) {
	if !r.allowCheck() {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, catchUpTimeout)
	defer cancel()
	changed, err := r.rebuildIfBehind(ctx)
	if err != nil {
		slog.Warn("catching up on an unknown target name failed", "err", err)
	}
	return changed, err
}

// RequestRebuild starts a rebuild in the background for a request that found
// this replica behind. Requests arrive in bursts, so it runs at most once a
// second. A row that usable() rejects stays behind the database for good, so
// the version is checked first, as pollOnce does, to keep requests for it from
// repeating the full read.
func (r *registry) RequestRebuild() {
	if !r.allowCheck() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(r.bg, rebuildTimeout)
		defer cancel()
		if _, err := r.rebuildIfBehind(ctx); err != nil {
			slog.Warn("rebuilding the targets failed; keeping the current ones", "err", err)
		}
	}()
}
