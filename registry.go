package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// entry is one served target with what is derived from it. The stamp is
// computed once here because every request compares against it.
type entry struct {
	Target Target
	Stamp  string
	Proxy  http.Handler
}

// snapshot is an immutable view of the targets being served. A request loads
// one and uses it throughout, so a target cannot change definition between the
// audience check and the credential swap.
type snapshot struct {
	entries    []*entry
	byName     map[string]*entry
	byResource map[string]*entry
}

// registry hands out the current snapshot. Replacing it is a single atomic
// store, so readers never take a lock.
type registry struct {
	cur atomic.Pointer[snapshot]
}

func (r *registry) Load() *snapshot   { return r.cur.Load() }
func (r *registry) Store(s *snapshot) { r.cur.Store(s) }

// newSnapshot builds a snapshot from targets, which must be non-empty because
// the single-target paths read the first entry. An entry
// whose stamp matches one in prev keeps that entry's proxy, so its in-flight
// limit and connection pool survive a rebuild that did not change where it
// sends requests.
func newSnapshot(targets []Target, publicURL string, prev *snapshot) (*snapshot, error) {
	if len(targets) == 0 {
		return nil, errors.New("no targets to serve")
	}
	s := &snapshot{
		byName:     make(map[string]*entry, len(targets)),
		byResource: make(map[string]*entry, len(targets)),
	}
	for _, t := range targets {
		e := &entry{Target: t, Stamp: t.Stamp()}
		if old := prev.find(t.Name); old != nil && old.Stamp == e.Stamp {
			e.Proxy = old.Proxy
		} else {
			u, err := url.Parse(t.UpstreamMCP)
			if err != nil {
				return nil, fmt.Errorf("target %q: %w", t.Name, err)
			}
			// Only a per_user target can produce an upstream 401 the user can act on.
			enrolURL := ""
			if t.Mode == CredPerUser {
				enrolURL = publicURL + "/settings"
			}
			e.Proxy = newReverseProxy(u, enrolURL)
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
func (s *snapshot) MultiTarget() bool { return s.entries[0].Target.Name != "" }

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
