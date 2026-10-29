package main

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// lagging makes the harness's server answer from a second registry, standing in
// for a replica that has not polled. Targets are then created through the
// harness's own store, as an admin on another replica would.
func (h *harness) lagging() (*registry, *Store) {
	h.t.Helper()
	other, otherStore := h.secondReplica()
	h.srv.reg = other
	return other, otherStore
}

func (h *harness) metadataStatus(name string) (int, http.Header) {
	h.t.Helper()
	resp := h.get(h.proxy.URL + "/.well-known/oauth-protected-resource/" + name + "/mcp")
	resp.Body.Close()
	return resp.StatusCode, resp.Header
}

// A replica that has not polled yet answers the first request for a target
// created in the last poll window, instead of a 404 a client may treat as final.
func TestUnknownNameCatchesUpOnTheFirstRequest(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	other, _ := h.lagging()

	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	if other.Load().byName["gamma"] != nil {
		t.Fatal("the lagging replica already has the target")
	}
	if status, _ := h.mcpStatus("/gamma/mcp", ""); status != http.StatusUnauthorized {
		t.Errorf("/gamma/mcp: status %d, want the 401 challenge, not a 404", status)
	}

	h.createAdmin(h.adminTarget("delta", "/alpha-upstream"))
	other.lastRequest.Store(0)
	if status, _ := h.metadataStatus("delta"); status != http.StatusOK {
		t.Errorf("metadata for delta: status %d, want 200", status)
	}
}

// A name that does not exist is still a 404, and the check behind it runs at
// most once a second however much unknown-name traffic arrives.
func TestUnknownNameStays404AndIsThrottled(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	other, _ := h.lagging()

	if status, _ := h.mcpStatus("/nope/mcp", ""); status != http.StatusNotFound {
		t.Fatalf("unknown name: status %d, want 404", status)
	}

	// Created after the check above, so only a second read could find it.
	h.createAdmin(h.adminTarget("later", "/alpha-upstream"))
	if status, _ := h.mcpStatus("/later/mcp", ""); status != http.StatusNotFound {
		t.Errorf("inside the throttle window: status %d, want 404 without another read", status)
	}
	if other.Load().byName["later"] != nil {
		t.Error("the replica read the database again inside the throttle window")
	}

	// Control: once the window passes the same request finds it.
	other.lastRequest.Store(0)
	if status, _ := h.mcpStatus("/later/mcp", ""); status != http.StatusUnauthorized {
		t.Errorf("after the window: status %d, want 401", status)
	}
}

// When the replica cannot reach the database it cannot say the name is absent.
func TestFailedCatchUpAnswers503(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	other, otherStore := h.lagging()
	otherStore.Close()

	if status, hdr := h.mcpStatus("/gamma/mcp", ""); status != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" {
		t.Errorf("/gamma/mcp: status %d, Retry-After %q; want 503 with Retry-After", status, hdr.Get("Retry-After"))
	}
	other.lastRequest.Store(0)
	if status, hdr := h.metadataStatus("gamma"); status != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" {
		t.Errorf("metadata: status %d, Retry-After %q; want 503 with Retry-After", status, hdr.Get("Retry-After"))
	}
}

// With the feature off an unknown name is a plain 404 and the targets table is
// not touched, so renaming it away changes nothing.
func TestUnknownNameWithFeatureOffNeverTouchesTargets(t *testing.T) {
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

	if status, _ := h.mcpStatus("/nope/mcp", ""); status != http.StatusNotFound {
		t.Errorf("/nope/mcp: status %d, want 404", status)
	}
	if status, _ := h.metadataStatus("nope"); status != http.StatusNotFound {
		t.Errorf("metadata: status %d, want 404", status)
	}
}

// Callers queued on an up-to-date snapshot each cost one cheap version read and
// never the full load.
func TestQueuedRebuildCallersSkipTheFullRead(t *testing.T) {
	h := newHarnessWith(t, adminTwoTargets)
	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()

	var loads atomic.Int32
	h.srv.store.afterVersionRead = func() { loads.Add(1) }
	pool := h.srv.store.pool
	before := pool.Stat().AcquireCount()

	const n = 8
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.srv.reg.rebuildIfBehind(t.Context()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if got := loads.Load(); got != 0 {
		t.Errorf("LoadAdminTargets ran %d times against an up-to-date snapshot", got)
	}
	if reads := pool.Stat().AcquireCount() - before; reads > n {
		t.Errorf("%d database reads for %d callers, want at most one each", reads, n)
	}
}
