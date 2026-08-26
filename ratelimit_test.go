package main

import (
	"strconv"
	"testing"
	"time"
)

func TestLimiterAllowsUpToTheLimitThenRefuses(t *testing.T) {
	l := newLimiter(3, time.Minute)

	for i := range 3 {
		if !l.allow("peer") {
			t.Fatalf("request %d was refused inside the limit", i+1)
		}
	}
	if l.allow("peer") {
		t.Error("the limiter allowed a fourth request")
	}

	// A different caller has its own budget.
	if !l.allow("other-peer") {
		t.Error("a different peer was refused")
	}
}

func TestLimiterRecoversAfterTheWindow(t *testing.T) {
	l := newLimiter(1, 20*time.Millisecond)

	if !l.allow("peer") {
		t.Fatal("the first request was refused")
	}
	if l.allow("peer") {
		t.Fatal("the second request inside the window was allowed")
	}

	time.Sleep(30 * time.Millisecond)
	if !l.allow("peer") {
		t.Error("the limiter did not recover after its window elapsed")
	}
}

func TestLimiterBoundsItsOwnMemory(t *testing.T) {
	l := newLimiter(1, time.Hour)

	for i := range maxTrackedKeys + 100 {
		l.allow(string(rune(i%1114111)) + "-key")
	}
	if len(l.windows) > maxTrackedKeys {
		t.Errorf("the limiter tracks %d keys, over its own cap of %d", len(l.windows), maxTrackedKeys)
	}
}

// TestLimiterStillServesKnownCallersWhenFull covers the case where the tracking
// map is at its cap. An established caller inside its budget must still be
// answered: serving it does not add a key, and refusing it would punish exactly
// the callers a flood is not coming from.
func TestLimiterStillServesKnownCallersWhenFull(t *testing.T) {
	l := newLimiter(5, time.Hour)

	const known = "established-caller"
	if !l.allow(known) {
		t.Fatal("the established caller was refused on its first request")
	}

	// Fill the map to its cap with live windows.
	for i := len(l.windows); i < maxTrackedKeys; i++ {
		l.allow("flood-" + strconv.Itoa(i))
	}
	if len(l.windows) != maxTrackedKeys {
		t.Fatalf("setup: tracking %d keys, want %d", len(l.windows), maxTrackedKeys)
	}

	if !l.allow(known) {
		t.Error("an established caller inside its budget was refused because the map was full")
	}

	// A genuinely new caller is still refused, because admitting it would grow
	// the map past the cap.
	if l.allow("brand-new-caller") {
		t.Error("a new caller was admitted past the tracking cap")
	}
}
