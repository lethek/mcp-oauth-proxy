package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRedirectURIRejectsUserinfo: "https://accounts.google.com@evil.example/cb"
// parses with Host evil.example, and the consent screen prints the string as
// given. A reader sees a name they trust and approves a redirect elsewhere,
// which defeats the one control standing between an anonymous registration and
// someone else's credentials.
func TestRedirectURIRejectsUserinfo(t *testing.T) {
	for _, raw := range []string{
		"https://accounts.google.com@evil.example/cb",
		"https://user:pass@evil.example/cb",
		"https://user@evil.example/cb",
	} {
		if err := validateRedirectURI(raw); err == nil {
			t.Errorf("accepted %q, which reads as a different host than it targets", raw)
		}
	}

	// The same host without the misleading prefix is still fine.
	if err := validateRedirectURI("https://evil.example/cb"); err != nil {
		t.Errorf("rejected an ordinary https redirect: %v", err)
	}
}

// TestRedirectURIIsLengthCapped: registration is anonymous and a client row
// survives for unusedClientTTL, so an unbounded URI is a way to fill the
// database from outside.
func TestRedirectURIIsLengthCapped(t *testing.T) {
	long := "https://client.example/" + strings.Repeat("x", maxRedirectURILen)
	if err := validateRedirectURI(long); err == nil {
		t.Error("accepted a redirect_uri over the length cap")
	}
	if err := validateRedirectURI("https://client.example/" + strings.Repeat("x", 100)); err != nil {
		t.Errorf("rejected an ordinary-length redirect_uri: %v", err)
	}
}

func TestIsLoopbackHostIsCaseInsensitive(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST", "LocalHost", "localhost."} {
		if !isLoopbackHost(host) {
			t.Errorf("isLoopbackHost(%q) = false, want true", host)
		}
	}
	if isLoopbackHost("notlocalhost") {
		t.Error("isLoopbackHost(\"notlocalhost\") = true")
	}
}

// TestClientKeyTrustsOnlyDeclaredHops is the rate-limiter's whole correctness
// property.
//
// Ignoring X-Forwarded-For entirely means every caller behind an ingress shares
// one bucket, so a single client exceeding the cap locks everyone else out —
// a remote kill switch rather than a defence. Honouring it blindly is the
// opposite mistake, letting a caller mint a fresh bucket per request. Only the
// declared number of hops, counted from the right, is trustworthy.
func TestClientKeyTrustsOnlyDeclaredHops(t *testing.T) {
	req := func(xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// No declared hops: the header is caller-supplied and must be ignored.
	if got := clientKey(req("1.2.3.4"), 0); got != "10.0.0.1" {
		t.Errorf("with no trusted hops, key = %q, want the peer address", got)
	}

	// One hop: the peer IS the only trusted hop, so still the peer.
	if got := clientKey(req("1.2.3.4"), 1); got != "10.0.0.1" {
		t.Errorf("with one trusted hop, key = %q, want the peer address", got)
	}

	// Two hops: the rightmost header entry was written by our own edge.
	if got := clientKey(req("9.9.9.9, 1.2.3.4"), 2); got != "1.2.3.4" {
		t.Errorf("with two trusted hops, key = %q, want the rightmost entry", got)
	}

	// A caller prepending entries cannot reach further left than declared.
	if got := clientKey(req("spoofed, 9.9.9.9, 1.2.3.4"), 2); got != "1.2.3.4" {
		t.Errorf("a spoofed prefix changed the key to %q", got)
	}

	// More hops declared than present falls back to the peer rather than
	// reading an attacker-controlled entry.
	if got := clientKey(req("1.2.3.4"), 9); got != "10.0.0.1" {
		t.Errorf("with more hops than entries, key = %q, want the peer address", got)
	}
}

// TestClientKeyAggregatesIPv6: a single host is routinely given a whole /64, so
// keying on the full address hands out an unlimited supply of fresh buckets and
// fills the table that refuses new keys when full.
func TestClientKeyAggregatesIPv6(t *testing.T) {
	key := func(addr string) string {
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.RemoteAddr = addr
		return clientKey(r, 0)
	}

	a := key("[2001:db8:1:2::1]:443")
	b := key("[2001:db8:1:2:ffff:ffff:ffff:ffff]:443")
	if a != b {
		t.Errorf("addresses in one /64 produced different keys %q and %q", a, b)
	}
	if c := key("[2001:db8:1:3::1]:443"); c == a {
		t.Error("addresses in different /64s shared a key")
	}
	// IPv4 is keyed exactly, since a single address is the unit there.
	if got := key("203.0.113.5:443"); got != "203.0.113.5" {
		t.Errorf("IPv4 key = %q, want the exact address", got)
	}
}
