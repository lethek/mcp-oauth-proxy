package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
// one bucket, so a single client exceeding the cap locks everyone else out — a
// remote kill switch rather than a defence. Honouring it blindly is the opposite
// mistake, letting a caller mint a fresh bucket per request.
//
// The arithmetic is the part worth pinning. Each proxy APPENDS the address it
// received from, so with one proxy the header holds the client and the peer is
// the proxy. An earlier version of this test asserted the peer was correct for
// one hop, which was simply wrong and hid an off-by-one that left the shared
// bucket in place.
func TestClientKeyTrustsOnlyDeclaredHops(t *testing.T) {
	req := func(xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// No declared hops: the header is entirely caller-supplied and is ignored.
	if got := clientKey(req("1.2.3.4"), 0); got != "10.0.0.1" {
		t.Errorf("with no trusted hops, key = %q, want the peer address", got)
	}

	// One proxy: it appended the client and connected to us, so the client is
	// the only entry and the peer is the proxy.
	if got := clientKey(req("198.51.100.7"), 1); got != "198.51.100.7" {
		t.Errorf("with one trusted hop, key = %q, want the client from the header", got)
	}

	// Two proxies: the header is "client, proxy1" and the peer is proxy2.
	if got := clientKey(req("198.51.100.7, 10.0.0.2"), 2); got != "198.51.100.7" {
		t.Errorf("with two trusted hops, key = %q, want the client", got)
	}

	// A caller prepending entries cannot displace the one its proxy wrote,
	// because a spoofed value lands to the LEFT of it.
	if got := clientKey(req("spoofed, 198.51.100.7"), 1); got != "198.51.100.7" {
		t.Errorf("a spoofed prefix changed the key to %q", got)
	}
	if got := clientKey(req("spoofed, 198.51.100.7, 10.0.0.2"), 2); got != "198.51.100.7" {
		t.Errorf("a spoofed prefix changed the key to %q", got)
	}

	// Separate header lines are one chain, so splitting the spoof across them
	// does not help either.
	multi := req("")
	multi.Header.Add("X-Forwarded-For", "spoofed")
	multi.Header.Add("X-Forwarded-For", "198.51.100.7")
	if got := clientKey(multi, 1); got != "198.51.100.7" {
		t.Errorf("a spoof split across header lines changed the key to %q", got)
	}

	// Fewer entries than declared hops means the header was stripped or the
	// configuration is wrong. Reading further left would trust a caller-supplied
	// value, so the peer is used instead.
	if got := clientKey(req("1.2.3.4"), 9); got != "10.0.0.1" {
		t.Errorf("with more hops than entries, key = %q, want the peer address", got)
	}
	if got := clientKey(req(""), 1); got != "10.0.0.1" {
		t.Errorf("with no header at all, key = %q, want the peer address", got)
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

// TestWrongClientIDDoesNotConsumeTheRefreshToken guards a sequence that used to
// destroy a working session.
//
// The token was marked used before the client binding was checked, so a refresh
// naming the wrong client burned the caller's only valid token. The legitimate
// retry that followed then looked like a replay, and replay detection revokes
// the entire session. An ordinary mistake, or one hostile request from anyone
// holding a leaked token, was enough to sign a user out permanently.
func TestWrongClientIDDoesNotConsumeTheRefreshToken(t *testing.T) {
	h := newHarness(t)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	_, refresh := h.tokens(clientID, redirect)

	for name, given := range map[string]string{
		"a different client": "some-other-client",
		"no client at all":   "",
	} {
		t.Run("refused for "+name, func(t *testing.T) {
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
			if given != "" {
				form.Set("client_id", given)
			}
			resp := h.postForm("/token", form)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
		})
	}

	// The token must still be usable by the client it belongs to.
	resp := h.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the legitimate refresh failed with %d; the earlier attempts consumed the token", resp.StatusCode)
	}

	// And the session survived, so nothing was revoked along the way.
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" {
		t.Error("no access token issued")
	}
}

// TestDiscoveryRequiresAnIssuer: RFC 8414 makes the issuer mandatory, and it is
// the field the match is performed against. Accepting a document without one
// meant the check could be skipped by omitting it.
func TestDiscoveryRequiresAnIssuer(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"authorization_endpoint": "https://provider.example/authorize",
			"token_endpoint":         "https://provider.example/token",
		})
	}))
	defer provider.Close()

	if _, err := NewUpstream(&Config{UpstreamIssuer: provider.URL}).Meta(context.Background()); err == nil {
		t.Fatal("accepted a discovery document that declared no issuer")
	}
}

// TestIsPublicIPRejectsEmbeddedIPv4 covers the IPv6 forms that carry a v4
// destination inside them. net.IP only recognises the ::ffff: mapping, so
// checking the v6 ranges alone let an address reach the very networks the guard
// exists to exclude.
func TestIsPublicIPRejectsEmbeddedIPv4(t *testing.T) {
	for raw, want := range map[string]bool{
		// IPv4-compatible, ::a.b.c.d
		"::10.0.0.99":     false,
		"::127.0.0.1":     false,
		"::93.184.216.34": true,
		// 6to4, 2002:aabb:ccdd::/48 where aabb:ccdd is the v4 address
		"2002:0a00:0063::": false, // 10.0.0.99
		"2002:7f00:0001::": false, // 127.0.0.1
		"2002:5db8:d822::": true,  // 93.184.216.34
		// NAT64
		"64:ff9b::10.0.0.99":     false,
		"64:ff9b::93.184.216.34": true,
		// An ordinary v6 address is unaffected.
		"2606:2800:220::": true,
		"fd00::1":         false,
	} {
		if got := isPublicIP(net.ParseIP(raw)); got != want {
			t.Errorf("isPublicIP(%s) = %v, want %v", raw, got, want)
		}
	}
}

// TestCIMDFailuresDoNotEvictDocuments: the negative cache exists to stop
// repeated outbound fetches, so it must not become a way to force them. Sharing
// one map meant 256 bogus client_ids discarded every real client's document.
func TestCIMDFailuresDoNotEvictDocuments(t *testing.T) {
	c := newCIMD(false)
	c.store("https://good.example/mcp", Client{ID: "https://good.example/mcp", Name: "Good"}, nil)

	for i := 0; i < cimdCacheSize*2; i++ {
		c.store("https://bad.example/"+strconv.Itoa(i), Client{}, errors.New("nope"))
	}

	entry, ok := c.cached("https://good.example/mcp")
	if !ok || entry.err != nil {
		t.Fatal("a flood of failures evicted a cached document")
	}
	if entry.client.Name != "Good" {
		t.Errorf("cached document = %+v", entry.client)
	}
}
