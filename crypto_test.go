package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRequestWithAuth(header string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

// TestS256RFC7636 uses the worked example from RFC 7636 appendix B. If this
// drifts, every PKCE verification silently stops meaning anything.
func TestS256RFC7636(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := s256(verifier); got != challenge {
		t.Errorf("s256(%q) = %q, want %q", verifier, got, challenge)
	}
}

func TestNewSecretIsUniqueAndLong(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		s := newSecret()
		if len(s) < 43 {
			t.Fatalf("newSecret() = %q, want at least 43 characters of base64", s)
		}
		if seen[s] {
			t.Fatalf("newSecret() repeated %q", s)
		}
		seen[s] = true
	}
}

func TestSealRoundTrip(t *testing.T) {
	s, err := newSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"access_token":"secret"}`)

	sealed, err := s.seal(purposeUpstreamToken, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Error("sealed output contains the plaintext")
	}

	opened, err := s.open(purposeUpstreamToken, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Errorf("open(seal(x)) = %q, want %q", opened, plain)
	}
}

func TestSealUsesAFreshNonce(t *testing.T) {
	s, err := newSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.seal(purposeUpstreamToken, []byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.seal(purposeUpstreamToken, []byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("sealing the same plaintext twice produced identical ciphertext")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	s, err := newSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.seal(purposeUpstreamToken, []byte("upstream token"))
	if err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := s.open(purposeUpstreamToken, tampered); err == nil {
		t.Error("open accepted a modified ciphertext")
	}

	if _, err := s.open(purposeUpstreamToken, sealed[:4]); err == nil {
		t.Error("open accepted a truncated ciphertext")
	}

	other, err := newSealer(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.open(purposeUpstreamToken, sealed); err == nil {
		t.Error("open accepted a ciphertext sealed under a different key")
	}
}

func TestBearerFrom(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":    "abc",
		"bearer abc":    "abc",
		"BEARER  abc  ": "abc",
		"Basic abc":     "",
		"abc":           "",
		"":              "",
		"Bearer":        "",
		"Bearer\tabc":   "",
	}
	for header, want := range cases {
		r := newRequestWithAuth(header)
		if got := bearerFrom(r); got != want {
			t.Errorf("bearerFrom(%q) = %q, want %q", header, got, want)
		}
	}
}

// TestSealIsBoundToItsPurpose: one key protects several unrelated values, so a
// ciphertext produced for one must not open as another. Without the binding,
// safety would rest on the plaintexts failing to unmarshal into each other's
// types, which is a property of today's structs rather than a guarantee.
func TestSealIsBoundToItsPurpose(t *testing.T) {
	s, err := newSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"sub":"someone"}`)

	sealed, err := s.seal(purposeSettingsSession, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.open(purposeUserCredential, sealed); err == nil {
		t.Error("a settings cookie opened as a stored credential")
	}
	if _, err := s.open(purposeUpstreamToken, sealed); err == nil {
		t.Error("a settings cookie opened as an upstream token")
	}
	if _, err := s.open(purposeSettingsSession, sealed); err != nil {
		t.Errorf("its own purpose failed to open: %v", err)
	}
}
