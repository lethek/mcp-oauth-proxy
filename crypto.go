package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// newSecret returns a URL-safe random string suitable for use as an
// authorization code, access token, refresh token or client identifier.
func newSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is what we actually persist for bearer credentials. A database
// disclosure then yields no usable tokens. These values are already
// high-entropy, so a plain SHA-256 is enough — there is nothing to brute force.
func hashToken(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// s256 computes the PKCE code challenge for a verifier, per RFC 7636.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type sealer struct{ aead cipher.AEAD }

func newSealer(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

// seal encrypts plaintext and prefixes the nonce, so the result is
// self-contained and safe to store as a single opaque column.
func (s *sealer) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *sealer) open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("ciphertext shorter than nonce")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], nil)
}
