package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/quietly-messenger/quietly-crypto/auth"
	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/pow"
)

// TestAuthSignRequestMatchesLibrary pins the FFI signing helper to the library
// the server verifies: a client using quietly_auth_sign_request produces
// exactly what auth.VerifyRequest accepts.
func TestAuthSignRequestMatchesLibrary(t *testing.T) {
	kp, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const method = "POST"
	const path = "/v1/devices?limit=100"
	const ts = int64(1785340801234)
	body := []byte(`{"v":"quietly/1"}`)
	nonce, err := auth.NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	sig, ok := authSignRequest(kp.PrivateKey, method, path, ts, nonce, body)
	if !ok {
		t.Fatal("authSignRequest rejected a valid key")
	}
	if len(sig) != cryptocore.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), cryptocore.SignatureSize)
	}
	if !auth.VerifyRequest(kp.PublicKey, method, path, ts, nonce, body, sig) {
		t.Fatal("FFI signature does not verify")
	}
	// The signature is bound to the canonical string: a different body fails.
	if auth.VerifyRequest(kp.PublicKey, method, path, ts, nonce, []byte("tampered"), sig) {
		t.Fatal("FFI signature verified over a different body")
	}
	// Wrong private-key length is rejected before any signing.
	if _, ok := authSignRequest(kp.PrivateKey[:16], method, path, ts, nonce, body); ok {
		t.Fatal("short private key accepted")
	}
}

func TestAuthBodyHashAndCanonical(t *testing.T) {
	body := []byte(`{"v":"quietly/1"}`)
	sum := sha256.Sum256(body)
	if got := string(authBodyHash(body)); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("body hash = %q", got)
	}
	// An empty body hashes as SHA-256("") and is accepted (nil, length 0).
	if got := string(authBodyHash(nil)); got != auth.BodyHash(nil) {
		t.Fatalf("empty body hash = %q", got)
	}

	got := string(authCanonical("GET", "/v1/users/bob", 1785340801234, "nonce", nil))
	want := "GET\n/v1/users/bob\n1785340801234\nnonce\n" + auth.BodyHash(nil)
	if got != want {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
}

func TestPowSolveNonce(t *testing.T) {
	const ts = int64(1785340801234)
	nonce, ok := powSolveNonce("alice", ts, 10)
	if !ok {
		t.Fatal("valid difficulty rejected")
	}
	if !pow.Verify("alice", ts, nonce, 10) {
		t.Fatal("solved nonce does not verify")
	}
	if _, ok := powSolveNonce("alice", ts, pow.MaxDifficulty+1); ok {
		t.Fatal("out-of-range difficulty accepted")
	}
	if _, ok := powSolveNonce("alice", ts, -1); ok {
		t.Fatal("negative difficulty accepted")
	}
}
