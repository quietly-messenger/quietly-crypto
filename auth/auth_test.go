package auth

import (
	"strings"
	"testing"

	"github.com/quietly-messenger/quietly-crypto/identity"
)

// Known-answer vector for the §5.1 canonical string, using the example from
// PROTOCOL.md (the empty-body SHA-256 is the well-known
// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855).
func TestCanonicalStringKnownAnswer(t *testing.T) {
	got := CanonicalString("POST", "/v1/messages?limit=50", 1785340800000, "qtFT7cJ2mVvJ7t0RJHYy9w", nil)
	want := "POST\n/v1/messages?limit=50\n1785340800000\nqtFT7cJ2mVvJ7t0RJHYy9w\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("CanonicalString mismatch\n got %q\nwant %q", got, want)
	}
}

func TestBodyHashEmptyBody(t *testing.T) {
	got := BodyHash(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("BodyHash(empty) = %q, want %q", got, want)
	}
}

func TestSignVerifyRequest(t *testing.T) {
	ik, err := identity.GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) == 0 || strings.ContainsAny(nonce, "+/=") {
		t.Fatalf("nonce should be base64url without padding, got %q", nonce)
	}

	body := []byte(`{"username":"alice"}`)
	sig, err := SignRequest(ik.SigPriv, "POST", "/v1/accounts", 1785340800000, nonce, body)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if !VerifyRequest(ik.SigPub, "POST", "/v1/accounts", 1785340800000, nonce, body, sig) {
		t.Fatal("signature failed to verify")
	}

	// Any tampering must fail verification.
	if VerifyRequest(ik.SigPub, "POST", "/v1/accounts", 1785340800001, nonce, body, sig) {
		t.Fatal("tampered timestamp verified")
	}
	if VerifyRequest(ik.SigPub, "GET", "/v1/accounts", 1785340800000, nonce, body, sig) {
		t.Fatal("tampered method verified")
	}
	if VerifyRequest(ik.SigPub, "POST", "/v1/accounts", 1785340800000, nonce, []byte("tampered"), sig) {
		t.Fatal("tampered body verified")
	}
}
