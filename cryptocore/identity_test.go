package cryptocore

import (
	"bytes"
	"testing"
)

func TestIdentitySignVerify(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	if len(kp.PublicKey) != IdentityPublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(kp.PublicKey), IdentityPublicKeySize)
	}
	if len(kp.PrivateKey) != IdentityPrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(kp.PrivateKey), IdentityPrivateKeySize)
	}

	msg := []byte("quietly identity test message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), SignatureSize)
	}
	if !VerifyIdentitySignature(kp.PublicKey, msg, sig) {
		t.Fatal("signature failed to verify")
	}
}

func TestIdentityVerifyRejectsTamperedMessage(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	msg := []byte("original")
	sig, _ := kp.Sign(msg)
	if VerifyIdentitySignature(kp.PublicKey, []byte("tampered"), sig) {
		t.Fatal("tampered message unexpectedly verified")
	}
	if VerifyIdentitySignature(kp.PublicKey, msg, bytes.Repeat([]byte{0}, SignatureSize)) {
		t.Fatal("zero signature unexpectedly verified")
	}
}

func TestNewIdentityKeyPair(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}

	got, err := NewIdentityKeyPair(kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("NewIdentityKeyPair: %v", err)
	}
	if !bytes.Equal(got.PublicKey, kp.PublicKey) || !bytes.Equal(got.PrivateKey, kp.PrivateKey) {
		t.Fatal("round-tripped keypair does not match")
	}

	if _, err := NewIdentityKeyPair(kp.PublicKey[:16], kp.PrivateKey); err == nil {
		t.Fatal("expected error for short public key")
	}
	if _, err := NewIdentityKeyPair(kp.PublicKey, kp.PrivateKey[:16]); err == nil {
		t.Fatal("expected error for short private key")
	}

	other, _ := GenerateIdentityKeyPair()
	if _, err := NewIdentityKeyPair(kp.PublicKey, other.PrivateKey); err == nil {
		t.Fatal("expected error for mismatched private key")
	}
}
