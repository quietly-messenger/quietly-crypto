package cryptocore

import (
	"bytes"
	"testing"
)

func TestX25519SharedSecretIsSymmetric(t *testing.T) {
	a, err := GeneratePreKey()
	if err != nil {
		t.Fatalf("GeneratePreKey a: %v", err)
	}
	b, err := GeneratePreKey()
	if err != nil {
		t.Fatalf("GeneratePreKey b: %v", err)
	}

	ab, err := X25519(a.PrivateKey, b.PublicKey)
	if err != nil {
		t.Fatalf("X25519(a, B): %v", err)
	}
	ba, err := X25519(b.PrivateKey, a.PublicKey)
	if err != nil {
		t.Fatalf("X25519(b, A): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("shared secrets do not match")
	}
	if len(ab) != X25519SharedSecretSize {
		t.Fatalf("shared secret length = %d, want %d", len(ab), X25519SharedSecretSize)
	}
}

func TestNewPreKey(t *testing.T) {
	pk, err := GeneratePreKey()
	if err != nil {
		t.Fatalf("GeneratePreKey: %v", err)
	}
	got, err := NewPreKey(pk.PublicKey, pk.PrivateKey)
	if err != nil {
		t.Fatalf("NewPreKey: %v", err)
	}
	if !bytes.Equal(got.PublicKey, pk.PublicKey) || !bytes.Equal(got.PrivateKey, pk.PrivateKey) {
		t.Fatal("round-tripped prekey does not match")
	}

	if _, err := NewPreKey(pk.PublicKey[:16], pk.PrivateKey); err == nil {
		t.Fatal("expected error for short public key")
	}
	if _, err := NewPreKey(pk.PublicKey, pk.PrivateKey[:16]); err == nil {
		t.Fatal("expected error for short private key")
	}

	other, _ := GeneratePreKey()
	if _, err := NewPreKey(pk.PublicKey, other.PrivateKey); err == nil {
		t.Fatal("expected error for mismatched private key")
	}
}

func TestX25519RejectsLowOrderPoint(t *testing.T) {
	pk, err := GeneratePreKey()
	if err != nil {
		t.Fatalf("GeneratePreKey: %v", err)
	}
	// The all-zero public key is a low-order point: ECDH must reject it.
	if _, err := X25519(pk.PrivateKey, make([]byte, X25519PublicKeySize)); err == nil {
		t.Fatal("expected error for low-order public key")
	}
}

func TestX25519PublicKeyMatches(t *testing.T) {
	pk, err := GeneratePreKey()
	if err != nil {
		t.Fatalf("GeneratePreKey: %v", err)
	}
	pub, err := X25519PublicKey(pk.PrivateKey)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}
	if !bytes.Equal(pub, pk.PublicKey) {
		t.Fatal("derived public key does not match generated public key")
	}
}
