package cryptocore

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := randomBytes(AEADKeySize)
	nonce, _ := randomBytes(AEADNonceSize)
	plaintext := []byte("quietly secret message")
	aad := []byte("routing metadata")

	ct, err := Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ct) != len(plaintext)+AEADTagSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext)+AEADTagSize)
	}

	pt, err := Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatal("round-tripped plaintext does not match")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, _ := randomBytes(AEADKeySize)
	ct, err := Encrypt(key, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) != AEADNonceSize+len("hello")+AEADTagSize {
		t.Fatalf("encrypted length = %d", len(ct))
	}
	pt, err := Decrypt(key, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("decrypted %q, want %q", pt, "hello")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key, _ := randomBytes(AEADKeySize)
	nonce, _ := randomBytes(AEADNonceSize)
	ct, _ := Seal(key, nonce, []byte("secret"), nil)

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0x01
	if _, err := Open(key, nonce, tampered, nil); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}

	wrongKey, _ := randomBytes(AEADKeySize)
	if _, err := Open(wrongKey, nonce, ct, nil); err == nil {
		t.Fatal("expected error for wrong key")
	}

	wrongNonce, _ := randomBytes(AEADNonceSize)
	if _, err := Open(key, wrongNonce, ct, nil); err == nil {
		t.Fatal("expected error for wrong nonce")
	}
}
