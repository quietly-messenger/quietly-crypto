package cryptocore

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 5869 Appendix A.1 Test Case 1 (SHA-256).
func TestHKDFSHA256RFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")

	got, err := HKDFSHA256(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("HKDFSHA256: %v", err)
	}
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a" +
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865")
	if !bytes.Equal(got, want) {
		t.Fatalf("HKDF mismatch\n got %x\nwant %x", got, want)
	}
}

func TestHKDFSHA256IsDeterministic(t *testing.T) {
	a, err := HKDFSHA256([]byte("ikm"), []byte("salt"), []byte("info"), 32)
	if err != nil {
		t.Fatalf("HKDFSHA256: %v", err)
	}
	b, _ := HKDFSHA256([]byte("ikm"), []byte("salt"), []byte("info"), 32)
	if !bytes.Equal(a, b) {
		t.Fatal("HKDF output is not deterministic")
	}
	if _, err := HKDFSHA256(nil, nil, nil, 0); err == nil {
		t.Fatal("expected error for zero output length")
	}
}

func TestArgon2idDeterministic(t *testing.T) {
	p := Argon2idParams{Time: 2, Memory: 8 * 1024, Threads: 1, KeyLen: 32}
	salt := []byte("somesalt") // >= MinArgon2idSaltLen
	a, err := Argon2id([]byte("correct horse battery staple"), salt, p)
	if err != nil {
		t.Fatalf("Argon2id: %v", err)
	}
	b, _ := Argon2id([]byte("correct horse battery staple"), salt, p)
	if !bytes.Equal(a, b) {
		t.Fatal("Argon2id output is not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("Argon2id key length = %d, want 32", len(a))
	}
}

// TestArgon2idRejectsInvalidParams locks in the fail-closed validation that
// prevents x/crypto panics and unbounded allocations.
func TestArgon2idRejectsInvalidParams(t *testing.T) {
	salt := []byte("somesalt")
	valid := Argon2idParams{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}

	if _, err := Argon2id([]byte("p"), salt, valid); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(Argon2idParams) Argon2idParams
		salt []byte
	}{
		{"zero time", func(p Argon2idParams) Argon2idParams { p.Time = 0; return p }, salt},
		{"zero threads", func(p Argon2idParams) Argon2idParams { p.Threads = 0; return p }, salt},
		{"zero key len", func(p Argon2idParams) Argon2idParams { p.KeyLen = 0; return p }, salt},
		{"short salt", func(p Argon2idParams) Argon2idParams { return p }, []byte("short")},
		{"huge memory", func(p Argon2idParams) Argon2idParams { p.Memory = MaxArgon2idMemoryKiB + 1; return p }, salt},
	}
	for _, c := range cases {
		if _, err := Argon2id([]byte("p"), c.salt, c.mut(valid)); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}
