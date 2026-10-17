package safety

import (
	"bytes"
	"testing"
)

// Independent known-answer vector: 30 bytes of 0xFF produce six chunks of
// 0xFFFFFFFFFF, and 0xFFFFFFFFFF mod 100000 = 27775.
func TestFormatKnownAnswer(t *testing.T) {
	fp := bytes.Repeat([]byte{0xFF}, FingerprintSize)
	got, err := Format(fp)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	want := "277752777527775277752777527775"
	if got != want {
		t.Fatalf("Format = %q, want %q", got, want)
	}
}

func TestFormatPadsGroups(t *testing.T) {
	// A chunk of value 1 must render as "00001" (five digits, zero-padded).
	fp := make([]byte, FingerprintSize)
	fp[4] = 0x01 // first 5-byte chunk = 0x0000000001
	got, err := Format(fp)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if got[:5] != "00001" {
		t.Fatalf("first group = %q, want %q", got[:5], "00001")
	}
	if len(got) != 30 {
		t.Fatalf("formatted length = %d, want 30", len(got))
	}
}

func TestFormatRejectsShortInput(t *testing.T) {
	if _, err := Format(make([]byte, FingerprintSize-1)); err == nil {
		t.Fatal("expected error for short fingerprint")
	}
}

func TestFingerprintDeterministicAndDistinct(t *testing.T) {
	var uid [16]byte
	copy(uid[:], []byte("user-a"))

	ikDH := bytes.Repeat([]byte{0x11}, 32)
	ikSig := bytes.Repeat([]byte{0x22}, 32)

	a := Fingerprint(uid, ikDH, ikSig)
	b := Fingerprint(uid, ikDH, ikSig)
	if a != b {
		t.Fatal("Fingerprint is not deterministic")
	}

	other := Fingerprint(uid, ikDH, bytes.Repeat([]byte{0x33}, 32))
	if a == other {
		t.Fatal("Fingerprint must change when a key changes")
	}

	otherUID := uid
	otherUID[0] ^= 0x01
	if a == Fingerprint(otherUID, ikDH, ikSig) {
		t.Fatal("Fingerprint must change when user_id changes")
	}
}

func TestSafetyNumberIsOrderIndependent(t *testing.T) {
	var uidA, uidB [16]byte
	copy(uidA[:], []byte("alice"))
	copy(uidB[:], []byte("bob"))

	fpA := Fingerprint(uidA, bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32))
	fpB := Fingerprint(uidB, bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x04}, 32))

	ab, err := SafetyNumber(fpA[:], fpB[:])
	if err != nil {
		t.Fatalf("SafetyNumber: %v", err)
	}
	ba, err := SafetyNumber(fpB[:], fpA[:])
	if err != nil {
		t.Fatalf("SafetyNumber: %v", err)
	}
	if ab != ba {
		t.Fatalf("safety number is not order-independent: %q vs %q", ab, ba)
	}
	if len(ab) != 60 {
		t.Fatalf("combined safety number length = %d, want 60", len(ab))
	}
}
