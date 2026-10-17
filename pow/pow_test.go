package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Independent known-answer vector: the preimage
// "quietly/1 pow" || 0x00 || "alice" || 0x00 || "1234567890" || 0x00 || "0"
// hashes to this digest and has 3 leading zero bits.
func TestPreimageKnownAnswer(t *testing.T) {
	p := preimage("alice", 1234567890, 0)
	got := sha256.Sum256(p)
	want, _ := hex.DecodeString("192c3a130fb1501db2884e361c3ea1c25590281dd1067c2c16cc677329d0bb05")
	if string(got[:]) != string(want) {
		t.Fatalf("preimage hash mismatch\n got %x\nwant %x", got, want)
	}
	if leadingZeroBits(got[:]) != 3 {
		t.Fatalf("leading zero bits = %d, want 3", leadingZeroBits(got[:]))
	}
	if !Verify("alice", 1234567890, 0, 3) {
		t.Fatal("Verify(difficulty=3) should be true")
	}
	if Verify("alice", 1234567890, 0, 4) {
		t.Fatal("Verify(difficulty=4) should be false")
	}
}

func TestSolveAndVerify(t *testing.T) {
	const difficulty = 12
	ts := int64(1785340800000)
	nonce := Solve("bob", ts, difficulty)

	if nonce == 0 && difficulty > 8 {
		t.Fatal("unexpectedly trivial nonce")
	}
	if !Verify("bob", ts, nonce, difficulty) {
		t.Fatal("solved nonce failed verification")
	}
	if !Verify("bob", ts, nonce, difficulty-1) {
		t.Fatal("proof should also satisfy a lower difficulty")
	}
	if Verify("bob", ts, nonce-1, difficulty) {
		t.Fatal("nonce-1 should not satisfy the difficulty (Solve must return the minimum)")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	ts := int64(1785340800000)
	nonce := Solve("carol", ts, 10)

	if Verify("carol", ts+1, nonce, 10) {
		t.Fatal("tampered timestamp accepted")
	}
	if Verify("carolx", ts, nonce, 10) {
		t.Fatal("tampered username accepted")
	}
}

func TestSolveLowercasesUsername(t *testing.T) {
	ts := int64(1785340800000)
	a := Solve("Alice", ts, 8)
	b := Solve("alice", ts, 8)
	if a != b {
		t.Fatalf("Solve must be case-insensitive: got %d and %d", a, b)
	}
	if !Verify("ALICE", ts, a, 8) {
		t.Fatal("uppercase username failed verification after lowercasing")
	}
}

func TestVerifyRejectsOutOfRangeDifficulty(t *testing.T) {
	if Verify("a", 1, 0, -1) {
		t.Fatal("negative difficulty accepted")
	}
	if Verify("a", 1, 0, MaxDifficulty+1) {
		t.Fatal("difficulty above 256 accepted")
	}
}
