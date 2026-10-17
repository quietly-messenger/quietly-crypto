package cryptocore

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 4231 Test Case 1 (HMAC-SHA256).
func TestHMACSHA256RFC4231(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := []byte("Hi There")
	got := HMACSHA256(key, data)
	want, _ := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	if !bytes.Equal(got, want) {
		t.Fatalf("HMAC-SHA256 mismatch\n got %x\nwant %x", got, want)
	}
}

func TestHMACSHA256DiffersWithKey(t *testing.T) {
	data := []byte("message")
	a := HMACSHA256([]byte("key-a"), data)
	b := HMACSHA256([]byte("key-b"), data)
	if bytes.Equal(a, b) {
		t.Fatal("HMACs under different keys must differ")
	}
	if len(a) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(a))
	}
}
