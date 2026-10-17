package protocol

import "testing"

// TestZeroizeWipesSecretsAndSkippedKeys checks the FFI-facing Zeroize contract:
// every secret buffer is cleared, skipped message keys are dropped, a second
// call is harmless, and the session stops being able to decrypt.
func TestZeroizeWipesSecretsAndSkippedKeys(t *testing.T) {
	alice, bob := establish(t)

	// Bob skips one message so a skipped key is stored, then decrypts the next.
	h1, c1, err := alice.Encrypt([]byte("skipped"))
	if err != nil {
		t.Fatal(err)
	}
	h2, c2, err := alice.Encrypt([]byte("delivered"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(h2, c2); err != nil {
		t.Fatal(err)
	}
	if len(bob.skipped) == 0 {
		t.Fatal("expected a stored skipped message key")
	}

	bob.Zeroize()

	if !allZero(bob.rk) || !allZero(bob.cks) || !allZero(bob.ckr) || !allZero(bob.dhr) {
		t.Fatal("root/chain keys survived Zeroize")
	}
	if bob.dhs != nil && !allZero(bob.dhs.PrivateKey) {
		t.Fatal("ratchet private key survived Zeroize")
	}
	if len(bob.skipped) != 0 {
		t.Fatal("skipped message keys survived Zeroize")
	}
	if len(bob.chainOrder) != 0 {
		t.Fatal("skipped-chain index survived Zeroize")
	}

	bob.Zeroize() // idempotent

	// With the skipped key wiped, the out-of-order message can no longer open.
	if _, err := bob.Decrypt(h1, c1); err == nil {
		t.Fatal("zeroized session decrypted a skipped message")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
