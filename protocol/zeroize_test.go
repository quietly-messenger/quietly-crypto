package protocol

import (
	"sync"
	"testing"
)

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

// TestZeroizeIsSerializedWithSessionUse pins audit F-24 in the protocol layer:
// Zeroize must take the session lock, so wiping a session another goroutine is
// actively using cannot race reads/writes of the key buffers (cks wipe vs
// Encrypt's HMAC read) or the skipped map (iterate/delete vs clone). Run with
// -race to make a missing lock fail here.
func TestZeroizeIsSerializedWithSessionUse(t *testing.T) {
	alice, bob := establish(t)

	// Leave bob's skipped-key map populated so Zeroize has entries to iterate.
	h1, c1, err := alice.Encrypt([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	h2, c2, err := alice.Encrypt([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(h2, c2); err != nil {
		t.Fatal(err)
	}
	if len(bob.skipped) == 0 {
		t.Fatal("expected a stored skipped message key")
	}

	halt := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		for {
			select {
			case <-halt:
				return
			default:
			}
			// Both paths touch buffers Zeroize wipes: Encrypt consumes the
			// sending chain, Decrypt clones and prunes skipped keys.
			_, _, _ = bob.Encrypt([]byte("race"))
			once.Do(func() { close(started) })
			_, _ = bob.Decrypt(h1, c1)
		}
	}()
	<-started // ensure the wipe starts while the session is being used

	bob.Zeroize()

	// The wipe must leave the session inert: the root key is cleared and the
	// out-of-order message can no longer open. (Encrypt would still run on the
	// zeroed chain buffers and produce garbage — integrity-safe at the peer,
	// but nothing useful — so it is not asserted here.)
	if !allZero(bob.rk) {
		t.Fatal("root key survived Zeroize under concurrent use")
	}
	if len(bob.skipped) != 0 {
		t.Fatal("skipped keys survived Zeroize under concurrent use")
	}
	if _, err := bob.Decrypt(h1, c1); err == nil {
		t.Fatal("decrypt after Zeroize succeeded")
	}
	close(halt)
	<-done
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
