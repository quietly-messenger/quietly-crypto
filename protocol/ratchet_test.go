package protocol

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// TestRatchetKDFKnownAnswer locks the Double Ratchet KDF chain (§9.1) against
// an independent reference vector. It also cross-checks Go's X25519 against the
// reference implementation.
func TestRatchetKDFKnownAnswer(t *testing.T) {
	spkBPub := mustHex(t, "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d")

	// Cross-check X25519(R_A_priv=0x08, SPK_B) against the reference value.
	dh, err := cryptocore.X25519(bytes.Repeat([]byte{0x08}, 32), spkBPub)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	if !bytes.Equal(dh, mustHex(t, "bb36f6b54576ac7aa70391f569e972e4ca3b847a124ca80ba1bd47dfc7c3ea4d")) {
		t.Fatalf("X25519 mismatch\n got %x", dh)
	}

	sk := mustHex(t, "e1de2b7bf8bc4d7236eb7997bf7bdfd9ae72a5b58e11399fc0a7c88830c0bf8a")
	rk, ck, err := kdfRoot(sk, dh)
	if err != nil {
		t.Fatalf("kdfRoot: %v", err)
	}
	if !bytes.Equal(rk, mustHex(t, "eda35490077a07985cffde51c49da98fe59eb3cc4d7adc4a38cfe9e163587157")) {
		t.Fatalf("kdfRoot rk mismatch\n got %x", rk)
	}
	if !bytes.Equal(ck, mustHex(t, "255a620409fde9664dc5fe496a2df5553c1a3339451e553650deefbe7139160b")) {
		t.Fatalf("kdfRoot ck mismatch\n got %x", ck)
	}

	mk, ckNext := kdfChain(ck)
	if !bytes.Equal(mk, mustHex(t, "32e2d2d08510daab2c79d74d954c8cc2588bf735fe012ab10c35d8176061c07b")) {
		t.Fatalf("kdfChain mk mismatch\n got %x", mk)
	}
	if !bytes.Equal(ckNext, mustHex(t, "e3ad8cd0ad2d64691bf443745d23f43d0b115e5c404839623fe88ca0f79103fb")) {
		t.Fatalf("kdfChain ck_next mismatch\n got %x", ckNext)
	}

	key, nonce, err := messageKey(mk)
	if err != nil {
		t.Fatalf("messageKey: %v", err)
	}
	if !bytes.Equal(key, mustHex(t, "626bc4e2226314db0cb982ed0d4dda5fc89d178a35e40e39004e442d8cc30f61")) {
		t.Fatalf("messageKey key mismatch\n got %x", key)
	}
	if !bytes.Equal(nonce, mustHex(t, "1abc4efc1a7dd84a0b8c5054")) {
		t.Fatalf("messageKey nonce mismatch\n got %x", nonce)
	}
}

// establish sets up an initiator (alice) and responder (bob) session from
// freshly generated keys, asserting the X3DH results agree.
func establish(t *testing.T) (alice, bob *Session) {
	t.Helper()
	ikA, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	ikB, spkB, otpkB, bundleB, err := GeneratePreKeyBundle(true)
	if err != nil {
		t.Fatal(err)
	}

	skA, adA, ekA, err := X3DHInitiate(ikA, bundleB)
	if err != nil {
		t.Fatal(err)
	}
	skB, adB, err := X3DHRespond(ikB, spkB, otpkB, ikA.DHPub, ikA.SigPub, ekA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skA, skB) || !bytes.Equal(adA, adB) {
		t.Fatal("initiator and responder disagree on SK/AD")
	}

	alice, err = NewInitiatorSession(skA, adA, bundleB.SignedPreKey)
	if err != nil {
		t.Fatal(err)
	}
	bob, err = NewResponderSession(skB, adB, spkB)
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func TestBidirectionalConversation(t *testing.T) {
	alice, bob := establish(t)

	send := func(from, to *Session, label string) {
		t.Helper()
		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf("%s-%d", label, i)
			h, c, err := from.Encrypt([]byte(msg))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			pt, err := to.Decrypt(h, c)
			if err != nil {
				t.Fatalf("Decrypt(%s): %v", msg, err)
			}
			if string(pt) != msg {
				t.Fatalf("got %q, want %q", pt, msg)
			}
		}
	}

	// Multiple rounds in both directions, interleaved.
	for round := 0; round < 3; round++ {
		send(alice, bob, fmt.Sprintf("a%d", round))
		send(bob, alice, fmt.Sprintf("b%d", round))
	}
}

func TestOutOfOrderDelivery(t *testing.T) {
	alice, bob := establish(t)

	type msg struct {
		h Header
		c []byte
		p string
	}
	var msgs []msg
	for i := 0; i < 6; i++ {
		h, c, err := alice.Encrypt([]byte(fmt.Sprintf("m%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, msg{h: h, c: c, p: fmt.Sprintf("m%d", i)})
	}

	// Deliver in reverse order; skipped message keys must fill the gaps.
	for i := len(msgs) - 1; i >= 0; i-- {
		pt, err := bob.Decrypt(msgs[i].h, msgs[i].c)
		if err != nil {
			t.Fatalf("decrypt out-of-order m%d: %v", i, err)
		}
		if string(pt) != msgs[i].p {
			t.Fatalf("got %q, want %q", pt, msgs[i].p)
		}
	}
}

func TestTamperedMessageDoesNotAdvanceState(t *testing.T) {
	alice, bob := establish(t)

	h1, c1, _ := alice.Encrypt([]byte("m1"))
	h2, c2, _ := alice.Encrypt([]byte("m2"))

	bad := append([]byte(nil), c1...)
	bad[0] ^= 0x01
	if _, err := bob.Decrypt(h1, bad); err == nil {
		t.Fatal("tampered message unexpectedly decrypted")
	}

	// §9.3: the failed message must not desynchronize the session.
	pt, err := bob.Decrypt(h2, c2)
	if err != nil {
		t.Fatalf("next message failed after a tampered one: %v", err)
	}
	if string(pt) != "m2" {
		t.Fatalf("got %q, want %q", pt, "m2")
	}
}

func TestPostCompromiseSecurity(t *testing.T) {
	alice, bob := establish(t)

	// Alice sends m1; Bob receives it (which performs Bob's DH ratchet).
	h1, c1, _ := alice.Encrypt([]byte("m1"))
	if _, err := bob.Decrypt(h1, c1); err != nil {
		t.Fatal(err)
	}

	// Attacker captures Alice's full state right after she sent m1.
	attacker := alice.clone()

	// Bob replies (new ratchet key); Alice receives and ratchets forward.
	hr1, cr1, _ := bob.Encrypt([]byte("r1"))
	if _, err := alice.Decrypt(hr1, cr1); err != nil {
		t.Fatal(err)
	}

	// Alice sends m2 under her fresh ratchet key.
	h2, c2, _ := alice.Encrypt([]byte("m2"))

	// The attacker knows Alice's old ratchet private key and chain keys, but
	// not the fresh DH secret mixed in during the post-compromise ratchet.
	if _, err := attacker.Decrypt(h2, c2); err == nil {
		t.Fatal("post-compromise security violated: attacker decrypted m2")
	}
}

func TestForwardSecrecy(t *testing.T) {
	alice, bob := establish(t)

	h1, c1, _ := alice.Encrypt([]byte("m1"))
	if _, err := bob.Decrypt(h1, c1); err != nil {
		t.Fatal(err)
	}

	// Bob's receiving chain key has advanced past m1. The message key his
	// current chain key produces for the *next* message must not decrypt m1,
	// whose key was derived from an earlier chain key and discarded.
	mk, _ := kdfChain(bob.ckr)
	key, nonce, err := messageKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cryptocore.OpenChaCha(key, nonce, c1, bob.aadFor(h1)); err == nil {
		t.Fatal("forward secrecy broken: current chain key decrypted a past message")
	}
}

func TestSkipLimitExceeded(t *testing.T) {
	alice, bob := establish(t)

	h0, c0, _ := alice.Encrypt([]byte("m0"))
	if _, err := bob.Decrypt(h0, c0); err != nil {
		t.Fatal(err)
	}

	// Forge a header on the same chain claiming a message number far beyond
	// the skip limit (§9.4).
	var pub [X25519KeySize]byte
	copy(pub[:], h0.RatchetPublicKey[:])
	forged := Header{RatchetPublicKey: pub, PN: 0, N: maxSkipPerChain + 2}
	if _, err := bob.Decrypt(forged, []byte("xx")); err == nil {
		t.Fatal("expected skip-limit error")
	}

	// The session must remain usable.
	h1, c1, _ := alice.Encrypt([]byte("m1"))
	pt, err := bob.Decrypt(h1, c1)
	if err != nil || string(pt) != "m1" {
		t.Fatalf("session unusable after skip-limit error: pt=%q err=%v", pt, err)
	}
}
