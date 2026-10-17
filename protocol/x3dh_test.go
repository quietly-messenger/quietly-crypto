package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// Independent known-answer vector: fixed keys derived with a reference
// implementation (Python `cryptography`). Any change to the X3DH KDF wiring
// (DH order, F padding, AD layout, domain string, salt) breaks this test.
func TestX3DHKnownAnswer(t *testing.T) {
	ik := &IdentityKeys{
		DHPub:   mustHex(t, "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"),
		DHPriv:  bytes.Repeat([]byte{0x01}, 32),
		SigPub:  bytes.Repeat([]byte{0x02}, 32),
		SigPriv: bytes.Repeat([]byte{0x00}, 64),
	}
	bundle := PreKeyBundle{
		IdentityKeyDH:   mustHex(t, "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"),
		IdentityKeySig:  bytes.Repeat([]byte{0x04}, 32),
		SignedPreKeyID:  1,
		SignedPreKey:    mustHex(t, "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d"),
		OneTimePreKeyID: 42,
		OneTimePreKey:   mustHex(t, "f5b2d6e60f9477e310c2982daaa6c9136c108a1777c5947e448fa37d68174557"),
	}
	ek := &cryptocore.PreKey{PrivateKey: bytes.Repeat([]byte{0x07}, 32)}

	sk, ad, err := x3dhInitiate(ik, bundle, ek)
	if err != nil {
		t.Fatalf("x3dhInitiate: %v", err)
	}

	wantSK := mustHex(t, "e1de2b7bf8bc4d7236eb7997bf7bdfd9ae72a5b58e11399fc0a7c88830c0bf8a")
	if !bytes.Equal(sk, wantSK) {
		t.Fatalf("X3DH SK mismatch\n got %x\nwant %x", sk, wantSK)
	}

	// AD must be IK_A_dh || IK_A_sig || IK_B_dh || IK_B_sig (§8.2).
	wantAD := append([]byte(nil), ik.DHPub...)
	wantAD = append(wantAD, ik.SigPub...)
	wantAD = append(wantAD, bundle.IdentityKeyDH...)
	wantAD = append(wantAD, bundle.IdentityKeySig...)
	if len(ad) != 128 || !bytes.Equal(ad, wantAD) {
		t.Fatalf("AD mismatch\n got %x\nwant %x", ad, wantAD)
	}
}

func TestX3DHRespondMatchesKnownAnswer(t *testing.T) {
	ikB := &IdentityKeys{
		DHPub:   mustHex(t, "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"),
		DHPriv:  bytes.Repeat([]byte{0x03}, 32),
		SigPub:  bytes.Repeat([]byte{0x04}, 32),
		SigPriv: bytes.Repeat([]byte{0x00}, 64),
	}
	spkB := &cryptocore.PreKey{
		PublicKey:  mustHex(t, "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d"),
		PrivateKey: bytes.Repeat([]byte{0x05}, 32),
	}
	otpkB := &cryptocore.PreKey{
		PublicKey:  mustHex(t, "f5b2d6e60f9477e310c2982daaa6c9136c108a1777c5947e448fa37d68174557"),
		PrivateKey: bytes.Repeat([]byte{0x06}, 32),
	}

	sk, _, err := X3DHRespond(
		ikB, spkB, otpkB,
		mustHex(t, "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"), // IK_A_dh
		bytes.Repeat([]byte{0x02}, 32), // IK_A_sig
		mustHex(t, "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d"), // EK_A
	)
	if err != nil {
		t.Fatalf("X3DHRespond: %v", err)
	}
	wantSK := mustHex(t, "e1de2b7bf8bc4d7236eb7997bf7bdfd9ae72a5b58e11399fc0a7c88830c0bf8a")
	if !bytes.Equal(sk, wantSK) {
		t.Fatalf("responder SK mismatch\n got %x\nwant %x", sk, wantSK)
	}
}

func TestX3DHInitiatorResponderAgree(t *testing.T) {
	for _, withOTPK := range []bool{true, false} {
		ikA, err := GenerateIdentityKeys()
		if err != nil {
			t.Fatal(err)
		}
		ikB, spkB, otpkB, bundleB, err := GeneratePreKeyBundle(withOTPK)
		if err != nil {
			t.Fatal(err)
		}

		skA, adA, ekA, err := X3DHInitiate(ikA, bundleB)
		if err != nil {
			t.Fatalf("X3DHInitiate: %v", err)
		}
		skB, adB, err := X3DHRespond(ikB, spkB, otpkB, ikA.DHPub, ikA.SigPub, ekA.PublicKey)
		if err != nil {
			t.Fatalf("X3DHRespond: %v", err)
		}

		if !bytes.Equal(skA, skB) {
			t.Fatalf("withOTPK=%v: SK mismatch between initiator and responder", withOTPK)
		}
		if !bytes.Equal(adA, adB) {
			t.Fatalf("withOTPK=%v: AD mismatch", withOTPK)
		}
	}
}

func TestX3DHBundleTamperingChangesSK(t *testing.T) {
	ikA, _ := GenerateIdentityKeys()
	_, _, _, bundleB, _ := GeneratePreKeyBundle(true)

	sk0, _, _, err := X3DHInitiate(ikA, bundleB)
	if err != nil {
		t.Fatal(err)
	}

	tamper := func(mut func(*PreKeyBundle)) bool {
		b := bundleB
		mut(&b)
		sk, _, _, err := X3DHInitiate(ikA, b)
		if err != nil {
			return false // a structurally invalid bundle is also a failure
		}
		return !bytes.Equal(sk, sk0)
	}

	if !tamper(func(b *PreKeyBundle) { b.IdentityKeyDH[0] ^= 0x01 }) {
		t.Fatal("tampering with the recipient identity DH key did not change SK")
	}
	if !tamper(func(b *PreKeyBundle) { b.SignedPreKey[0] ^= 0x01 }) {
		t.Fatal("tampering with the signed prekey did not change SK")
	}
	if !tamper(func(b *PreKeyBundle) { b.OneTimePreKey[0] ^= 0x01 }) {
		t.Fatal("tampering with the one-time prekey did not change SK")
	}
}
