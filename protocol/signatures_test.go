package protocol

import (
	"testing"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

func TestIdentityBindingSignVerify(t *testing.T) {
	ik, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignIdentityBinding(ik.SigPriv, ik.DHPub)
	if err != nil {
		t.Fatalf("SignIdentityBinding: %v", err)
	}
	if !VerifyIdentityBinding(ik.SigPub, ik.DHPub, sig) {
		t.Fatal("identity binding failed to verify")
	}
	// Tampered key or signature must not verify.
	sig[0] ^= 0x01
	if VerifyIdentityBinding(ik.SigPub, ik.DHPub, sig) {
		t.Fatal("tampered identity binding verified")
	}
}

func TestSignedPreKeySignVerify(t *testing.T) {
	ik, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	spk, err := cryptocore.GeneratePreKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignSignedPreKey(ik.SigPriv, 42, spk.PublicKey)
	if err != nil {
		t.Fatalf("SignSignedPreKey: %v", err)
	}
	if !VerifySignedPreKey(ik.SigPub, 42, spk.PublicKey, sig) {
		t.Fatal("signed prekey failed to verify")
	}
	// The signature must bind the prekey id and public key.
	if VerifySignedPreKey(ik.SigPub, 43, spk.PublicKey, sig) {
		t.Fatal("signed prekey verified under the wrong id")
	}
	sig[0] ^= 0x01
	if VerifySignedPreKey(ik.SigPub, 42, spk.PublicKey, sig) {
		t.Fatal("tampered signed-prekey signature verified")
	}
}

// TestX3DHInitiateRejectsInvalidSignature is the regression test for C1: the
// initiator must not derive a session from a bundle whose signatures do not
// verify against the recipient's identity signing key.
func TestX3DHInitiateRejectsInvalidSignature(t *testing.T) {
	ikA, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, bundleB, err := GeneratePreKeyBundle(true)
	if err != nil {
		t.Fatal(err)
	}

	// The genuine bundle is accepted.
	if _, _, _, err := X3DHInitiate(ikA, bundleB); err != nil {
		t.Fatalf("genuine bundle rejected: %v", err)
	}

	// Tampered signed-prekey signature.
	badSPK := bundleB
	badSPK.SignedPreKeySignature = append([]byte(nil), bundleB.SignedPreKeySignature...)
	badSPK.SignedPreKeySignature[0] ^= 0x01
	if _, _, _, err := X3DHInitiate(ikA, badSPK); err == nil {
		t.Fatal("tampered signed-prekey signature accepted")
	}

	// Tampered identity-binding signature.
	badBinding := bundleB
	badBinding.IdentityBinding = append([]byte(nil), bundleB.IdentityBinding...)
	badBinding.IdentityBinding[0] ^= 0x01
	if _, _, _, err := X3DHInitiate(ikA, badBinding); err == nil {
		t.Fatal("tampered identity-binding signature accepted")
	}
}
