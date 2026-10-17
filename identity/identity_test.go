package identity

import "testing"

// These tests exercise the server-facing surface directly: the server verifies
// registration bundles via PreKeyBundle.Verify without holding private keys.
func TestIdentityKeysValidate(t *testing.T) {
	ik, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := ik.Validate(); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}

	bad := *ik
	bad.DHPriv = bad.DHPriv[:16]
	if err := bad.Validate(); err == nil {
		t.Fatal("short DH private key accepted")
	}
}

func TestPreKeyBundleVerify(t *testing.T) {
	_, _, _, bundle, err := GeneratePreKeyBundle(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Verify(); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}

	// Tampering with the signed-prekey signature must be rejected.
	tampered := bundle
	tampered.SignedPreKeySignature = append([]byte(nil), bundle.SignedPreKeySignature...)
	tampered.SignedPreKeySignature[0] ^= 0x01
	if err := tampered.Verify(); err == nil {
		t.Fatal("tampered signed-prekey signature accepted")
	}

	// Tampering with the identity binding must be rejected.
	tampered = bundle
	tampered.IdentityBinding = append([]byte(nil), bundle.IdentityBinding...)
	tampered.IdentityBinding[0] ^= 0x01
	if err := tampered.Verify(); err == nil {
		t.Fatal("tampered identity binding accepted")
	}
}
