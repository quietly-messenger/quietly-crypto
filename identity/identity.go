// Package identity holds the shared identity-key and prekey-bundle types and
// their signatures. Both the client (which owns the private keys and signs
// them) and the home server (which verifies them at registration) depend on
// this package, so key formats and signatures cannot drift between them.
//
// The server never holds the private halves; it fills only the public fields
// it receives and calls PreKeyBundle.Verify.
package identity

import (
	"fmt"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// IdentityKeys is a device's long-term identity: an X25519 DH keypair and an
// Ed25519 signing keypair, bound at registration by the identity-binding
// signature (PROTOCOL.md §2). Two keys rather than one Curve25519 key keeps a
// hand-written key-conversion primitive out of the core.
type IdentityKeys struct {
	DHPub   []byte // identity_key_dh public (32 bytes)
	DHPriv  []byte // identity_key_dh private (32 bytes)
	SigPub  []byte // identity_key_sig public (32 bytes)
	SigPriv []byte // identity_key_sig private (64 bytes)
}

// PreKeyBundle is what a sender fetches for a recipient device
// (PROTOCOL.md §7.2): the recipient's identity keys, their signatures, the
// signed prekey, and one optional one-time prekey.
type PreKeyBundle struct {
	IdentityKeyDH         []byte // IK_B_dh (32 bytes)
	IdentityKeySig        []byte // IK_B_sig (32 bytes)
	IdentityBinding       []byte // Ed25519 sig over identity_key_dh (64 bytes)
	SignedPreKeyID        uint32
	SignedPreKey          []byte // SPK_B (32 bytes)
	SignedPreKeySignature []byte // Ed25519 sig over id_be32 || SPK_B (64 bytes)
	OneTimePreKeyID       uint32 // 0 means no one-time prekey was used
	OneTimePreKey         []byte // OPK_B (32 bytes), empty when unused
}

// GenerateIdentityKeys generates a fresh identity (X25519 + Ed25519 keypairs).
func GenerateIdentityKeys() (*IdentityKeys, error) {
	dh, err := cryptocore.GeneratePreKey()
	if err != nil {
		return nil, fmt.Errorf("generating identity DH key: %w", err)
	}
	sig, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating identity signature key: %w", err)
	}
	return &IdentityKeys{
		DHPub:   dh.PublicKey,
		DHPriv:  dh.PrivateKey,
		SigPub:  sig.PublicKey,
		SigPriv: sig.PrivateKey,
	}, nil
}

// GeneratePreKeyBundle generates a responder's bundle: a fresh identity, a
// signed prekey, and an optional one-time prekey, all correctly signed. It is
// a test convenience and a reference for device registration.
func GeneratePreKeyBundle(withOneTimePreKey bool) (*IdentityKeys, *cryptocore.PreKey, *cryptocore.PreKey, PreKeyBundle, error) {
	ik, err := GenerateIdentityKeys()
	if err != nil {
		return nil, nil, nil, PreKeyBundle{}, err
	}
	spk, err := cryptocore.GeneratePreKey()
	if err != nil {
		return nil, nil, nil, PreKeyBundle{}, err
	}
	var otpk *cryptocore.PreKey
	if withOneTimePreKey {
		otpk, err = cryptocore.GeneratePreKey()
		if err != nil {
			return nil, nil, nil, PreKeyBundle{}, err
		}
	}

	identityBinding, err := SignIdentityBinding(ik.SigPriv, ik.DHPub)
	if err != nil {
		return nil, nil, nil, PreKeyBundle{}, err
	}
	signedPreKeySig, err := SignSignedPreKey(ik.SigPriv, 1, spk.PublicKey)
	if err != nil {
		return nil, nil, nil, PreKeyBundle{}, err
	}

	bundle := PreKeyBundle{
		IdentityKeyDH:         ik.DHPub,
		IdentityKeySig:        ik.SigPub,
		IdentityBinding:       identityBinding,
		SignedPreKeyID:        1,
		SignedPreKey:          spk.PublicKey,
		SignedPreKeySignature: signedPreKeySig,
	}
	if otpk != nil {
		bundle.OneTimePreKeyID = 42
		bundle.OneTimePreKey = otpk.PublicKey
	}
	return ik, spk, otpk, bundle, nil
}

// Validate checks that an identity's key material has the required lengths.
func (ik *IdentityKeys) Validate() error {
	if ik == nil {
		return fmt.Errorf("identity keys are nil")
	}
	if len(ik.DHPub) != cryptocore.X25519PublicKeySize || len(ik.DHPriv) != cryptocore.X25519PrivateKeySize {
		return fmt.Errorf("identity DH keys must be %d bytes", cryptocore.X25519PublicKeySize)
	}
	if len(ik.SigPub) != cryptocore.IdentityPublicKeySize || len(ik.SigPriv) != cryptocore.IdentityPrivateKeySize {
		return fmt.Errorf("identity signature keys must be %d (public) and %d (private) bytes",
			cryptocore.IdentityPublicKeySize, cryptocore.IdentityPrivateKeySize)
	}
	return nil
}

func validateBundle(b PreKeyBundle) error {
	if len(b.IdentityKeyDH) != cryptocore.X25519PublicKeySize || len(b.IdentityKeySig) != cryptocore.IdentityPublicKeySize {
		return fmt.Errorf("bundle identity keys must be %d bytes", cryptocore.X25519PublicKeySize)
	}
	if len(b.IdentityBinding) != cryptocore.SignatureSize {
		return fmt.Errorf("bundle identity binding must be %d bytes", cryptocore.SignatureSize)
	}
	if len(b.SignedPreKey) != cryptocore.X25519PublicKeySize {
		return fmt.Errorf("bundle signed prekey must be %d bytes", cryptocore.X25519PublicKeySize)
	}
	if len(b.SignedPreKeySignature) != cryptocore.SignatureSize {
		return fmt.Errorf("bundle signed-prekey signature must be %d bytes", cryptocore.SignatureSize)
	}
	if b.OneTimePreKeyID != 0 && len(b.OneTimePreKey) != cryptocore.X25519PublicKeySize {
		return fmt.Errorf("bundle one-time prekey must be %d bytes when present", cryptocore.X25519PublicKeySize)
	}
	return nil
}
