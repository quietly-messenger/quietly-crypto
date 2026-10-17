package protocol

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
// (PROTOCOL.md §7.2): the recipient's identity keys, signed prekey, and one
// optional one-time prekey.
type PreKeyBundle struct {
	IdentityKeyDH   []byte // IK_B_dh (32 bytes)
	IdentityKeySig  []byte // IK_B_sig (32 bytes)
	SignedPreKeyID  uint32
	SignedPreKey    []byte // SPK_B (32 bytes)
	OneTimePreKeyID uint32 // 0 means no one-time prekey was used
	OneTimePreKey   []byte // OPK_B (32 bytes), empty when unused
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
// signed prekey, and an optional one-time prekey. It is a test convenience and
// also a reference for device registration.
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

	bundle := PreKeyBundle{
		IdentityKeyDH:  ik.DHPub,
		IdentityKeySig: ik.SigPub,
		SignedPreKeyID: 1,
		SignedPreKey:   spk.PublicKey,
	}
	if otpk != nil {
		bundle.OneTimePreKeyID = 42
		bundle.OneTimePreKey = otpk.PublicKey
	}
	return ik, spk, otpk, bundle, nil
}

func validateIdentity(ik *IdentityKeys) error {
	if ik == nil {
		return fmt.Errorf("identity keys are nil")
	}
	if len(ik.DHPub) != 32 || len(ik.DHPriv) != 32 {
		return fmt.Errorf("identity DH keys must be 32 bytes")
	}
	if len(ik.SigPub) != 32 || len(ik.SigPriv) != 64 {
		return fmt.Errorf("identity signature keys must be 32 (public) and 64 (private) bytes")
	}
	return nil
}

func validateBundle(b PreKeyBundle) error {
	if len(b.IdentityKeyDH) != 32 || len(b.IdentityKeySig) != 32 {
		return fmt.Errorf("bundle identity keys must be 32 bytes")
	}
	if len(b.SignedPreKey) != 32 {
		return fmt.Errorf("bundle signed prekey must be 32 bytes")
	}
	if b.OneTimePreKeyID != 0 && len(b.OneTimePreKey) != 32 {
		return fmt.Errorf("bundle one-time prekey must be 32 bytes when present")
	}
	return nil
}
