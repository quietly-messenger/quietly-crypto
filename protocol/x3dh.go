package protocol

import (
	"crypto/sha256"
	"fmt"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// fBytes is the X3DH padding byte string F = 0xFF repeated 32 times (§8.1).
var fBytes = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// X3DHInitiate computes the X3DH shared secret (SK) and associated data (AD)
// for the initiator, given its identity and the responder's bundle (§8.1). It
// verifies the bundle's signatures before deriving, so a tampered or forged
// bundle is rejected rather than producing a session with the attacker (§7.2).
// It also returns the ephemeral key EK_A, whose public half and identity keys
// go into the initial message.
func X3DHInitiate(ik *IdentityKeys, bundle PreKeyBundle) (sk, ad []byte, ek *cryptocore.PreKey, err error) {
	if err := ik.Validate(); err != nil {
		return nil, nil, nil, err
	}
	if err := bundle.Verify(); err != nil {
		return nil, nil, nil, err
	}
	ek, err = cryptocore.GeneratePreKey()
	if err != nil {
		return nil, nil, nil, err
	}
	sk, ad, err = x3dhInitiate(ik, bundle, ek)
	if err != nil {
		return nil, nil, nil, err
	}
	return sk, ad, ek, nil
}

// x3dhInitiate is the deterministic core of X3DHInitiate, taking an explicit
// ephemeral key so it can be exercised against known-answer test vectors. It
// performs no signature verification; callers must verify the bundle first.
func x3dhInitiate(ik *IdentityKeys, bundle PreKeyBundle, ek *cryptocore.PreKey) (sk, ad []byte, err error) {
	dh1, err := cryptocore.X25519(ik.DHPriv, bundle.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(dh1)
	dh2, err := cryptocore.X25519(ek.PrivateKey, bundle.IdentityKeyDH)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(dh2)
	dh3, err := cryptocore.X25519(ek.PrivateKey, bundle.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(dh3)

	// One-time prekey id 0 is the "absent" sentinel (PROTOCOL.md §9.2:
	// otpk_id = 0 means none used). The server MUST assign one-time prekey ids
	// starting at 1 so a legitimate id-0 prekey can never silently drop DH4.
	var dh4 []byte
	if bundle.OneTimePreKeyID != 0 {
		dh4, err = cryptocore.X25519(ek.PrivateKey, bundle.OneTimePreKey)
		if err != nil {
			return nil, nil, err
		}
		defer zeroize(dh4)
	}

	ad = buildAD(ik.DHPub, ik.SigPub, bundle.IdentityKeyDH, bundle.IdentityKeySig)
	sk, err = x3dhShared(dh1, dh2, dh3, dh4, ad)
	if err != nil {
		return nil, nil, err
	}
	return sk, ad, nil
}

// X3DHRespond computes SK and AD for the responder, given its identity, its
// signed and optional one-time prekeys, and the initiator's public keys and
// ephemeral key from the initial message (§8.3).
func X3DHRespond(ik *IdentityKeys, spk, otpk *cryptocore.PreKey, initDHPub, initSigPub, initEK []byte) (sk, ad []byte, err error) {
	if err := ik.Validate(); err != nil {
		return nil, nil, err
	}
	if spk == nil || len(spk.PrivateKey) != cryptocore.X25519PrivateKeySize {
		return nil, nil, fmt.Errorf("responder signed prekey must be %d bytes", cryptocore.X25519PrivateKeySize)
	}
	if len(initDHPub) != cryptocore.X25519PublicKeySize || len(initSigPub) != cryptocore.IdentityPublicKeySize || len(initEK) != cryptocore.X25519PublicKeySize {
		return nil, nil, fmt.Errorf("initial message keys must be %d bytes", cryptocore.X25519PublicKeySize)
	}

	dh1, err := cryptocore.X25519(spk.PrivateKey, initDHPub)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(dh1)
	dh2, err := cryptocore.X25519(ik.DHPriv, initEK)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(dh2)
	dh3, err := cryptocore.X25519(spk.PrivateKey, initEK)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(dh3)

	var dh4 []byte
	if otpk != nil {
		dh4, err = cryptocore.X25519(otpk.PrivateKey, initEK)
		if err != nil {
			return nil, nil, err
		}
		defer zeroize(dh4)
	}

	ad = buildAD(initDHPub, initSigPub, ik.DHPub, ik.SigPub)
	sk, err = x3dhShared(dh1, dh2, dh3, dh4, ad)
	if err != nil {
		return nil, nil, err
	}
	return sk, ad, nil
}

// x3dhShared derives SK from the four DH outputs and associated data:
//
//	SK = HKDF-SHA256(ikm = F || DH1 || DH2 || DH3 [|| DH4],
//	                 salt = 32 zero bytes,
//	                 info = "quietly/1 x3dh" || 0x00 || SHA-256(AD),
//	                 len  = 32)
func x3dhShared(dh1, dh2, dh3, dh4, ad []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(fBytes)+4*32)
	ikm = append(ikm, fBytes...)
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	if len(dh4) != 0 {
		ikm = append(ikm, dh4...)
	}
	defer zeroize(ikm)

	digest := sha256.Sum256(ad)
	info := DomainSeparate(DomainX3DH, digest[:])

	return cryptocore.HKDFSHA256(ikm, make([]byte, 32), info, 32)
}

// buildAD returns IK_A_dh || IK_A_sig || IK_B_dh || IK_B_sig (128 bytes, §8.2).
func buildAD(ikADH, ikASig, ikBDH, ikBSig []byte) []byte {
	ad := make([]byte, 0, 128)
	ad = append(ad, ikADH...)
	ad = append(ad, ikASig...)
	ad = append(ad, ikBDH...)
	ad = append(ad, ikBSig...)
	return ad
}
