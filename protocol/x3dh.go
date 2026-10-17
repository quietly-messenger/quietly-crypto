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
// also returns the ephemeral key EK_A, whose public half and identity keys go
// into the initial message.
func X3DHInitiate(ik *IdentityKeys, bundle PreKeyBundle) (sk, ad []byte, ek *cryptocore.PreKey, err error) {
	if err := validateIdentity(ik); err != nil {
		return nil, nil, nil, err
	}
	if err := validateBundle(bundle); err != nil {
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
// ephemeral key so it can be exercised against known-answer test vectors.
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

	// ikm = F || DH1 || DH2 || DH3 [|| DH4]
	ikm := make([]byte, 0, len(fBytes)+3*32+32)
	ikm = append(ikm, fBytes...)
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	if bundle.OneTimePreKeyID != 0 {
		dh4, err := cryptocore.X25519(ek.PrivateKey, bundle.OneTimePreKey)
		if err != nil {
			return nil, nil, err
		}
		defer zeroize(dh4)
		ikm = append(ikm, dh4...)
	}

	ad = buildAD(ik.DHPub, ik.SigPub, bundle.IdentityKeyDH, bundle.IdentityKeySig)

	// info = "quietly/1 x3dh" || 0x00 || SHA-256(AD)
	digest := sha256.Sum256(ad)
	info := DomainSeparate(DomainX3DH, digest[:])

	sk, err = cryptocore.HKDFSHA256(ikm, make([]byte, 32), info, 32)
	if err != nil {
		return nil, nil, err
	}
	return sk, ad, nil
}

// X3DHRespond computes SK and AD for the responder, given its identity, its
// signed and optional one-time prekeys, and the initiator's public keys and
// ephemeral key from the initial message (§8.3).
func X3DHRespond(ik *IdentityKeys, spk, otpk *cryptocore.PreKey, initDHPub, initSigPub, initEK []byte) (sk, ad []byte, err error) {
	if err := validateIdentity(ik); err != nil {
		return nil, nil, err
	}
	if spk == nil || len(spk.PrivateKey) != 32 {
		return nil, nil, fmt.Errorf("responder signed prekey must be 32 bytes")
	}
	if len(initDHPub) != 32 || len(initSigPub) != 32 || len(initEK) != 32 {
		return nil, nil, fmt.Errorf("initial message keys must be 32 bytes")
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

	ikm := make([]byte, 0, len(fBytes)+3*32+32)
	ikm = append(ikm, fBytes...)
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	if otpk != nil {
		dh4, err := cryptocore.X25519(otpk.PrivateKey, initEK)
		if err != nil {
			return nil, nil, err
		}
		defer zeroize(dh4)
		ikm = append(ikm, dh4...)
	}

	ad = buildAD(initDHPub, initSigPub, ik.DHPub, ik.SigPub)

	digest := sha256.Sum256(ad)
	info := DomainSeparate(DomainX3DH, digest[:])

	sk, err = cryptocore.HKDFSHA256(ikm, make([]byte, 32), info, 32)
	if err != nil {
		return nil, nil, err
	}
	return sk, ad, nil
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
