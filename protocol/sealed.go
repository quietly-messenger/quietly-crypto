package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// UserDevice identifies a recipient device: its user id (raw UUID bytes) and
// device id (u16).
type UserDevice struct {
	UserID   [UUIDSize]byte
	DeviceID uint16
}

// aad returns recipient_user_id || recipient_device_id (u16 BE), the sealed
// sender associated data (§10.1).
func (u UserDevice) aad() []byte {
	b := make([]byte, 0, UUIDSize+DeviceIDSize)
	b = append(b, u.UserID[:]...)
	return binary.BigEndian.AppendUint16(b, u.DeviceID)
}

// SealSealedSender seals a sealed payload (sender identity + ratchet message)
// for a recipient using a hedged ephemeral key (§10.1). The sender's identity
// DH private key and a hash of the payload are mixed into the ephemeral key so
// a repeated random value does not repeat the key.
func SealSealedSender(senderIKDHPriv []byte, recipient UserDevice, recipientIKDH []byte, payload SealedPayload) (SealedBlob, error) {
	if len(senderIKDHPriv) != 32 || len(recipientIKDH) != 32 {
		return SealedBlob{}, fmt.Errorf("sealed sender: keys must be 32 bytes")
	}

	inner := EncodeSealedPayload(payload)

	random32 := make([]byte, 32)
	if err := cryptocore.RandomBytes(random32); err != nil {
		return SealedBlob{}, err
	}
	innerHash := sha256.Sum256(inner)

	ikm := make([]byte, 0, 32+32+32)
	ikm = append(ikm, random32...)
	ikm = append(ikm, senderIKDHPriv...)
	ikm = append(ikm, innerHash[:]...)
	defer zeroize(ikm)

	ePriv, err := cryptocore.HKDFSHA256(ikm, make([]byte, 32), []byte(DomainSealedEphemeral), 32)
	if err != nil {
		return SealedBlob{}, err
	}
	defer zeroize(ePriv)
	zeroize(random32)

	ePub, err := cryptocore.X25519PublicKey(ePriv)
	if err != nil {
		return SealedBlob{}, err
	}

	dh, err := cryptocore.X25519(ePriv, recipientIKDH)
	if err != nil {
		return SealedBlob{}, err
	}
	defer zeroize(dh)

	nonce := make([]byte, SealedNonceSize)
	if err := cryptocore.RandomBytes(nonce); err != nil {
		return SealedBlob{}, err
	}

	salt := make([]byte, 0, 32+32)
	salt = append(salt, ePub...)
	salt = append(salt, recipientIKDH...)

	key, err := cryptocore.HKDFSHA256(dh, salt, []byte(DomainSealedSender), 32)
	if err != nil {
		return SealedBlob{}, err
	}
	defer zeroize(key)

	ct, err := cryptocore.Seal(key, nonce, inner, recipient.aad())
	if err != nil {
		return SealedBlob{}, err
	}

	var blob SealedBlob
	copy(blob.EphemeralPublicKey[:], ePub)
	copy(blob.Nonce[:], nonce)
	blob.Ciphertext = ct
	return blob, nil
}

// OpenSealedSender opens a sealed blob and returns the sender-revealing
// payload (§10.3). A decryption failure returns an error and changes no state.
func OpenSealedSender(recipientIKDHPriv []byte, recipient UserDevice, blob SealedBlob) (SealedPayload, error) {
	if len(recipientIKDHPriv) != 32 {
		return SealedPayload{}, fmt.Errorf("sealed sender: recipient key must be 32 bytes")
	}

	dh, err := cryptocore.X25519(recipientIKDHPriv, blob.EphemeralPublicKey[:])
	if err != nil {
		return SealedPayload{}, err
	}
	defer zeroize(dh)

	ikBDH, err := cryptocore.X25519PublicKey(recipientIKDHPriv)
	if err != nil {
		return SealedPayload{}, err
	}

	salt := make([]byte, 0, 32+32)
	salt = append(salt, blob.EphemeralPublicKey[:]...)
	salt = append(salt, ikBDH...)

	key, err := cryptocore.HKDFSHA256(dh, salt, []byte(DomainSealedSender), 32)
	if err != nil {
		return SealedPayload{}, err
	}
	defer zeroize(key)

	inner, err := cryptocore.Open(key, blob.Nonce[:], blob.Ciphertext, recipient.aad())
	if err != nil {
		return SealedPayload{}, err
	}

	return DecodeSealedPayload(inner)
}
