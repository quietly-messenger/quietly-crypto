package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// SignIdentityBinding signs identity_key_dh with identity_key_sig, producing
// the identity-binding signature (PROTOCOL.md §2, §7.1).
func SignIdentityBinding(sigPriv, dhPub []byte) ([]byte, error) {
	return cryptocore.SignIdentity(sigPriv, DomainSeparate(DomainIdentityBinding, dhPub))
}

// VerifyIdentityBinding reports whether sig is a valid identity-binding
// signature over identity_key_dh by identity_key_sig.
func VerifyIdentityBinding(sigPub, dhPub, sig []byte) bool {
	return cryptocore.VerifyIdentitySignature(sigPub, DomainSeparate(DomainIdentityBinding, dhPub), sig)
}

// SignSignedPreKey signs id_be32 || public_key with identity_key_sig, producing
// the signed-prekey signature (PROTOCOL.md §7.1).
func SignSignedPreKey(sigPriv []byte, id uint32, spkPub []byte) ([]byte, error) {
	return cryptocore.SignIdentity(sigPriv, signedPreKeyPayload(id, spkPub))
}

// VerifySignedPreKey reports whether sig is a valid signed-prekey signature
// over id_be32 || public_key by identity_key_sig.
func VerifySignedPreKey(sigPub []byte, id uint32, spkPub, sig []byte) bool {
	return cryptocore.VerifyIdentitySignature(sigPub, signedPreKeyPayload(id, spkPub), sig)
}

// signedPreKeyPayload returns DomainSeparate("signed-prekey", id_be32 || pub).
func signedPreKeyPayload(id uint32, spkPub []byte) []byte {
	idBE := make([]byte, 4)
	binary.BigEndian.PutUint32(idBE, id)
	return DomainSeparate(DomainSignedPrekey, append(idBE, spkPub...))
}

// VerifyBundle checks a prekey bundle's identity-binding and signed-prekey
// signatures against its identity signing key (§7.2). A bundle whose
// signatures do not verify must be rejected before any X3DH derivation.
func (b PreKeyBundle) Verify() error {
	if err := validateBundle(b); err != nil {
		return err
	}
	if !VerifyIdentityBinding(b.IdentityKeySig, b.IdentityKeyDH, b.IdentityBinding) {
		return fmt.Errorf("prekey bundle: identity-binding signature invalid")
	}
	if !VerifySignedPreKey(b.IdentityKeySig, b.SignedPreKeyID, b.SignedPreKey, b.SignedPreKeySignature) {
		return fmt.Errorf("prekey bundle: signed-prekey signature invalid")
	}
	return nil
}
