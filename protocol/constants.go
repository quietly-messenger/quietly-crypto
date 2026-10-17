package protocol

import (
	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/quietly"
)

// Version and domain-separation strings are re-exported from the shared
// `quietly` package so there is a single source of truth for every protocol
// constant (see ARCHITECTURE.md). The server imports `quietly` directly.
const (
	Version     = quietly.Version
	VersionByte = quietly.VersionByte
)

// Message types (§9.2, §10.2). Client-only: the server never parses these.
const (
	MsgTypeInitial = 0x01
	MsgTypeNormal  = 0x02
)

// Session types (§10.2). Group sessions (0x01) are reserved for v2.
const (
	SessionTypePairwise = 0x00
	SessionTypeGroup    = 0x01
)

// Domain-separation strings (§3.3), re-exported from `quietly`.
const (
	DomainIdentityBinding = quietly.DomainIdentityBinding
	DomainSignedPrekey    = quietly.DomainSignedPrekey
	DomainX3DH            = quietly.DomainX3DH
	DomainRatchetRoot     = quietly.DomainRatchetRoot
	DomainRatchetMessage  = quietly.DomainRatchetMessage
	DomainSealedSender    = quietly.DomainSealedSender
	DomainSealedEphemeral = quietly.DomainSealedEphemeral
	DomainSafetyNumber    = quietly.DomainSafetyNumber
	DomainPoW             = quietly.DomainPoW
	DomainRequest         = quietly.DomainRequest
)

// Field and wire sizes. Key/nonce/tag sizes are aliases of the cryptocore
// primitives' sizes so they cannot drift; the wire-layout sizes are defined
// here (§9, §10).
const (
	X25519KeySize = cryptocore.X25519PublicKeySize
	UUIDSize      = 16
	DeviceIDSize  = 2
	GroupIDSize   = 16

	// HeaderSize is the 40-byte ratchet header: ratchet_public_key(32) ||
	// pn(4) || n(4).
	HeaderSize = 40

	// NormalMessageHeaderSize is version(1) || type(1) || header(40).
	NormalMessageHeaderSize = 42

	// InitialMessageHeaderSize is version(1) || type(1) || IK_A_dh(32) ||
	// IK_A_sig(32) || EK_A(32) || spk_id(4) || otpk_id(4) || header(40).
	InitialMessageHeaderSize = 146

	// SealedPayloadPrefixSize is the fixed 41-byte prefix of a sealed payload:
	// version(1) || sender_user_id(16) || sender_device_id(2) ||
	// session_type(1) || group_id(16) || msg_type(1) || inner_len(4).
	SealedPayloadPrefixSize = 41

	// SealedBlobPrefixSize is the fixed 57-byte prefix of a sealed blob:
	// version(1) || E_pub(32) || nonce(24).
	SealedBlobPrefixSize = 57

	// AEAD parameters (§3, §9.1, §10.1).
	RatchetNonceSize = cryptocore.ChaChaNonceSize // ChaCha20-Poly1305 (IETF)
	SealedNonceSize  = cryptocore.AEADNonceSize   // XChaCha20-Poly1305
	TagSize          = cryptocore.AEADTagSize     // Poly1305 tag
)

// DomainSeparate returns domain || 0x00 || payload, the canonical domain
// separation applied to every signature and KDF input (§3.3).
func DomainSeparate(domain string, payload []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(payload))
	out = append(out, domain...)
	out = append(out, 0x00)
	out = append(out, payload...)
	return out
}
