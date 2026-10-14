package protocol

// Version is the protocol version constant. It appears in every request and
// every envelope; a mismatch is a hard error, never a silent parse failure
// (PROTOCOL.md §1).
const Version = "quietly/1"

// VersionByte is the leading byte of every ratchet message (§9.2) and sealed
// payload (§10.2).
const VersionByte = 0x01

// Message types (§9.2, §10.2).
const (
	MsgTypeInitial = 0x01
	MsgTypeNormal  = 0x02
)

// Session types (§10.2). Group sessions (0x01) are reserved for v2.
const (
	SessionTypePairwise = 0x00
	SessionTypeGroup    = 0x01
)

// Domain-separation strings (§3.3). ASCII, no trailing NUL.
const (
	DomainIdentityBinding = "quietly/1 identity-binding"
	DomainSignedPrekey    = "quietly/1 signed-prekey"
	DomainX3DH            = "quietly/1 x3dh"
	DomainRatchetRoot     = "quietly/1 ratchet-root"
	DomainRatchetMessage  = "quietly/1 ratchet-msg"
	DomainSealedSender    = "quietly/1 sealed-sender"
	DomainSealedEphemeral = "quietly/1 sealed-ephemeral"
	DomainSafetyNumber    = "quietly/1 safety-number"
	DomainPoW             = "quietly/1 pow"
	DomainRequest         = "quietly/1 request"
)

// Field and wire sizes (§9, §10).
const (
	X25519KeySize = 32
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
	RatchetKeySize   = 32
	RatchetNonceSize = 12 // ChaCha20-Poly1305 (IETF), derived nonce
	SealedKeySize    = 32
	SealedNonceSize  = 24 // XChaCha20-Poly1305, random nonce
	TagSize          = 16 // Poly1305 authentication tag
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
