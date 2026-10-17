// Package quietly holds protocol-wide constants shared by every Quietly
// component — the client crypto core, the home server, and the Flutter client.
// These are the values that must never drift between implementations.
package quietly

// Version is the protocol version constant. It appears in every request and
// every envelope; a mismatch is a hard error, never a silent parse failure
// (PROTOCOL.md §1).
const Version = "quietly/1"

// VersionByte is the leading byte of every ratchet message (§9.2) and sealed
// payload (§10.2).
const VersionByte = 0x01

// DomainSeparate returns domain || 0x00 || payload, the canonical domain
// separation applied to every signature and KDF input (§3.3).
func DomainSeparate(domain string, payload []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(payload))
	out = append(out, domain...)
	out = append(out, 0x00)
	out = append(out, payload...)
	return out
}

// Domain-separation strings (PROTOCOL.md §3.3). ASCII, no trailing NUL.
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
