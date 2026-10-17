// Package protocol is the client-side cryptographic protocol layer of
// Quietly: X3DH session establishment, the Double Ratchet, sealed sender, and
// the frozen binary wire formats and domain-separation constants they use.
//
// The normative specification is `quietly-server/api/v1/PROTOCOL.md`. This
// package encodes the crypto-relevant parts of that spec — the ratchet message
// layouts (§9.2), the sealed-payload layout (§10.2), the domain-separation
// strings (§3.3, re-exported from the shared `quietly` package), and the
// prekey-bundle signatures (§7) — as executable Go code.
//
// This package is client-only: the server stores and routes the ciphertext
// these formats describe, but it never runs the ratchet and never parses these
// inner layers. See ARCHITECTURE.md for the shared-vs-client-only split.
package protocol
