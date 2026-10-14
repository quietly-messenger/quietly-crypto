// Package protocol is the client-side cryptographic protocol layer of
// Quietly: the frozen binary wire formats and domain-separation constants for
// X3DH session establishment, the Double Ratchet, and sealed sender.
//
// The normative specification is `quietly-server/api/v1/PROTOCOL.md`. This
// package encodes the crypto-relevant parts of that spec — the ratchet message
// layouts (§9.2), the sealed-payload layout (§10.2), and the domain-separation
// strings (§3.3) — as executable Go code, so that client and server agree on
// every byte and constant without relying on a shared markdown file.
//
// Today this package provides the wire-format encoding/decoding and the
// constants only. The X3DH handshake and the Double Ratchet state machine are
// the next implementation step and will live here alongside the formats they
// produce.
//
// This package is client-only: the server stores and routes the ciphertext
// these formats describe, but it never runs the ratchet and never parses these
// inner layers. See ARCHITECTURE.md for the shared-vs-client-only split.
package protocol
