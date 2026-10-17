# Architecture

`quietly-crypto` is the **single source of truth for Quietly's cryptographic
algorithms and byte layouts**. Both the home server (a Go program) and the
client (Flutter via `dart:ffi`) consume the *same* code, so an algorithm, a
constant, or a wire format is changed in exactly one place.

The normative protocol specification lives in `quietly-server/api/v1/PROTOCOL.md`.
This repository encodes the crypto-relevant parts of that spec — the binary
wire layouts and the domain-separation constants — as executable Go code, so
that client and server cannot drift apart.

## Consumers

| Consumer | Language | How it uses this module |
|---|---|---|
| Home server | Go | imports packages directly as a normal Go module |
| Client | Dart/Flutter | loads the `ffi` package compiled to a shared library (`.so`/`.dll`) |

The server imports only the **shared** packages. The client, through the FFI
binding, additionally reaches the **client-only** protocol layer.

## Package layout

| Package | Scope | Contains |
|---|---|---|
| `cryptocore` | **shared** | Primitives: Ed25519, X25519, HKDF-SHA256, HMAC-SHA256, Argon2id, ChaCha20-Poly1305, XChaCha20-Poly1305, CSPRNG |
| `protocol` | **client** | X3DH, Double Ratchet, sealed sender, and the frozen wire formats and constants (§7–§10) |
| `pow` | **shared** | Proof-of-work solver + verifier (§4) |
| `safety` | **shared** | Safety-number fingerprint derivation (§9.5) |
| `ffi` | **client** | C ABI exports for `dart:ffi` |

The rule: anything the server and client must agree on lives in a shared
package; anything that touches client session keys or the ratchet lives in a
client-only package. Because Go compiles only imported packages, the server
importing `cryptocore` (or `pow`) never links in the client-only `protocol`
code.

## Security boundary

**Shared code ≠ shared secrets.** The server imports the shared primitives but
never runs the ratchet, never holds client private keys, and never sees
plaintext. All secret key material lives on the device; the `ffi` layer is the
only bridge to the client, and it copies every input into Go-owned memory
before use (Go's crypto caches may register weak pointers, which is only valid
for Go heap allocations).

## Versioning

This is a versioned Go module. `quietly-server` pins it as a dependency, and
the Flutter client builds it from the same pinned version. This — not copying
the code into each repo — is what keeps "change in one place" true across the
two codebases.
