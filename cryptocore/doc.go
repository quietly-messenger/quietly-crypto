// Package cryptocore implements the cryptographic building blocks for the
// Quietly messenger: Ed25519 identity keys, X25519 prekeys and
// Diffie-Hellman, HKDF-SHA256 and Argon2id key derivation, and
// XChaCha20-Poly1305 authenticated encryption.
//
// These primitives are the foundation for X3DH session establishment and the
// Double Ratchet. Every operation is backed by the Go standard library or
// golang.org/x/crypto; no cryptographic primitives are hand-rolled.
//
// The package is designed to be used in two ways:
//
//   - Imported directly by Go code (see the [cryptocore] API below).
//   - Compiled to a C shared library (`.so`/`.dll`/`.dylib`) for FFI consumers
//     such as Dart/Flutter via `dart:ffi`. The C ABI is implemented in the
//     sibling `ffi` package; build it with `make build`.
package cryptocore
