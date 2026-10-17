// Command ffi builds quietly-crypto as a C shared library (`.so`, `.dll`, or
// `.dylib`) that can be loaded from any language with a C foreign-function
// interface, including Dart/Flutter via `dart:ffi`.
//
// It is not meant to be run directly. Build it with:
//
//	go build -buildmode=c-shared -o libquietly_crypto.so ./ffi
//
// or, for a fully optimized release build, use the repository Makefile
// (`make build`). `-buildmode=c-shared` also emits a C header
// (`libquietly_crypto.h`) next to the shared library.
//
// # Conventions
//
//   - All byte buffers are caller-owned; functions write into caller-provided
//     buffers and never transfer memory ownership.
//   - Every input buffer is copied into Go-owned memory before use. This is
//     required for correctness: Go's crypto packages may register weak
//     pointers to key material, which is only valid for Go heap allocations —
//     never for memory owned by the C caller (stack or malloc'd).
//   - Fixed-size buffers have their required length embedded in the parameter
//     name (e.g. `pub32` is 32 bytes, `priv64` is 64 bytes).
//   - Functions return 0 on success and -1 on any error. Identity verification
//     additionally returns 1 for a valid signature and 0 for an invalid one.
//   - `quietly_version` returns a static, NUL-terminated string that is valid
//     for the lifetime of the process and must not be freed.
package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"unsafe"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

var versionCStr = C.CString(cryptocore.LibraryVersion)

// main is required by the c-shared toolchain to satisfy the linker, but it is
// never invoked when the package is loaded as a shared library.
func main() {}

// quietly_version returns the library version as a NUL-terminated string. The
// returned pointer is valid for the lifetime of the process and must not be
// freed.
//
//export quietly_version
func quietly_version() *C.char {
	return versionCStr
}

// quietly_random_bytes fills out[0:n] with cryptographically secure random
// bytes. Returns 0 on success and -1 on failure.
//
//export quietly_random_bytes
func quietly_random_bytes(out *C.uchar, n C.int) C.int {
	if n < 0 {
		return -1
	}
	buf := make([]byte, int(n))
	if err := cryptocore.RandomBytes(buf); err != nil {
		return -1
	}
	dst, ok := outView(out, len(buf))
	if !ok {
		return -1
	}
	copy(dst, buf)
	return 0
}

// quietly_identity_keypair_generate writes a fresh Ed25519 identity keypair:
// pub32 (32 bytes) and priv64 (64 bytes, seed||public key). Returns 0 on
// success and -1 on failure.
//
//export quietly_identity_keypair_generate
func quietly_identity_keypair_generate(pub32, priv64 *C.uchar) C.int {
	pub, ok := outView(pub32, cryptocore.IdentityPublicKeySize)
	if !ok {
		return -1
	}
	priv, ok := outView(priv64, cryptocore.IdentityPrivateKeySize)
	if !ok {
		return -1
	}
	kp, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		return -1
	}
	copy(pub, kp.PublicKey)
	copy(priv, kp.PrivateKey)
	return 0
}

// quietly_identity_sign writes a 64-byte Ed25519 signature of msg[0:msgLen]
// into sig64 using the private key priv64. Returns 0 on success and -1 on
// failure.
//
//export quietly_identity_sign
func quietly_identity_sign(sig64, priv64, msg *C.uchar, msgLen C.int) C.int {
	sig, ok := outView(sig64, cryptocore.SignatureSize)
	if !ok {
		return -1
	}
	priv, ok := copyIn(priv64, cryptocore.IdentityPrivateKeySize)
	if !ok {
		return -1
	}
	message, ok := copyIn(msg, int(msgLen))
	if !ok {
		return -1
	}
	s, err := cryptocore.SignIdentity(priv, message)
	if err != nil {
		return -1
	}
	copy(sig, s)
	return 0
}

// quietly_identity_verify verifies a 64-byte Ed25519 signature over
// msg[0:msgLen] using pub32. Returns 1 if valid, 0 if invalid, and -1 on
// malformed input.
//
//export quietly_identity_verify
func quietly_identity_verify(pub32, msg *C.uchar, msgLen C.int, sig64 *C.uchar) C.int {
	pub, ok := copyIn(pub32, cryptocore.IdentityPublicKeySize)
	if !ok {
		return -1
	}
	message, ok := copyIn(msg, int(msgLen))
	if !ok {
		return -1
	}
	sig, ok := copyIn(sig64, cryptocore.SignatureSize)
	if !ok {
		return -1
	}
	if cryptocore.VerifyIdentitySignature(pub, message, sig) {
		return 1
	}
	return 0
}

// quietly_prekey_generate writes a fresh X25519 keypair: pub32 and priv32.
// Returns 0 on success and -1 on failure.
//
//export quietly_prekey_generate
func quietly_prekey_generate(pub32, priv32 *C.uchar) C.int {
	pub, ok := outView(pub32, cryptocore.X25519PublicKeySize)
	if !ok {
		return -1
	}
	priv, ok := outView(priv32, cryptocore.X25519PrivateKeySize)
	if !ok {
		return -1
	}
	pk, err := cryptocore.GeneratePreKey()
	if err != nil {
		return -1
	}
	copy(pub, pk.PublicKey)
	copy(priv, pk.PrivateKey)
	return 0
}

// quietly_x25519 computes the X25519 shared secret from priv32 and pub32,
// writing the 32-byte result into shared32. Returns 0 on success and -1 on
// failure.
//
//export quietly_x25519
func quietly_x25519(shared32, priv32, pub32 *C.uchar) C.int {
	shared, ok := outView(shared32, cryptocore.X25519SharedSecretSize)
	if !ok {
		return -1
	}
	priv, ok := copyIn(priv32, cryptocore.X25519PrivateKeySize)
	if !ok {
		return -1
	}
	pub, ok := copyIn(pub32, cryptocore.X25519PublicKeySize)
	if !ok {
		return -1
	}
	secret, err := cryptocore.X25519(priv, pub)
	if err != nil {
		return -1
	}
	copy(shared, secret)
	return 0
}

// quietly_hkdf_sha256 derives outLen bytes with HKDF-SHA256, writing them into
// out. ikm, salt, and info are the HKDF inputs. Returns 0 on success and -1 on
// failure.
//
//export quietly_hkdf_sha256
func quietly_hkdf_sha256(out *C.uchar, outLen C.int, ikm *C.uchar, ikmLen C.int, salt *C.uchar, saltLen C.int, info *C.uchar, infoLen C.int) C.int {
	if outLen < 0 {
		return -1
	}
	ikmBytes, ok := copyIn(ikm, int(ikmLen))
	if !ok {
		return -1
	}
	saltBytes, ok := copyIn(salt, int(saltLen))
	if !ok {
		return -1
	}
	infoBytes, ok := copyIn(info, int(infoLen))
	if !ok {
		return -1
	}
	derived, err := cryptocore.HKDFSHA256(ikmBytes, saltBytes, infoBytes, int(outLen))
	if err != nil {
		return -1
	}
	dst, ok := outView(out, len(derived))
	if !ok {
		return -1
	}
	copy(dst, derived)
	return 0
}

// quietly_argon2id derives outLen bytes with Argon2id, writing them into out.
// time is the number of passes, memory the cost in KiB, and threads the degree
// of parallelism. Returns 0 on success and -1 on failure.
//
//export quietly_argon2id
func quietly_argon2id(out *C.uchar, outLen C.int, password *C.uchar, passwordLen C.int, salt *C.uchar, saltLen C.int, time, memory C.uint, threads C.uchar) C.int {
	if outLen < 0 {
		return -1
	}
	passwordBytes, ok := copyIn(password, int(passwordLen))
	if !ok {
		return -1
	}
	saltBytes, ok := copyIn(salt, int(saltLen))
	if !ok {
		return -1
	}
	key, err := cryptocore.Argon2id(
		passwordBytes,
		saltBytes,
		cryptocore.Argon2idParams{
			Time:    uint32(time),
			Memory:  uint32(memory),
			Threads: uint8(threads),
			KeyLen:  uint32(outLen),
		},
	)
	if err != nil {
		return -1
	}
	dst, ok := outView(out, len(key))
	if !ok {
		return -1
	}
	copy(dst, key)
	return 0
}

// quietly_aead_seal encrypts plaintext[0:plaintextLen] with
// XChaCha20-Poly1305 using key32 and nonce24, writing ciphertext||tag into out
// and the resulting length into *outLen. outCap must be at least
// plaintextLen + 16. Returns 0 on success and -1 on failure.
//
//export quietly_aead_seal
func quietly_aead_seal(out *C.uchar, outCap C.int, outLen *C.int, key32, nonce24, plaintext *C.uchar, plaintextLen C.int, aad *C.uchar, aadLen C.int) C.int {
	if outCap < 0 || outLen == nil {
		return -1
	}
	key, ok := copyIn(key32, cryptocore.AEADKeySize)
	if !ok {
		return -1
	}
	nonce, ok := copyIn(nonce24, cryptocore.AEADNonceSize)
	if !ok {
		return -1
	}
	pt, ok := copyIn(plaintext, int(plaintextLen))
	if !ok {
		return -1
	}
	aa, ok := copyIn(aad, int(aadLen))
	if !ok {
		return -1
	}
	ct, err := cryptocore.Seal(key, nonce, pt, aa)
	if err != nil {
		return -1
	}
	if int(outCap) < len(ct) {
		return -1
	}
	dst, ok := outView(out, len(ct))
	if !ok {
		return -1
	}
	copy(dst, ct)
	*outLen = C.int(len(ct))
	return 0
}

// quietly_aead_open decrypts and authenticates ciphertext[0:ciphertextLen]
// with XChaCha20-Poly1305 using key32 and nonce24, writing the plaintext into
// out and its length into *outLen. Returns 0 on success and -1 on failure
// (including authentication failure).
//
//export quietly_aead_open
func quietly_aead_open(out *C.uchar, outCap C.int, outLen *C.int, key32, nonce24, ciphertext *C.uchar, ciphertextLen C.int, aad *C.uchar, aadLen C.int) C.int {
	if outCap < 0 || outLen == nil {
		return -1
	}
	key, ok := copyIn(key32, cryptocore.AEADKeySize)
	if !ok {
		return -1
	}
	nonce, ok := copyIn(nonce24, cryptocore.AEADNonceSize)
	if !ok {
		return -1
	}
	ct, ok := copyIn(ciphertext, int(ciphertextLen))
	if !ok {
		return -1
	}
	aa, ok := copyIn(aad, int(aadLen))
	if !ok {
		return -1
	}
	pt, err := cryptocore.Open(key, nonce, ct, aa)
	if err != nil {
		return -1
	}
	if int(outCap) < len(pt) {
		return -1
	}
	dst, ok := outView(out, len(pt))
	if !ok {
		return -1
	}
	copy(dst, pt)
	*outLen = C.int(len(pt))
	return 0
}

// maxInputLen caps the size of a single caller-supplied buffer, protecting the
// host process from an absurd allocation (a hostile caller could otherwise
// request up to 2 GiB per call).
const maxInputLen = 64 << 20 // 64 MiB

// copyIn returns a fresh Go heap slice containing n bytes copied from p. A nil
// pointer is acceptable when n is zero. Inputs are copied so that Go's crypto
// packages never observe memory owned by the C caller (which would be invalid
// for weak-pointer registration).
func copyIn(p *C.uchar, n int) ([]byte, bool) {
	if n == 0 {
		return nil, true
	}
	if n < 0 || n > maxInputLen || p == nil {
		return nil, false
	}
	b := make([]byte, n)
	copy(b, unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
	return b, true
}

// outView returns a Go slice that aliases exactly n bytes of caller-owned C
// memory, for writing results back to the caller. The pointer must not be nil.
func outView(p *C.uchar, n int) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), n), true
}
