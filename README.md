# Quietly crypto

Cryptographic core of [Quietly](https://github.com/quietly-messenger) — a messenger with Telegram-level UX and a Signal/Matrix-level security model. This repository was originally a Zig crate and has been migrated to a Go library.

The library provides the full client crypto stack — X3DH session establishment, the Double Ratchet, sealed sender, plus the shared primitives, proof of work, and safety numbers — and it can be consumed two ways:

1. **As a Go module** — import `github.com/quietly-messenger/quietly-crypto` (packages `cryptocore`, `protocol`, `pow`, `safety`) from any Go program.
2. **As a C shared library** — compile to a `.so` / `.dll` / `.dylib` (plus a generated C header) and load it from any FFI consumer, most importantly Flutter via `dart:ffi`.

> **Status:** early development, no stable release yet. APIs will change without notice until v1. No cryptographic primitive here is hand-rolled — everything is backed by the Go standard library or `golang.org/x/crypto`.

## Contents

- [What's implemented](#whats-implemented)
- [Layout](#layout)
- [Building](#building)
- [Using from Go](#using-from-go)
- [Using from Flutter (FFI)](#using-from-flutter-ffi)
- [C API reference](#c-api-reference)
- [Security notes](#security-notes)
- [License](#license)

## What's implemented

| Primitive | Backing | Purpose |
|---|---|---|
| Ed25519 identity keys | `crypto/ed25519` | Long-term device identity; request/signature verification |
| X25519 key exchange | `crypto/ecdh` | One-time and signed prekeys, Diffie-Hellman for X3DH |
| HKDF-SHA256 | `crypto/hkdf` | X3DH and ratchet key derivation (RFC 5869) |
| HMAC-SHA256 | `crypto/hmac` | Double Ratchet chain KDF |
| Argon2id | `golang.org/x/crypto/argon2` | Recovery-phrase → backup key |
| ChaCha20-Poly1305 (IETF) | `golang.org/x/crypto/chacha20poly1305` | Ratchet message encryption |
| XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` | Sealed sender |
| CSPRNG | `crypto/rand` | Nonces, salts, key generation |

The `protocol` package implements X3DH (§8), the Double Ratchet (§9), and
sealed sender (§10) on top of those primitives, and encodes the frozen binary
wire formats and domain-separation constants from the server's
`api/v1/PROTOCOL.md`. The `pow` and `safety` packages implement the shared
proof-of-work (§4) and safety-number fingerprint (§9.5).

## Layout

```
quietly/          shared protocol constants: version + domain strings
cryptocore/       shared primitives (package cryptocore)
identity/         shared identity keys, bundles, signatures (package identity)
auth/             shared request authentication (package auth)
protocol/         client-only X3DH, Double Ratchet, sealed sender (package protocol)
pow/              shared proof of work (package pow)
safety/           shared safety-number fingerprints (package safety)
ffi/              package main: C ABI exports for the shared library
Makefile          build, test, and cross-compile targets
ARCHITECTURE.md   shared-vs-client-only layering + server integration map
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for how the server (Go import) and the
client (FFI) consume the same code, and which packages each may use.

## Building

Prerequisites:

- Go 1.26.5+
- A C compiler for cgo (`gcc`/`clang`; for Windows cross-compiles, `mingw-w64`)

Release builds are fully optimized: reproducible (`-trimpath -buildvcs=false`), stripped (`-ldflags "-s -w"`), and the cgo shim is compiled with `-O3`.

```bash
make build            # host OS: .so on Linux, .dylib on macOS, .dll on Windows
make build-linux      # dist/libquietly_crypto.so
make build-windows    # dist/quietly_crypto.dll (amd64, via mingw-w64)
make build-windows-arm64
make build-darwin     # .dylib (needs osxcross; normally run on a Mac)
make all              # linux + windows

make test             # go test -race ./...
make vet              # go vet ./...
make fmt              # gofmt
make clean            # remove dist/
```

Each build emits both the library and a generated C header (`libquietly_crypto.h` or `quietly_crypto.h`) into `dist/`.

### Building without make

The equivalent raw command for the host OS is:

```bash
go build -buildmode=c-shared -trimpath -buildvcs=false \
    -ldflags "-s -w" -o dist/libquietly_crypto.so ./ffi
```

## Using from Go

```go
package main

import (
	"fmt"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

func main() {
	kp, _ := cryptocore.GenerateIdentityKeyPair()
	sig, _ := kp.Sign([]byte("hello"))
	ok := cryptocore.VerifyIdentitySignature(kp.PublicKey, []byte("hello"), sig)
	fmt.Println(ok) // true
}
```

## Using from Flutter (FFI)

Build the library for each target platform, bundle it as a Flutter asset, and bind it with `dart:ffi`:

```dart
import 'dart:ffi';
import 'package:ffi/ffi.dart';

typedef _VersionC = Pointer<Utf8> Function();
typedef _VersionDart = Pointer<Utf8> Function();

final DynamicLibrary lib = DynamicLibrary.open('libquietly_crypto.so');
final _VersionDart version = lib
    .lookupFunction<_VersionC, _VersionDart>('quietly_version');
print(version().toDartString()); // 0.1.0
```

## C API reference

All byte buffers are caller-owned; functions write into caller-provided buffers and return `0` on success, `-1` on error (`quietly_identity_verify`/`quietly_bundle_verify`/`quietly_pow_verify` return `1` for a valid value, `0` for invalid). Fixed-size buffers carry their length in the parameter name (`pub32`, `priv64`, `sig64`, `nonce24`, …). See the generated header for exact prototypes.

The session layer is exposed through opaque integer handles — Go owns the
session objects and their keys, so the Dart side never holds ratchet state or
reassembles the protocol.

### Primitives

| Function | Description |
|---|---|
| `quietly_version()` | Library version (static string, do not free) |
| `quietly_random_bytes(out, n)` | Fill `out` with `n` CSPRNG bytes |
| `quietly_identity_keypair_generate(pub32, priv64)` | Generate an Ed25519 keypair |
| `quietly_identity_sign(sig64, priv64, msg, msgLen)` | Sign a message |
| `quietly_identity_verify(pub32, msg, msgLen, sig64)` | Verify a signature |
| `quietly_prekey_generate(pub32, priv32)` | Generate an X25519 keypair |
| `quietly_x25519(shared32, priv32, pub32)` | Compute an X25519 shared secret |
| `quietly_hkdf_sha256(out, outLen, ikm, ikmLen, salt, saltLen, info, infoLen)` | Derive keys via HKDF-SHA256 |
| `quietly_argon2id(out, outLen, password, passwordLen, salt, saltLen, time, memory, threads)` | Derive a key via Argon2id |
| `quietly_aead_seal(out, outCap, outLen, key32, nonce24, plaintext, plaintextLen, aad, aadLen)` | Encrypt with XChaCha20-Poly1305 |
| `quietly_aead_open(out, outCap, outLen, key32, nonce24, ciphertext, ciphertextLen, aad, aadLen)` | Decrypt and authenticate |
| `quietly_aead_seal_random(out, outCap, outLen, key32, plaintext, plaintextLen, aad, aadLen)` | Encrypt with a fresh random nonce (prepended) |
| `quietly_aead_open_random(out, outCap, outLen, key32, sealed, sealedLen, aad, aadLen)` | Decrypt the random-nonce output |

### Sessions (opaque handles)

| Function | Description |
|---|---|
| `quietly_session_initiate(keys, bundle, plaintext, …) → handle` | Establish as initiator; writes the initial message |
| `quietly_session_respond(keys, spk, otpk, initial, …) → handle` | Establish as responder; writes the first plaintext |
| `quietly_session_encrypt(handle, plaintext, …)` | Encrypt → normal-message wire bytes |
| `quietly_session_decrypt(handle, msg, …)` | Decrypt a normal-message wire frame |
| `quietly_session_free(handle)` | Release a session |
| `quietly_bundle_verify(ikSig, ikDH, binding, spkID, spk, spkSig)` | Verify a bundle's signatures |
| `quietly_identity_binding_sign(sigPriv, dhPub, out)` | Sign the identity binding |
| `quietly_signed_prekey_sign(sigPriv, spkID, spkPub, out)` | Sign a signed prekey |
| `quietly_seal_sender(…, inner, …)` | Seal a ratchet message for a recipient |
| `quietly_open_sender(…, blob, …)` | Open a sealed blob → sender + inner |
| `quietly_safety_number(userIDa, ikDHa, ikSiga, userIDb, ikDHb, ikSigb, …)` | Combined safety number |
| `quietly_pow_verify(username, timestampMS, nonce, difficulty)` | Verify a proof of work |

## Security notes

- Secrets are plain Go `[]byte` values. The `protocol` package zeroizes DH
  outputs, ephemeral keys, and derived keys as they go out of scope, but this is
  best-effort: the Go runtime may move or copy a slice, so it is not a hard
  guarantee that no copy remains in memory.
- X25519 rejects low-order public keys (`crypto/ecdh` returns an error), which mitigates small-subgroup attacks during X3DH.
- All randomness comes from `crypto/rand` (the OS CSPRNG).
- The protocol logic is covered by known-answer test vectors (X3DH, the ratchet
  KDF chain) generated against an independent reference implementation, plus
  property tests for forward secrecy, post-compromise security, and out-of-order
  delivery.

## License

AGPL-3.0 — see [LICENSE](./LICENSE).
