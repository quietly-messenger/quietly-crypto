# Quietly crypto

Cryptographic core of [Quietly](https://github.com/quietly-messenger) — a messenger with Telegram-level UX and a Signal/Matrix-level security model. This repository was originally a Zig crate and has been migrated to a Go library.

The library provides the primitives the client needs to run X3DH session establishment and the Double Ratchet, and it can be consumed two ways:

1. **As a Go module** — import `github.com/quietly-messenger/quietly-crypto/cryptocore` from any Go program.
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
| HKDF-SHA256 | `crypto/hkdf` | Ratchet key derivation (RFC 5869) |
| Argon2id | `golang.org/x/crypto/argon2` | Recovery-phrase → backup key |
| XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` | Message and attachment encryption |
| CSPRNG | `crypto/rand` | Nonces, salts, key generation |

The X3DH handshake and the Double Ratchet state machine are composed from these primitives and are the next implementation step; they are intentionally kept out of this repo until the protocol schema (`api/v1/PROTOCOL.md` in the server) is frozen.

## Layout

```
cryptocore/       importable Go library (package cryptocore)
ffi/              package main: C ABI exports for the shared library
Makefile          build, test, and cross-compile targets
```

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

All byte buffers are caller-owned; functions write into caller-provided buffers and return `0` on success, `-1` on error (`quietly_identity_verify` returns `1` for a valid signature, `0` for invalid). Fixed-size buffers carry their length in the parameter name (`pub32`, `priv64`, `sig64`, `nonce24`, …). See the generated header for exact prototypes.

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

## Security notes

- Keys and secrets are plain Go `[]byte` values. This crate does not yet zeroize them on deallocation; callers handling long-lived key material should consider `runtime.KeepAlive` and explicit zeroization once the protocol layer lands.
- X25519 rejects low-order public keys (`crypto/ecdh` returns an error), which mitigates small-subgroup attacks during X3DH.
- All randomness comes from `crypto/rand` (the OS CSPRNG).

## License

AGPL-3.0 — see [LICENSE](./LICENSE).
