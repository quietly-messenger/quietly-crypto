package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"github.com/quietly-messenger/quietly-crypto/auth"
	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/pow"
)

// --- Request authentication (§5) and proof of work (§4): the client-side
// helpers Dart must not re-implement. Canonicalization lives here so the client
// and the server can never disagree on the signed string. ---
//
// The Go-level shims below hold the logic (cgo cannot appear in test files);
// the exported functions add only the buffer plumbing.

// authSignRequest validates key size and signs the §5.1 canonical string.
func authSignRequest(sigPriv []byte, method, path string, timestampMS int64, nonce string, body []byte) ([]byte, bool) {
	if len(sigPriv) != cryptocore.IdentityPrivateKeySize {
		return nil, false
	}
	sig, err := auth.SignRequest(sigPriv, method, path, timestampMS, nonce, body)
	if err != nil {
		return nil, false
	}
	return sig, true
}

// authCanonical returns the §5.1 canonical request string.
func authCanonical(method, path string, timestampMS int64, nonce string, body []byte) []byte {
	return []byte(auth.CanonicalString(method, path, timestampMS, nonce, body))
}

// authBodyHash returns the §5.1 body hash (64 lowercase hex characters).
func authBodyHash(body []byte) []byte {
	return []byte(auth.BodyHash(body))
}

// powSolveNonce bounds difficulty before solving so a caller cannot trigger an
// unbounded search.
func powSolveNonce(username string, timestampMS int64, difficulty int) (uint64, bool) {
	if difficulty < 0 || difficulty > pow.MaxDifficulty {
		return 0, false
	}
	return pow.Solve(username, timestampMS, difficulty), true
}

// quietly_auth_body_hash writes the §5.1 body hash of body[0:bodyLen] — 64
// lowercase hex characters — into out, which must have room for 64 bytes. No
// length is written. Returns 0 on success and -1 on failure.
//
//export quietly_auth_body_hash
func quietly_auth_body_hash(body *C.uchar, bodyLen C.int, out *C.uchar) C.int {
	b, ok := copyIn(body, int(bodyLen))
	if !ok {
		return -1
	}
	dst, ok := outView(out, 64)
	if !ok {
		return -1
	}
	copy(dst, authBodyHash(b))
	return 0
}

// quietly_auth_canonical_string writes the §5.1 canonical request string —
// METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" SHA256_HEX(body) — into out
// and its length into *outLen. method must be uppercase; path includes the
// query string exactly as sent. Returns 0 on success and -1 on failure
// (including a short output buffer).
//
//export quietly_auth_canonical_string
func quietly_auth_canonical_string(
	method *C.uchar, methodLen C.int,
	path *C.uchar, pathLen C.int,
	timestampMS C.int64_t,
	nonce *C.uchar, nonceLen C.int,
	body *C.uchar, bodyLen C.int,
	out *C.uchar, outCap C.int, outLen *C.int,
) C.int {
	m, ok := copyIn(method, int(methodLen))
	if !ok {
		return -1
	}
	p, ok := copyIn(path, int(pathLen))
	if !ok {
		return -1
	}
	n, ok := copyIn(nonce, int(nonceLen))
	if !ok {
		return -1
	}
	b, ok := copyIn(body, int(bodyLen))
	if !ok {
		return -1
	}
	return writeOut(out, outCap, outLen, authCanonical(string(m), string(p), int64(timestampMS), string(n), b))
}

// quietly_auth_sign_request signs the §5.1 canonical string for
// (method, path, timestamp_ms, nonce, body) with the device's Ed25519 identity
// private key sigPriv64, writing the raw 64-byte signature into out64. The
// caller base64url-encodes it (no padding) for X-Quietly-Signature.
// Returns 0 on success and -1 on failure.
//
//export quietly_auth_sign_request
func quietly_auth_sign_request(
	sigPriv64 *C.uchar,
	method *C.uchar, methodLen C.int,
	path *C.uchar, pathLen C.int,
	timestampMS C.int64_t,
	nonce *C.uchar, nonceLen C.int,
	body *C.uchar, bodyLen C.int,
	out64 *C.uchar,
) C.int {
	priv, ok := copyIn(sigPriv64, cryptocore.IdentityPrivateKeySize)
	if !ok {
		return -1
	}
	m, ok := copyIn(method, int(methodLen))
	if !ok {
		return -1
	}
	p, ok := copyIn(path, int(pathLen))
	if !ok {
		return -1
	}
	n, ok := copyIn(nonce, int(nonceLen))
	if !ok {
		return -1
	}
	b, ok := copyIn(body, int(bodyLen))
	if !ok {
		return -1
	}
	sig, ok := authSignRequest(priv, string(m), string(p), int64(timestampMS), string(n), b)
	if !ok {
		return -1
	}
	dst, ok := outView(out64, len(sig))
	if !ok {
		return -1
	}
	copy(dst, sig)
	return 0
}

// quietly_auth_nonce generates a fresh 16-byte, base64url-encoded nonce for
// X-Quietly-Nonce, writing it into out and its length into *outLen.
// Returns 0 on success and -1 on failure.
//
//export quietly_auth_nonce
func quietly_auth_nonce(out *C.uchar, outCap C.int, outLen *C.int) C.int {
	n, err := auth.NewNonce()
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, []byte(n))
}

// quietly_pow_solve solves the §4 account-creation proof of work for
// (username, timestamp_ms) at `difficulty` leading zero bits, writing the
// winning nonce to *outNonce. difficulty must be in [0, 256].
// Returns 0 on success and -1 on invalid arguments or output pointer.
//
// Solving is O(2^difficulty) hash evaluations on the caller's thread; the
// caller decides when to run it (the protocol recommends a worker/isolate).
//
//export quietly_pow_solve
func quietly_pow_solve(username *C.uchar, usernameLen C.int, timestampMS C.int64_t, difficulty C.int, outNonce *C.uint64_t) C.int {
	if outNonce == nil {
		return -1
	}
	u, ok := copyIn(username, int(usernameLen))
	if !ok {
		return -1
	}
	nonce, ok := powSolveNonce(string(u), int64(timestampMS), int(difficulty))
	if !ok {
		return -1
	}
	*outNonce = C.uint64_t(nonce)
	return 0
}
