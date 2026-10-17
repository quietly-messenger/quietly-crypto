// Package auth implements request authentication (PROTOCOL.md §5): the
// canonical request string and its Ed25519 signature. The client signs each
// authenticated request with its identity signing key; the home server
// verifies it. Both build the same canonical string, so they cannot drift.
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/quietly"
)

// BodyHash returns the lowercase hex SHA-256 of a request body (§5.1). An
// empty body hashes to the SHA-256 of the empty string.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalString builds the §5.1 canonical string:
//
//	METHOD || "\n" || PATH || "\n" || TIMESTAMP || "\n" || NONCE || "\n" || SHA256_HEX(body)
//
// method must be uppercase; path includes the query string exactly as sent;
// timestamp is Unix milliseconds; nonce is the header value verbatim.
func CanonicalString(method, path string, timestampMS int64, nonce string, body []byte) string {
	return method + "\n" +
		path + "\n" +
		strconv.FormatInt(timestampMS, 10) + "\n" +
		nonce + "\n" +
		BodyHash(body)
}

// NewNonce returns a fresh 16-byte nonce as base64url without padding (§5.2).
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if err := cryptocore.RandomBytes(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SignRequest signs a request: Ed25519 over "quietly/1 request" || 0x00 ||
// canonical (§5.1).
func SignRequest(sigPriv []byte, method, path string, timestampMS int64, nonce string, body []byte) ([]byte, error) {
	return cryptocore.SignIdentity(sigPriv, requestPayload(method, path, timestampMS, nonce, body))
}

// VerifyRequest reports whether sig is a valid signature over the canonical
// string for the given request fields.
func VerifyRequest(sigPub []byte, method, path string, timestampMS int64, nonce string, body []byte, sig []byte) bool {
	return cryptocore.VerifyIdentitySignature(sigPub, requestPayload(method, path, timestampMS, nonce, body), sig)
}

func requestPayload(method, path string, timestampMS int64, nonce string, body []byte) []byte {
	return quietly.DomainSeparate(quietly.DomainRequest, []byte(CanonicalString(method, path, timestampMS, nonce, body)))
}
