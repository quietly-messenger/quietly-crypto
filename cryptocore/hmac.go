package cryptocore

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256 computes the HMAC-SHA256 of data under key (RFC 2104).
//
// It backs the Double Ratchet chain KDF (PROTOCOL.md §9.1), where mk and the
// next chain key are derived as HMAC-SHA256(ck, 0x01) and HMAC-SHA256(ck, 0x02).
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
