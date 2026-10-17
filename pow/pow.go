// Package pow implements the stateless account-creation proof of work
// (PROTOCOL.md §4). The client solves; the server verifies. Both use the same
// code so they can never disagree on the preimage construction.
package pow

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
	"strings"
)

// Domain is the proof-of-work domain-separation string (PROTOCOL.md §3.3).
const Domain = "quietly/1 pow"

// MaxDifficulty is the largest meaningful difficulty (a SHA-256 digest has at
// most 256 leading zero bits).
const MaxDifficulty = 256

// Solve finds the smallest nonce whose preimage hashes to at least `difficulty`
// leading zero bits. The caller is expected to have lowercased the username
// already; Solve lowercases defensively anyway.
func Solve(username string, timestampMS int64, difficulty int) uint64 {
	username = strings.ToLower(username)
	for nonce := uint64(0); ; nonce++ {
		if Verify(username, timestampMS, nonce, difficulty) {
			return nonce
		}
	}
}

// Verify reports whether the proof (username, timestamp_ms, nonce) produces a
// SHA-256 digest with at least `difficulty` leading zero bits.
func Verify(username string, timestampMS int64, nonce uint64, difficulty int) bool {
	if difficulty < 0 || difficulty > MaxDifficulty {
		return false
	}
	username = strings.ToLower(username)
	digest := sha256.Sum256(preimage(username, timestampMS, nonce))
	return leadingZeroBits(digest[:]) >= difficulty
}

// preimage builds "quietly/1 pow" || 0x00 || username || 0x00 ||
// timestamp_ms || 0x00 || nonce, where timestamp_ms and nonce are decimal
// ASCII with no leading zeros.
func preimage(username string, timestampMS int64, nonce uint64) []byte {
	ts := strconv.FormatInt(timestampMS, 10)
	n := strconv.FormatUint(nonce, 10)
	b := make([]byte, 0, len(Domain)+1+len(username)+1+len(ts)+1+len(n))
	b = append(b, Domain...)
	b = append(b, 0x00)
	b = append(b, username...)
	b = append(b, 0x00)
	b = append(b, ts...)
	b = append(b, 0x00)
	b = append(b, n...)
	return b
}

// leadingZeroBits counts leading zero bits starting at the most significant
// bit of byte 0 (PROTOCOL.md §4.1).
func leadingZeroBits(d []byte) int {
	total := 0
	for _, b := range d {
		if b == 0 {
			total += 8
			continue
		}
		total += bits.LeadingZeros8(b)
		break
	}
	return total
}
