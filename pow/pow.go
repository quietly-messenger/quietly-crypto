// Package pow implements the stateless account-creation proof of work
// (PROTOCOL.md §4). The client solves; the server verifies. Both use the same
// code so they can never disagree on the preimage construction.
package pow

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
	"strings"

	"github.com/quietly-messenger/quietly-crypto/quietly"
)

// Domain is the proof-of-work domain-separation string (PROTOCOL.md §3.3).
const Domain = quietly.DomainPoW

// MaxDifficulty is the largest meaningful difficulty (a SHA-256 digest has at
// most 256 leading zero bits).
const MaxDifficulty = 256

// Solve finds the smallest nonce whose preimage hashes to at least `difficulty`
// leading zero bits. The caller is expected to have lowercased the username
// already; Solve lowercases defensively anyway.
//
// Solve returns 0 for an invalid difficulty (outside [0, 256]). Callers that
// need to distinguish "solved at nonce 0" from "no solution" should use
// SolveLimit, which reports success explicitly.
func Solve(username string, timestampMS int64, difficulty int) uint64 {
	nonce, _ := solve(username, timestampMS, difficulty, 0)
	return nonce
}

// SolveLimit is Solve with an upper bound on the nonce: it returns
// (nonce, true) on success and (0, false) if no nonce in [0, maxNonce]
// satisfies the difficulty. Pass maxNonce == 0 for an unbounded search.
func SolveLimit(username string, timestampMS int64, difficulty int, maxNonce uint64) (uint64, bool) {
	return solve(username, timestampMS, difficulty, maxNonce)
}

func solve(username string, timestampMS int64, difficulty int, maxNonce uint64) (uint64, bool) {
	if difficulty < 0 || difficulty > MaxDifficulty {
		return 0, false
	}
	username = strings.ToLower(username)

	// The prefix is fixed across all nonces; build it once and reuse the
	// buffer, appending only the nonce each iteration.
	prefix := prefix(username, timestampMS)
	buf := make([]byte, 0, len(prefix)+20)
	for nonce := uint64(0); ; nonce++ {
		if maxNonce != 0 && nonce > maxNonce {
			return 0, false
		}
		buf = append(buf[:0], prefix...)
		buf = strconv.AppendUint(buf, nonce, 10)
		digest := sha256.Sum256(buf)
		if leadingZeroBits(digest[:]) >= difficulty {
			return nonce, true
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

// prefix builds "quietly/1 pow" || 0x00 || username || 0x00 || timestamp_ms
// || 0x00, the fixed part of the preimage.
func prefix(username string, timestampMS int64) []byte {
	ts := strconv.FormatInt(timestampMS, 10)
	b := make([]byte, 0, len(Domain)+1+len(username)+1+len(ts)+1)
	b = append(b, Domain...)
	b = append(b, 0x00)
	b = append(b, username...)
	b = append(b, 0x00)
	b = append(b, ts...)
	b = append(b, 0x00)
	return b
}

// preimage builds the full preimage: prefix || nonce, where nonce is decimal
// ASCII with no leading zeros.
func preimage(username string, timestampMS int64, nonce uint64) []byte {
	return strconv.AppendUint(prefix(username, timestampMS), nonce, 10)
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
