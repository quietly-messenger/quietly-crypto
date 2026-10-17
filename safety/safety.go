// Package safety implements safety-number fingerprints (PROTOCOL.md §9.5):
// a short, order-independent value two users can compare out of band to detect
// a man-in-the-middle.
package safety

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/quietly-messenger/quietly-crypto/quietly"
)

// Domain is the safety-number domain-separation string (PROTOCOL.md §3.3).
const Domain = quietly.DomainSafetyNumber

// FingerprintSize is the size of a rendered single-party fingerprint in bytes
// (PROTOCOL.md truncates SHA-256 output to 30 bytes).
const FingerprintSize = 30

// Fingerprint returns a party's 30-byte fingerprint:
//
//	SHA-256(Domain || 0x00 || user_id || IK_dh || IK_sig)
//
// truncated to 30 bytes.
func Fingerprint(userID [16]byte, ikDH, ikSig []byte) [FingerprintSize]byte {
	h := sha256.New()
	h.Write([]byte(Domain))
	h.Write([]byte{0x00})
	h.Write(userID[:])
	h.Write(ikDH)
	h.Write(ikSig)
	sum := h.Sum(nil)

	var fp [FingerprintSize]byte
	copy(fp[:], sum)
	return fp
}

// Format renders a 30-byte fingerprint as six groups of five decimal digits.
// Each 5-byte chunk is interpreted big-endian and taken modulo 100000, the
// same digitization libsignal uses, so fingerprints render identically across
// implementations. It returns an error for a short fingerprint.
func Format(fp []byte) (string, error) {
	if len(fp) < FingerprintSize {
		return "", fmt.Errorf("safety fingerprint must be at least %d bytes, got %d", FingerprintSize, len(fp))
	}
	var b strings.Builder
	b.Grow(FingerprintSize) // 6 chunks of 5 digits
	for i := 0; i < 6; i++ {
		var v uint64
		for j := 0; j < 5; j++ {
			v = v<<8 | uint64(fp[i*5+j])
		}
		b.WriteString(pad5(v % 100000))
	}
	return b.String(), nil
}

// SafetyNumber returns the combined, order-independent safety number of two
// parties. The two fingerprints are ordered by byte-wise comparison so both
// parties compute the identical value regardless of who initiated.
func SafetyNumber(fpA, fpB []byte) (string, error) {
	a, err := Format(fpA)
	if err != nil {
		return "", err
	}
	b, err := Format(fpB)
	if err != nil {
		return "", err
	}
	if bytes.Compare(fpA, fpB) <= 0 {
		return a + b, nil
	}
	return b + a, nil
}

func pad5(v uint64) string {
	s := strconv.FormatUint(v, 10)
	if len(s) >= 5 {
		return s
	}
	return strings.Repeat("0", 5-len(s)) + s
}
