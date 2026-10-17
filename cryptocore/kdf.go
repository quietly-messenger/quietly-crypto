package cryptocore

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// HKDFSHA256 derives outLen bytes from input key material using HKDF with
// SHA-256 (RFC 5869). salt and info may be empty.
func HKDFSHA256(ikm, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, fmt.Errorf("HKDF output length must be positive, got %d", outLen)
	}
	key, err := hkdf.Key(sha256.New, ikm, salt, string(info), outLen)
	if err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	return key, nil
}

// Argon2idParams configures the Argon2id password KDF used to derive a backup
// key from a user recovery phrase.
type Argon2idParams struct {
	Time    uint32 // number of passes
	Memory  uint32 // memory cost in KiB
	Threads uint8  // degree of parallelism
	KeyLen  uint32 // output length in bytes
}

// Argon2id parameter bounds. These exist so that invalid or hostile parameters
// return an error instead of panicking (x/crypto panics on Time/Threads == 0)
// or attempting an absurd allocation (Memory is in KiB, so the uint32 max is
// ~4 TiB).
const (
	// MinArgon2idSaltLen is the minimum salt length (RFC 9106 §3.1).
	MinArgon2idSaltLen = 8
	// MaxArgon2idMemoryKiB caps the memory cost at 1 GiB.
	MaxArgon2idMemoryKiB = 1 << 20
)

// DefaultArgon2idParams returns the recommended parameters for deriving a
// 32-byte backup key from a user recovery phrase.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Time:    3,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
	}
}

// Argon2id derives a key of p.KeyLen bytes from password and salt. It returns
// an error for parameters that x/crypto would panic on, for a short salt, or
// for an unreasonably large memory cost.
func Argon2id(password, salt []byte, p Argon2idParams) ([]byte, error) {
	if p.KeyLen == 0 {
		return nil, fmt.Errorf("Argon2id key length must be positive")
	}
	if p.Time < 1 {
		return nil, fmt.Errorf("Argon2id time (passes) must be at least 1")
	}
	if p.Threads < 1 {
		return nil, fmt.Errorf("Argon2id threads must be at least 1")
	}
	if len(salt) < MinArgon2idSaltLen {
		return nil, fmt.Errorf("Argon2id salt must be at least %d bytes (RFC 9106)", MinArgon2idSaltLen)
	}
	if p.Memory > MaxArgon2idMemoryKiB {
		return nil, fmt.Errorf("Argon2id memory must not exceed %d KiB", MaxArgon2idMemoryKiB)
	}
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen), nil
}
