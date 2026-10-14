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

// Argon2id derives a key of p.KeyLen bytes from password and salt.
func Argon2id(password, salt []byte, p Argon2idParams) ([]byte, error) {
	if p.KeyLen == 0 {
		return nil, fmt.Errorf("Argon2id key length must be positive")
	}
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen), nil
}
