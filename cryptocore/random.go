package cryptocore

import (
	"crypto/rand"
	"fmt"
)

// RandomBytes fills b with cryptographically secure random bytes.
func RandomBytes(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("reading random bytes: %w", err)
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if err := RandomBytes(b); err != nil {
		return nil, err
	}
	return b, nil
}
