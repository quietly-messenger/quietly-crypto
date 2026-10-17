package cryptocore

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// AEADKeySize is the size of the XChaCha20-Poly1305 key in bytes.
	AEADKeySize = chacha20poly1305.KeySize
	// AEADNonceSize is the size of the XChaCha20-Poly1305 nonce in bytes.
	AEADNonceSize = chacha20poly1305.NonceSizeX
	// AEADTagSize is the size of the Poly1305 authentication tag in bytes.
	AEADTagSize = 16
	// ChaChaNonceSize is the size of the ChaCha20-Poly1305 (IETF) nonce in
	// bytes. This is the AEAD used for ratchet messages (PROTOCOL.md §9.1).
	ChaChaNonceSize = chacha20poly1305.NonceSize
)

// Encrypt encrypts plaintext with XChaCha20-Poly1305, prepending a fresh
// random nonce. The result is nonce || ciphertext.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	nonce, err := randomBytes(AEADNonceSize)
	if err != nil {
		return nil, err
	}
	sealed, err := Seal(key, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, sealed...), nil
}

// Decrypt decrypts and authenticates the output of Encrypt (nonce || ciphertext).
func Decrypt(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < AEADNonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(sealed))
	}
	return Open(key, sealed[:AEADNonceSize], sealed[AEADNonceSize:], aad)
}

// Seal encrypts plaintext with XChaCha20-Poly1305 using an explicit nonce,
// returning ciphertext||tag.
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != AEADNonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", AEADNonceSize, len(nonce))
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates the output of Seal.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != AEADNonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", AEADNonceSize, len(nonce))
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

// SealChaCha encrypts plaintext with ChaCha20-Poly1305 (IETF, 96-bit nonce)
// using an explicit 12-byte nonce, returning ciphertext||tag.
func SealChaCha(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newChaCha(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// OpenChaCha decrypts and authenticates the output of SealChaCha.
func OpenChaCha(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newChaCha(key, nonce)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

func newChaCha(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("AEAD key must be %d bytes, got %d", AEADKeySize, len(key))
	}
	if len(nonce) != ChaChaNonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", ChaChaNonceSize, len(nonce))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("creating AEAD: %w", err)
	}
	return aead, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("AEAD key must be %d bytes, got %d", AEADKeySize, len(key))
	}
	return chacha20poly1305.NewX(key)
}
