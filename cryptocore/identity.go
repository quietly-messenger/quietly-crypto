package cryptocore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// IdentityPublicKeySize is the size of an Ed25519 public key in bytes.
	IdentityPublicKeySize = ed25519.PublicKeySize
	// IdentityPrivateKeySize is the size of an Ed25519 private key in bytes.
	// It is the 32-byte seed followed by the 32-byte public key.
	IdentityPrivateKeySize = ed25519.PrivateKeySize
	// SignatureSize is the size of an Ed25519 signature in bytes.
	SignatureSize = ed25519.SignatureSize
)

// IdentityKeyPair is a long-term Ed25519 identity keypair for a device.
type IdentityKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateIdentityKeyPair creates a new random Ed25519 identity keypair.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating identity keypair: %w", err)
	}
	return &IdentityKeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// NewIdentityKeyPair builds an IdentityKeyPair from raw keys, validating both
// lengths and that the private key's embedded public key matches publicKey.
func NewIdentityKeyPair(publicKey, privateKey []byte) (*IdentityKeyPair, error) {
	if len(publicKey) != IdentityPublicKeySize {
		return nil, fmt.Errorf("identity public key must be %d bytes, got %d", IdentityPublicKeySize, len(publicKey))
	}
	if len(privateKey) != IdentityPrivateKeySize {
		return nil, fmt.Errorf("identity private key must be %d bytes, got %d", IdentityPrivateKeySize, len(privateKey))
	}
	if !bytes.Equal(ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey), ed25519.PublicKey(publicKey)) {
		return nil, errors.New("identity private key does not match public key")
	}
	return &IdentityKeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// Sign returns a 64-byte Ed25519 signature of message.
func (k *IdentityKeyPair) Sign(message []byte) ([]byte, error) {
	return SignIdentity(k.PrivateKey, message)
}

// SignIdentity signs message with a raw Ed25519 private key, returning a
// 64-byte signature.
func SignIdentity(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != IdentityPrivateKeySize {
		return nil, fmt.Errorf("identity private key must be %d bytes, got %d", IdentityPrivateKeySize, len(privateKey))
	}
	return ed25519.Sign(privateKey, message), nil
}

// VerifyIdentitySignature reports whether sig is a valid signature of message
// produced by publicKey. Malformed key or signature lengths return false.
func VerifyIdentitySignature(publicKey, message, sig []byte) bool {
	if len(publicKey) != IdentityPublicKeySize || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, sig)
}
