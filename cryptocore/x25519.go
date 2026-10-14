package cryptocore

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// X25519PublicKeySize is the size of an X25519 public key in bytes.
	X25519PublicKeySize = 32
	// X25519PrivateKeySize is the size of an X25519 private key in bytes.
	X25519PrivateKeySize = 32
	// X25519SharedSecretSize is the size of an X25519 shared secret in bytes.
	X25519SharedSecretSize = 32
)

// PreKey is an ephemeral X25519 keypair used as a one-time or signed prekey.
type PreKey struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GeneratePreKey creates a new random X25519 keypair.
func GeneratePreKey() (*PreKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating X25519 keypair: %w", err)
	}
	return &PreKey{
		PublicKey:  priv.PublicKey().Bytes(),
		PrivateKey: priv.Bytes(),
	}, nil
}

// NewPreKey builds a PreKey from raw keys, validating lengths and that the
// public key matches the private key.
func NewPreKey(publicKey, privateKey []byte) (*PreKey, error) {
	if len(publicKey) != X25519PublicKeySize {
		return nil, fmt.Errorf("X25519 public key must be %d bytes, got %d", X25519PublicKeySize, len(publicKey))
	}
	if len(privateKey) != X25519PrivateKeySize {
		return nil, fmt.Errorf("X25519 private key must be %d bytes, got %d", X25519PrivateKeySize, len(privateKey))
	}
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 private key: %w", err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), publicKey) {
		return nil, errors.New("X25519 public key does not match private key")
	}
	return &PreKey{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// X25519 computes the Diffie-Hellman shared secret between a private key and a
// peer public key. It rejects malformed keys and low-order public keys.
func X25519(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != X25519PrivateKeySize {
		return nil, fmt.Errorf("X25519 private key must be %d bytes, got %d", X25519PrivateKeySize, len(privateKey))
	}
	if len(peerPublicKey) != X25519PublicKeySize {
		return nil, fmt.Errorf("X25519 public key must be %d bytes, got %d", X25519PublicKeySize, len(peerPublicKey))
	}
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 private key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("computing X25519 shared secret: %w", err)
	}
	return shared, nil
}
