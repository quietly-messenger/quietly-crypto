package protocol

import "github.com/quietly-messenger/quietly-crypto/identity"

// The shared identity types and helpers are re-exported here so the
// client-facing protocol package exposes the full API in one place. The home
// server imports the `identity` package directly (see ARCHITECTURE.md).
type IdentityKeys = identity.IdentityKeys
type PreKeyBundle = identity.PreKeyBundle

var (
	GenerateIdentityKeys  = identity.GenerateIdentityKeys
	GeneratePreKeyBundle  = identity.GeneratePreKeyBundle
	SignIdentityBinding   = identity.SignIdentityBinding
	VerifyIdentityBinding = identity.VerifyIdentityBinding
	SignSignedPreKey      = identity.SignSignedPreKey
	VerifySignedPreKey    = identity.VerifySignedPreKey
)
