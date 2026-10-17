package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/pow"
	"github.com/quietly-messenger/quietly-crypto/protocol"
	"github.com/quietly-messenger/quietly-crypto/safety"
)

// --- Session registry: Go owns the sessions, the caller holds an opaque
// integer handle. This keeps *Session objects (and their keys) in Go-managed
// memory, never exposing a Go pointer across the FFI boundary. ---

// sessionRegistryMax bounds the number of live sessions. Adding past the cap
// evicts (and zeroizes) the oldest session, so a client that leaks handles
// cannot grow the registry without bound (audit F-13).
const sessionRegistryMax = 1024

type sessionRegistry struct {
	mu       sync.Mutex
	next     uint64
	mask     uint64
	order    []uint64
	sessions map[uint64]*protocol.Session
	max      int
}

// newSessionRegistry builds a registry whose handles are masked with a random
// per-process value, so they are not sequential and cannot be guessed by
// another in-process module (audit F-13).
func newSessionRegistry(max int) *sessionRegistry {
	return &sessionRegistry{
		mask:     randomHandleMask(),
		sessions: make(map[uint64]*protocol.Session),
		max:      max,
	}
}

// randomHandleMask returns a fresh per-process mask. It falls back to a
// time-derived value only if the OS entropy source fails.
func randomHandleMask() uint64 {
	var b [8]byte
	if err := cryptocore.RandomBytes(b[:]); err != nil {
		return uint64(time.Now().UnixNano()) | 1
	}
	return binary.LittleEndian.Uint64(b[:])
}

var sessions = newSessionRegistry(sessionRegistryMax)

func (r *sessionRegistry) add(s *protocol.Session) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.sessions) >= r.max {
		if !r.evictOldestLocked() {
			break
		}
	}
	for {
		r.next++
		if h := r.next ^ r.mask; h != 0 {
			r.sessions[h] = s
			r.order = append(r.order, h)
			return h
		}
	}
}

func (r *sessionRegistry) get(h uint64) *protocol.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[h]
}

func (r *sessionRegistry) remove(h uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[h]; ok {
		// Zeroize takes the session lock, so if a caller is mid-Encrypt this
		// waits for it before wiping (audit F-24). Lock order is always
		// registry → session; no path acquires them in reverse.
		s.Zeroize()
		delete(r.sessions, h)
	}
	// Drop stale order entries once they dominate, keeping the slice bounded
	// under churn (add/remove cycles).
	if len(r.order) > 4*r.max {
		live := r.order[:0]
		for _, oh := range r.order {
			if _, ok := r.sessions[oh]; ok {
				live = append(live, oh)
			}
		}
		r.order = live
	}
}

// evictOldestLocked zeroizes and drops the oldest live session. The caller
// holds r.mu; s.Zeroize takes the session lock (registry → session order).
func (r *sessionRegistry) evictOldestLocked() bool {
	for len(r.order) > 0 {
		h := r.order[0]
		r.order = r.order[1:]
		if s, ok := r.sessions[h]; ok {
			s.Zeroize()
			delete(r.sessions, h)
			return true
		}
	}
	return false
}

// writeOut copies data into the caller's out buffer and sets *outLen.
func writeOut(out *C.uchar, outCap C.int, outLen *C.int, data []byte) C.int {
	if outLen == nil || outCap < 0 || int(outCap) < len(data) {
		return -1
	}
	dst, ok := outView(out, len(data))
	if !ok {
		return -1
	}
	copy(dst, data)
	*outLen = C.int(len(data))
	return 0
}

func fixed32(b []byte) [32]byte {
	var a [32]byte
	copy(a[:], b)
	return a
}

func fixed16(b []byte) [16]byte {
	var a [16]byte
	copy(a[:], b)
	return a
}

// initiatorSession runs X3DH and the first encrypt for the initiator,
// returning the session and the fully-formed initial message.
func initiatorSession(ik *protocol.IdentityKeys, bundle protocol.PreKeyBundle, plaintext []byte) (*protocol.Session, []byte, error) {
	sk, ad, ek, err := protocol.X3DHInitiate(ik, bundle)
	if err != nil {
		return nil, nil, err
	}
	s, err := protocol.NewInitiatorSession(sk, ad, bundle.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	h, ct, err := s.Encrypt(plaintext)
	if err != nil {
		// The session was fully established; do not hand its keys to the GC.
		s.Zeroize()
		return nil, nil, err
	}
	initial := protocol.EncodeInitialMessage(protocol.InitialMessage{
		IdentityKeyDH:   fixed32(ik.DHPub),
		IdentityKeySig:  fixed32(ik.SigPub),
		EphemeralKey:    fixed32(ek.PublicKey),
		SignedPreKeyID:  bundle.SignedPreKeyID,
		OneTimePreKeyID: bundle.OneTimePreKeyID,
		Header:          h,
		Ciphertext:      ct,
	})
	return s, initial, nil
}

// responderSession runs X3DH respond and decrypts the first message, returning
// the session and the first plaintext.
func responderSession(ik *protocol.IdentityKeys, spk, otpk *cryptocore.PreKey, initial []byte) (*protocol.Session, []byte, error) {
	msg, err := protocol.DecodeInitialMessage(initial)
	if err != nil {
		return nil, nil, err
	}
	sk, ad, err := protocol.X3DHRespond(ik, spk, otpk, msg.IdentityKeyDH[:], msg.IdentityKeySig[:], msg.EphemeralKey[:])
	if err != nil {
		return nil, nil, err
	}
	s, err := protocol.NewResponderSession(sk, ad, spk)
	if err != nil {
		return nil, nil, err
	}
	pt, err := s.Decrypt(msg.Header, msg.Ciphertext)
	if err != nil {
		// Failed first decrypt: wipe the established session's keys.
		s.Zeroize()
		return nil, nil, err
	}
	return s, pt, nil
}

// quietly_session_initiate establishes the initiator side of a session from
// the caller's identity and the recipient's prekey bundle, encrypts the first
// message, and returns an opaque session handle. The fully-formed initial
// message (ready to seal) is written to out. Returns 0 on error.
//
//export quietly_session_initiate
func quietly_session_initiate(
	ikDHPriv, ikDHPub, ikSigPub, ikSigPriv *C.uchar,
	bIKDH, bIKSig, bBinding *C.uchar,
	bSPKID C.uint32_t,
	bSPK, bSPKSig *C.uchar,
	bOTPKID C.uint32_t,
	bOTPK *C.uchar,
	plaintext *C.uchar, plaintextLen C.int,
	out *C.uchar, outCap C.int, outLen *C.int,
) C.uint64_t {
	ik := &protocol.IdentityKeys{
		DHPriv:  mustIn(ikDHPriv, 32),
		DHPub:   mustIn(ikDHPub, 32),
		SigPub:  mustIn(ikSigPub, 32),
		SigPriv: mustIn(ikSigPriv, 64),
	}
	if ik.DHPriv == nil || ik.DHPub == nil || ik.SigPub == nil || ik.SigPriv == nil {
		return 0
	}

	bundle := protocol.PreKeyBundle{
		IdentityKeyDH:         mustIn(bIKDH, 32),
		IdentityKeySig:        mustIn(bIKSig, 32),
		IdentityBinding:       mustIn(bBinding, 64),
		SignedPreKeyID:        uint32(bSPKID),
		SignedPreKey:          mustIn(bSPK, 32),
		SignedPreKeySignature: mustIn(bSPKSig, 64),
		OneTimePreKeyID:       uint32(bOTPKID),
		OneTimePreKey:         mustIn(bOTPK, 32),
	}
	pt, ok := copyIn(plaintext, int(plaintextLen))
	if !ok {
		return 0
	}

	s, initial, err := initiatorSession(ik, bundle, pt)
	if err != nil {
		return 0
	}
	if writeOut(out, outCap, outLen, initial) != 0 {
		// The caller's buffer was too small: the session exists but has no
		// handle yet, so wipe it instead of leaking it to the GC (audit F-13).
		s.Zeroize()
		return 0
	}
	return C.uint64_t(sessions.add(s))
}

// quietly_session_respond establishes the responder side of a session from the
// caller's identity, its signed prekey, an optional one-time prekey, and the
// received initial message. The first message's plaintext is written to out.
// Returns 0 on error.
//
//export quietly_session_respond
func quietly_session_respond(
	ikDHPriv, ikDHPub, ikSigPub, ikSigPriv *C.uchar,
	spkPriv, spkPub, otpkPriv, otpkPub *C.uchar,
	initial *C.uchar, initialLen C.int,
	out *C.uchar, outCap C.int, outLen *C.int,
) C.uint64_t {
	ik := &protocol.IdentityKeys{
		DHPriv:  mustIn(ikDHPriv, 32),
		DHPub:   mustIn(ikDHPub, 32),
		SigPub:  mustIn(ikSigPub, 32),
		SigPriv: mustIn(ikSigPriv, 64),
	}
	spkPrivB := mustIn(spkPriv, 32)
	spkPubB := mustIn(spkPub, 32)
	if ik.DHPriv == nil || spkPrivB == nil || spkPubB == nil {
		return 0
	}
	spk := &cryptocore.PreKey{PublicKey: spkPubB, PrivateKey: spkPrivB}

	var otpk *cryptocore.PreKey
	if otpkPrivB := mustIn(otpkPriv, 32); otpkPrivB != nil {
		otpk = &cryptocore.PreKey{
			PublicKey:  mustIn(otpkPub, 32),
			PrivateKey: otpkPrivB,
		}
	}

	msgBytes, ok := copyIn(initial, int(initialLen))
	if !ok {
		return 0
	}

	s, pt, err := responderSession(ik, spk, otpk, msgBytes)
	if err != nil {
		return 0
	}
	if writeOut(out, outCap, outLen, pt) != 0 {
		s.Zeroize()
		return 0
	}
	return C.uint64_t(sessions.add(s))
}

// quietly_session_encrypt encrypts a plaintext under the session, returning the
// full normal-message wire bytes (version || type || header || ciphertext).
//
//export quietly_session_encrypt
func quietly_session_encrypt(handle C.uint64_t, plaintext *C.uchar, plaintextLen C.int, out *C.uchar, outCap C.int, outLen *C.int) C.int {
	s := sessions.get(uint64(handle))
	if s == nil {
		return -1
	}
	pt, ok := copyIn(plaintext, int(plaintextLen))
	if !ok {
		return -1
	}
	h, ct, err := s.Encrypt(pt)
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, protocol.EncodeNormalMessage(h, ct))
}

// quietly_session_decrypt decrypts a normal-message wire frame (as produced by
// quietly_session_encrypt), returning the plaintext.
//
//export quietly_session_decrypt
func quietly_session_decrypt(handle C.uint64_t, msg *C.uchar, msgLen C.int, out *C.uchar, outCap C.int, outLen *C.int) C.int {
	s := sessions.get(uint64(handle))
	if s == nil {
		return -1
	}
	frame, ok := copyIn(msg, int(msgLen))
	if !ok {
		return -1
	}
	m, err := protocol.DecodeNormalMessage(frame)
	if err != nil {
		return -1
	}
	pt, err := s.Decrypt(m.Header, m.Ciphertext)
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, pt)
}

// quietly_session_free releases a session handle. It is safe to call twice.
//
//export quietly_session_free
func quietly_session_free(handle C.uint64_t) {
	sessions.remove(uint64(handle))
}

// quietly_bundle_verify checks a prekey bundle's identity-binding and
// signed-prekey signatures. Returns 1 if valid, 0 if invalid.
//
//export quietly_bundle_verify
func quietly_bundle_verify(
	ikSig, ikDH, binding *C.uchar,
	spkID C.uint32_t, spk, spkSig *C.uchar,
) C.int {
	ikSigB := mustIn(ikSig, 32)
	ikDHB := mustIn(ikDH, 32)
	bindingB := mustIn(binding, 64)
	spkB := mustIn(spk, 32)
	spkSigB := mustIn(spkSig, 64)
	if ikSigB == nil || ikDHB == nil || bindingB == nil || spkB == nil || spkSigB == nil {
		return 0
	}
	if !protocol.VerifyIdentityBinding(ikSigB, ikDHB, bindingB) {
		return 0
	}
	if !protocol.VerifySignedPreKey(ikSigB, uint32(spkID), spkB, spkSigB) {
		return 0
	}
	return 1
}

// quietly_identity_binding_sign signs identity_key_dh with identity_key_sig,
// writing the 64-byte signature to out.
//
//export quietly_identity_binding_sign
func quietly_identity_binding_sign(sigPriv, dhPub *C.uchar, out *C.uchar) C.int {
	sigPrivB := mustIn(sigPriv, 64)
	dhPubB := mustIn(dhPub, 32)
	if sigPrivB == nil || dhPubB == nil {
		return -1
	}
	sig, err := protocol.SignIdentityBinding(sigPrivB, dhPubB)
	if err != nil {
		return -1
	}
	dst, ok := outView(out, len(sig))
	if !ok {
		return -1
	}
	copy(dst, sig)
	return 0
}

// quietly_signed_prekey_sign signs id_be32 || public_key with identity_key_sig,
// writing the 64-byte signature to out.
//
//export quietly_signed_prekey_sign
func quietly_signed_prekey_sign(sigPriv *C.uchar, spkID C.uint32_t, spkPub *C.uchar, out *C.uchar) C.int {
	sigPrivB := mustIn(sigPriv, 64)
	spkPubB := mustIn(spkPub, 32)
	if sigPrivB == nil || spkPubB == nil {
		return -1
	}
	sig, err := protocol.SignSignedPreKey(sigPrivB, uint32(spkID), spkPubB)
	if err != nil {
		return -1
	}
	dst, ok := outView(out, len(sig))
	if !ok {
		return -1
	}
	copy(dst, sig)
	return 0
}

// quietly_seal_sender seals a ratchet message for a recipient, returning the
// sealed blob.
//
//export quietly_seal_sender
func quietly_seal_sender(
	senderIKDHPriv *C.uchar,
	recipientUserID *C.uchar, recipientDeviceID C.uint16_t, recipientIKDH *C.uchar,
	senderUserID *C.uchar, senderDeviceID C.uint16_t, sessionType C.uchar, msgType C.uchar,
	inner *C.uchar, innerLen C.int,
	out *C.uchar, outCap C.int, outLen *C.int,
) C.int {
	senderIKDHPrivB := mustIn(senderIKDHPriv, 32)
	recipientUserIDB := mustIn(recipientUserID, 16)
	recipientIKDHB := mustIn(recipientIKDH, 32)
	senderUserIDB := mustIn(senderUserID, 16)
	innerB, ok := copyIn(inner, int(innerLen))
	if senderIKDHPrivB == nil || recipientUserIDB == nil || recipientIKDHB == nil || senderUserIDB == nil || !ok {
		return -1
	}

	payload := protocol.SealedPayload{
		SenderUserID:   fixed16(senderUserIDB),
		SenderDeviceID: uint16(senderDeviceID),
		SessionType:    byte(sessionType),
		MsgType:        byte(msgType),
		Inner:          innerB,
	}
	recipient := protocol.UserDevice{
		UserID:   fixed16(recipientUserIDB),
		DeviceID: uint16(recipientDeviceID),
	}

	blob, err := protocol.SealSealedSender(senderIKDHPrivB, recipient, recipientIKDHB, payload)
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, protocol.EncodeSealedBlob(blob))
}

// quietly_open_sender opens a sealed blob, returning the sender identity and
// the inner ratchet message bytes.
//
//export quietly_open_sender
func quietly_open_sender(
	recipientIKDHPriv *C.uchar,
	recipientUserID *C.uchar, recipientDeviceID C.uint16_t,
	blob *C.uchar, blobLen C.int,
	outSenderUserID *C.uchar, outSenderDeviceID *C.uint16_t, outSessionType *C.uchar, outMsgType *C.uchar,
	outInner *C.uchar, outCap C.int, outLen *C.int,
) C.int {
	recipientIKDHPrivB := mustIn(recipientIKDHPriv, 32)
	recipientUserIDB := mustIn(recipientUserID, 16)
	blobB, ok := copyIn(blob, int(blobLen))
	if recipientIKDHPrivB == nil || recipientUserIDB == nil || !ok {
		return -1
	}

	recipient := protocol.UserDevice{
		UserID:   fixed16(recipientUserIDB),
		DeviceID: uint16(recipientDeviceID),
	}
	b, err := protocol.DecodeSealedBlob(blobB)
	if err != nil {
		return -1
	}
	payload, err := protocol.OpenSealedSender(recipientIKDHPrivB, recipient, b)
	if err != nil {
		return -1
	}

	if outSenderUserID == nil || outSenderDeviceID == nil || outSessionType == nil || outMsgType == nil {
		return -1
	}
	senderUID, ok := outView(outSenderUserID, 16)
	if !ok {
		return -1
	}
	copy(senderUID, payload.SenderUserID[:])
	*outSenderDeviceID = C.uint16_t(payload.SenderDeviceID)
	*outSessionType = C.uchar(payload.SessionType)
	*outMsgType = C.uchar(payload.MsgType)

	return writeOut(outInner, outCap, outLen, payload.Inner)
}

// quietly_safety_number computes the combined, order-independent safety number
// of two parties as an ASCII string.
//
//export quietly_safety_number
func quietly_safety_number(
	userIDa, ikDHa, ikSiga, userIDb, ikDHb, ikSigb *C.uchar,
	out *C.uchar, outCap C.int, outLen *C.int,
) C.int {
	uA := mustIn(userIDa, 16)
	dhA := mustIn(ikDHa, 32)
	sigA := mustIn(ikSiga, 32)
	uB := mustIn(userIDb, 16)
	dhB := mustIn(ikDHb, 32)
	sigB := mustIn(ikSigb, 32)
	if uA == nil || dhA == nil || sigA == nil || uB == nil || dhB == nil || sigB == nil {
		return -1
	}
	fpA := safety.Fingerprint(fixed16(uA), dhA, sigA)
	fpB := safety.Fingerprint(fixed16(uB), dhB, sigB)
	s, err := safety.SafetyNumber(fpA[:], fpB[:])
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, []byte(s))
}

// quietly_pow_verify verifies an account-creation proof of work. Returns 1 if
// valid, 0 if not.
//
//export quietly_pow_verify
func quietly_pow_verify(username *C.uchar, usernameLen C.int, timestampMS C.int64_t, nonce C.uint64_t, difficulty C.int) C.int {
	u, ok := copyIn(username, int(usernameLen))
	if !ok {
		return 0
	}
	if pow.Verify(string(u), int64(timestampMS), uint64(nonce), int(difficulty)) {
		return 1
	}
	return 0
}

// quietly_aead_seal_random encrypts with XChaCha20-Poly1305 using a fresh
// random nonce, returning nonce || ciphertext. This is the safe default for a
// caller that does not manage nonces itself.
//
//export quietly_aead_seal_random
func quietly_aead_seal_random(key32, plaintext *C.uchar, plaintextLen C.int, aad *C.uchar, aadLen C.int, out *C.uchar, outCap C.int, outLen *C.int) C.int {
	key, ok := copyIn(key32, cryptocore.AEADKeySize)
	if !ok {
		return -1
	}
	pt, ok := copyIn(plaintext, int(plaintextLen))
	if !ok {
		return -1
	}
	aa, ok := copyIn(aad, int(aadLen))
	if !ok {
		return -1
	}
	sealed, err := cryptocore.Encrypt(key, pt, aa)
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, sealed)
}

// quietly_aead_open_random decrypts the output of quietly_aead_seal_random.
//
//export quietly_aead_open_random
func quietly_aead_open_random(key32, sealed *C.uchar, sealedLen C.int, aad *C.uchar, aadLen C.int, out *C.uchar, outCap C.int, outLen *C.int) C.int {
	key, ok := copyIn(key32, cryptocore.AEADKeySize)
	if !ok {
		return -1
	}
	sealedB, ok := copyIn(sealed, int(sealedLen))
	if !ok {
		return -1
	}
	aa, ok := copyIn(aad, int(aadLen))
	if !ok {
		return -1
	}
	pt, err := cryptocore.Decrypt(key, sealedB, aa)
	if err != nil {
		return -1
	}
	return writeOut(out, outCap, outLen, pt)
}

// mustIn reads exactly n bytes from p, returning nil on any error (including
// a nil pointer when n > 0).
func mustIn(p *C.uchar, n int) []byte {
	b, ok := copyIn(p, n)
	if !ok {
		return nil
	}
	return b
}
