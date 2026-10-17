package protocol

import (
	"bytes"
	"fmt"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// Ratchet limits (PROTOCOL.md §9.4, §15).
const (
	maxSkipPerChain  = 1000
	maxSkippedChains = 5
)

// skippedKey identifies a skipped message key by its chain (the remote ratchet
// public key) and message number.
type skippedKey struct {
	chain [X25519KeySize]byte
	n     uint32
}

// Session is a Double Ratchet session between two devices (PROTOCOL.md §9).
// It holds the root key, the ratchet keypairs, the sending and receiving chain
// keys, and any skipped message keys for out-of-order delivery.
type Session struct {
	ad []byte // 128-byte associated data (§8.2)

	rk  []byte             // root key (32 bytes)
	dhs *cryptocore.PreKey // our current ratchet keypair
	dhr []byte             // remote ratchet public key (nil until first received)
	cks []byte             // sending chain key
	ckr []byte             // receiving chain key
	ns  uint32             // messages sent in current chain
	nr  uint32             // messages received in current chain
	pn  uint32             // length of previous sending chain

	skipped    map[skippedKey][]byte // n -> derived key||nonce (44 bytes)
	chainOrder [][X25519KeySize]byte // chains with skipped keys, oldest first
}

// NewInitiatorSession establishes the initiator's side of a session from the
// X3DH shared secret. spkBPub is the responder's signed prekey public key,
// against which the initiator performs its first DH ratchet step (§8.4).
func NewInitiatorSession(sk, ad, spkBPub []byte) (*Session, error) {
	if len(sk) != 32 || len(ad) != 128 || len(spkBPub) != 32 {
		return nil, fmt.Errorf("initiator session: sk, ad, and spk must be 32, 128, and 32 bytes")
	}
	ra, err := cryptocore.GeneratePreKey()
	if err != nil {
		return nil, err
	}
	s := &Session{
		ad:      append([]byte(nil), ad...),
		rk:      append([]byte(nil), sk...),
		dhs:     ra,
		dhr:     append([]byte(nil), spkBPub...),
		skipped: make(map[skippedKey][]byte),
	}
	dh, err := cryptocore.X25519(ra.PrivateKey, spkBPub)
	if err != nil {
		return nil, err
	}
	defer zeroize(dh)
	s.rk, s.cks, err = kdfRoot(s.rk, dh)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// NewResponderSession establishes the responder's side of a session. The
// responder's signed prekey doubles as its initial ratchet keypair (§8.4);
// the first received message triggers the DH ratchet step.
func NewResponderSession(sk, ad []byte, spk *cryptocore.PreKey) (*Session, error) {
	if len(sk) != 32 || len(ad) != 128 {
		return nil, fmt.Errorf("responder session: sk and ad must be 32 and 128 bytes")
	}
	if spk == nil || len(spk.PrivateKey) != 32 {
		return nil, fmt.Errorf("responder session: signed prekey must be 32 bytes")
	}
	return &Session{
		ad:      append([]byte(nil), ad...),
		rk:      append([]byte(nil), sk...),
		dhs:     spk,
		dhr:     nil,
		skipped: make(map[skippedKey][]byte),
	}, nil
}

// Encrypt encrypts a plaintext under the current sending chain, advancing the
// chain. It returns the ratchet header and the ciphertext (including tag).
func (s *Session) Encrypt(plaintext []byte) (Header, []byte, error) {
	mk, nextCk := kdfChain(s.cks)
	s.cks = nextCk

	var pub [X25519KeySize]byte
	copy(pub[:], s.dhs.PublicKey)
	h := Header{RatchetPublicKey: pub, PN: s.pn, N: s.ns}
	s.ns++

	key, nonce, err := messageKey(mk)
	if err != nil {
		return Header{}, nil, err
	}
	defer zeroize(mk)

	ct, err := cryptocore.SealChaCha(key, nonce, plaintext, s.aadFor(h))
	if err != nil {
		return Header{}, nil, err
	}
	return h, ct, nil
}

// Decrypt decrypts a message given its header and ciphertext, handling
// out-of-order delivery via skipped message keys (§9.4). Per §9.3, a failed
// decryption MUST NOT advance any ratchet state, so the operation is performed
// on a snapshot that is only committed on success.
func (s *Session) Decrypt(h Header, ciphertext []byte) ([]byte, error) {
	snapshot := s.clone()
	pt, err := s.decrypt(h, ciphertext)
	if err != nil {
		*s = *snapshot
		return nil, err
	}
	return pt, nil
}

func (s *Session) decrypt(h Header, ciphertext []byte) ([]byte, error) {
	if pt, ok := s.trySkipped(h, ciphertext); ok {
		return pt, nil
	}

	if !bytes.Equal(h.RatchetPublicKey[:], s.dhr) {
		if err := s.skipMessageKeys(h.PN); err != nil {
			return nil, err
		}
		if err := s.dhRatchet(h); err != nil {
			return nil, err
		}
	}
	if err := s.skipMessageKeys(h.N); err != nil {
		return nil, err
	}

	mk, nextCk := kdfChain(s.ckr)
	s.ckr = nextCk
	s.nr++

	key, nonce, err := messageKey(mk)
	if err != nil {
		return nil, err
	}
	defer zeroize(mk)

	return cryptocore.OpenChaCha(key, nonce, ciphertext, s.aadFor(h))
}

// clone returns a deep copy of the session's mutable state.
func (s *Session) clone() *Session {
	c := &Session{
		ad:  append([]byte(nil), s.ad...),
		rk:  append([]byte(nil), s.rk...),
		dhr: append([]byte(nil), s.dhr...),
		cks: append([]byte(nil), s.cks...),
		ckr: append([]byte(nil), s.ckr...),
		ns:  s.ns,
		nr:  s.nr,
		pn:  s.pn,

		skipped:    make(map[skippedKey][]byte, len(s.skipped)),
		chainOrder: append([][X25519KeySize]byte(nil), s.chainOrder...),
	}
	if s.dhs != nil {
		c.dhs = &cryptocore.PreKey{
			PublicKey:  append([]byte(nil), s.dhs.PublicKey...),
			PrivateKey: append([]byte(nil), s.dhs.PrivateKey...),
		}
	}
	for k, v := range s.skipped {
		c.skipped[k] = append([]byte(nil), v...)
	}
	return c
}

// dhRatchet performs a DH ratchet step on receipt of a new remote ratchet key
// (§9.1): it derives the receiving chain from the old ratchet keypair, then
// generates a fresh ratchet keypair and derives the sending chain from it.
func (s *Session) dhRatchet(h Header) error {
	s.pn = s.ns
	s.ns = 0
	s.nr = 0
	s.dhr = append([]byte(nil), h.RatchetPublicKey[:]...)

	dh, err := cryptocore.X25519(s.dhs.PrivateKey, s.dhr)
	if err != nil {
		return err
	}
	s.rk, s.ckr, err = kdfRoot(s.rk, dh)
	zeroize(dh)
	if err != nil {
		return err
	}

	newDH, err := cryptocore.GeneratePreKey()
	if err != nil {
		return err
	}
	s.dhs = newDH

	dh, err = cryptocore.X25519(newDH.PrivateKey, s.dhr)
	if err != nil {
		return err
	}
	s.rk, s.cks, err = kdfRoot(s.rk, dh)
	zeroize(dh)
	if err != nil {
		return err
	}

	s.chainOrder = append(s.chainOrder, toArray32(s.dhr))
	if len(s.chainOrder) > maxSkippedChains {
		oldest := s.chainOrder[0]
		s.chainOrder = s.chainOrder[1:]
		for k := range s.skipped {
			if k.chain == oldest {
				delete(s.skipped, k)
			}
		}
	}
	return nil
}

// skipMessageKeys derives and stores the message keys from the current
// receiving position up to (but not including) `until`, enforcing the
// max-skip-per-chain limit (§9.4).
func (s *Session) skipMessageKeys(until uint32) error {
	if until <= s.nr {
		return nil
	}
	if until-s.nr > maxSkipPerChain {
		return fmt.Errorf("ratchet: skip limit exceeded (%d > %d)", until-s.nr, maxSkipPerChain)
	}
	for s.nr < until {
		mk, nextCk := kdfChain(s.ckr)
		s.ckr = nextCk
		key, nonce, err := messageKey(mk)
		zeroize(mk)
		if err != nil {
			return err
		}
		s.skipped[skippedKey{chain: toArray32(s.dhr), n: s.nr}] = append(key, nonce...)
		s.nr++
	}
	return nil
}

// trySkipped attempts to decrypt using a previously skipped message key. It
// reports whether a matching key existed (and consumed it if so).
func (s *Session) trySkipped(h Header, ciphertext []byte) ([]byte, bool) {
	key := skippedKey{chain: h.RatchetPublicKey, n: h.N}
	mk, ok := s.skipped[key]
	if !ok {
		return nil, false
	}
	delete(s.skipped, key)
	pt, err := cryptocore.OpenChaCha(mk[:32], mk[32:], ciphertext, s.aadFor(h))
	if err != nil {
		return nil, false
	}
	return pt, true
}

// aadFor returns AD || header_bytes (§9.3).
func (s *Session) aadFor(h Header) []byte {
	aad := make([]byte, 0, len(s.ad)+HeaderSize)
	aad = append(aad, s.ad...)
	return h.Encode(aad)
}

// kdfRoot derives rk_new || ck_new = HKDF-SHA256(ikm=dhOut, salt=rk,
// info="quietly/1 ratchet-root", len=64) (§9.1).
func kdfRoot(rk, dhOut []byte) ([]byte, []byte, error) {
	okm, err := cryptocore.HKDFSHA256(dhOut, rk, []byte(DomainRatchetRoot), 64)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}

// kdfChain derives mk = HMAC-SHA256(ck, 0x01) and ck_next = HMAC-SHA256(ck,
// 0x02) (§9.1).
func kdfChain(ck []byte) (mk, nextCk []byte) {
	mk = cryptocore.HMACSHA256(ck, []byte{0x01})
	nextCk = cryptocore.HMACSHA256(ck, []byte{0x02})
	return mk, nextCk
}

// messageKey expands mk into key || nonce = HKDF-SHA256(ikm=mk, salt=32 zero,
// info="quietly/1 ratchet-msg", len=44) (§9.1).
func messageKey(mk []byte) (key, nonce []byte, err error) {
	okm, err := cryptocore.HKDFSHA256(mk, make([]byte, 32), []byte(DomainRatchetMessage), 44)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}

func toArray32(b []byte) [X25519KeySize]byte {
	var a [X25519KeySize]byte
	copy(a[:], b)
	return a
}
