package protocol

import (
	"encoding/binary"
	"fmt"
)

// Header is the 40-byte Double Ratchet header (§9.2):
//
//	offset  size  field
//	0       32    ratchet_public_key      X25519
//	32      4     pn                      previous chain length, u32 BE
//	36      4     n                       message number in chain, u32 BE
type Header struct {
	RatchetPublicKey [X25519KeySize]byte
	PN               uint32
	N                uint32
}

// Encode appends the header's 40 bytes to dst.
func (h Header) Encode(dst []byte) []byte {
	dst = append(dst, h.RatchetPublicKey[:]...)
	dst = binary.BigEndian.AppendUint32(dst, h.PN)
	dst = binary.BigEndian.AppendUint32(dst, h.N)
	return dst
}

// DecodeHeader parses exactly HeaderSize bytes.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, errTooShort("ratchet header", HeaderSize, len(b))
	}
	var h Header
	copy(h.RatchetPublicKey[:], b[0:32])
	h.PN = binary.BigEndian.Uint32(b[32:36])
	h.N = binary.BigEndian.Uint32(b[36:40])
	return h, nil
}

// NormalMessage is a ratchet message in an established session (§9.2).
//
//	version(1) | type(1) | header(40) | ciphertext(var, includes 16-byte tag)
type NormalMessage struct {
	Header     Header
	Ciphertext []byte
}

// EncodeNormalMessage serializes a normal message to its wire form.
func EncodeNormalMessage(h Header, ciphertext []byte) []byte {
	buf := make([]byte, 0, NormalMessageHeaderSize+len(ciphertext))
	buf = append(buf, VersionByte, MsgTypeNormal)
	buf = h.Encode(buf)
	buf = append(buf, ciphertext...)
	return buf
}

// DecodeNormalMessage parses a normal message, rejecting a short buffer, a
// wrong version byte, or a wrong type byte.
func DecodeNormalMessage(b []byte) (NormalMessage, error) {
	if len(b) < NormalMessageHeaderSize {
		return NormalMessage{}, errTooShort("normal message", NormalMessageHeaderSize, len(b))
	}
	if b[0] != VersionByte {
		return NormalMessage{}, errVersion(b[0])
	}
	if b[1] != MsgTypeNormal {
		return NormalMessage{}, fmt.Errorf("normal message: unexpected type 0x%02x", b[1])
	}
	h, err := DecodeHeader(b[2:NormalMessageHeaderSize])
	if err != nil {
		return NormalMessage{}, err
	}
	return NormalMessage{Header: h, Ciphertext: b[NormalMessageHeaderSize:]}, nil
}

// InitialMessage is the X3DH initial message (§9.2):
//
//	version(1) | type(1) | IK_A_dh(32) | IK_A_sig(32) | EK_A(32) |
//	spk_id(4)  | otpk_id(4) | header(40) | ciphertext(var)
type InitialMessage struct {
	IdentityKeyDH   [X25519KeySize]byte // IK_A_dh
	IdentityKeySig  [32]byte            // IK_A_sig (Ed25519 public key)
	EphemeralKey    [X25519KeySize]byte // EK_A
	SignedPreKeyID  uint32
	OneTimePreKeyID uint32 // 0 = no one-time prekey used
	Header          Header
	Ciphertext      []byte
}

// EncodeInitialMessage serializes an initial message to its wire form.
func EncodeInitialMessage(m InitialMessage) []byte {
	buf := make([]byte, 0, InitialMessageHeaderSize+len(m.Ciphertext))
	buf = append(buf, VersionByte, MsgTypeInitial)
	buf = append(buf, m.IdentityKeyDH[:]...)
	buf = append(buf, m.IdentityKeySig[:]...)
	buf = append(buf, m.EphemeralKey[:]...)
	buf = binary.BigEndian.AppendUint32(buf, m.SignedPreKeyID)
	buf = binary.BigEndian.AppendUint32(buf, m.OneTimePreKeyID)
	buf = m.Header.Encode(buf)
	buf = append(buf, m.Ciphertext...)
	return buf
}

// DecodeInitialMessage parses an initial message with strict bounds checks.
func DecodeInitialMessage(b []byte) (InitialMessage, error) {
	if len(b) < InitialMessageHeaderSize {
		return InitialMessage{}, errTooShort("initial message", InitialMessageHeaderSize, len(b))
	}
	if b[0] != VersionByte {
		return InitialMessage{}, errVersion(b[0])
	}
	if b[1] != MsgTypeInitial {
		return InitialMessage{}, fmt.Errorf("initial message: unexpected type 0x%02x", b[1])
	}
	var m InitialMessage
	copy(m.IdentityKeyDH[:], b[2:34])
	copy(m.IdentityKeySig[:], b[34:66])
	copy(m.EphemeralKey[:], b[66:98])
	m.SignedPreKeyID = binary.BigEndian.Uint32(b[98:102])
	m.OneTimePreKeyID = binary.BigEndian.Uint32(b[102:106])
	h, err := DecodeHeader(b[106:146])
	if err != nil {
		return InitialMessage{}, err
	}
	m.Header = h
	m.Ciphertext = b[146:]
	return m, nil
}

// SealedPayload is the sender-revealing layer inside the sealed blob (§10.2).
// The fixed 41-byte prefix:
//
//	version(1) | sender_user_id(16) | sender_device_id(2) | session_type(1) |
//	group_id(16) | msg_type(1) | inner_len(4)
type SealedPayload struct {
	SenderUserID   [UUIDSize]byte // raw UUID bytes
	SenderDeviceID uint16
	SessionType    byte // SessionTypePairwise or SessionTypeGroup
	GroupID        [GroupIDSize]byte
	MsgType        byte // MsgTypeInitial or MsgTypeNormal
	Inner          []byte
}

// EncodeSealedPayload serializes a sealed payload to its wire form.
func EncodeSealedPayload(p SealedPayload) []byte {
	buf := make([]byte, 0, SealedPayloadPrefixSize+len(p.Inner))
	buf = append(buf, VersionByte)
	buf = append(buf, p.SenderUserID[:]...)
	buf = binary.BigEndian.AppendUint16(buf, p.SenderDeviceID)
	buf = append(buf, p.SessionType)
	buf = append(buf, p.GroupID[:]...)
	buf = append(buf, p.MsgType)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(p.Inner)))
	buf = append(buf, p.Inner...)
	return buf
}

// DecodeSealedPayload parses a sealed payload. Per §10.2 it is discarded
// without further parsing if shorter than 41 bytes or if inner_len disagrees
// with the remaining length.
func DecodeSealedPayload(b []byte) (SealedPayload, error) {
	if len(b) < SealedPayloadPrefixSize {
		return SealedPayload{}, errTooShort("sealed payload", SealedPayloadPrefixSize, len(b))
	}
	if b[0] != VersionByte {
		return SealedPayload{}, errVersion(b[0])
	}
	var p SealedPayload
	copy(p.SenderUserID[:], b[1:17])
	p.SenderDeviceID = binary.BigEndian.Uint16(b[17:19])
	p.SessionType = b[19]
	copy(p.GroupID[:], b[20:36])
	p.MsgType = b[36]
	innerLen := binary.BigEndian.Uint32(b[37:41])
	if uint64(innerLen) != uint64(len(b)-SealedPayloadPrefixSize) {
		return SealedPayload{}, fmt.Errorf(
			"sealed payload: inner_len %d does not match remaining %d bytes",
			innerLen, len(b)-SealedPayloadPrefixSize)
	}
	p.Inner = b[SealedPayloadPrefixSize:]
	return p, nil
}

// SealedBlob is the sealed-sender layer the server sees (§10.1):
//
//	version(1) | E_pub(32) | nonce(24) | ciphertext(var, includes 16-byte tag)
type SealedBlob struct {
	EphemeralPublicKey [X25519KeySize]byte // E_pub
	Nonce              [SealedNonceSize]byte
	Ciphertext         []byte
}

// EncodeSealedBlob serializes a sealed blob to its wire form.
func EncodeSealedBlob(b SealedBlob) []byte {
	buf := make([]byte, 0, SealedBlobPrefixSize+len(b.Ciphertext))
	buf = append(buf, VersionByte)
	buf = append(buf, b.EphemeralPublicKey[:]...)
	buf = append(buf, b.Nonce[:]...)
	buf = append(buf, b.Ciphertext...)
	return buf
}

// DecodeSealedBlob parses a sealed blob, rejecting one shorter than the fixed
// prefix plus a Poly1305 tag.
func DecodeSealedBlob(b []byte) (SealedBlob, error) {
	const min = SealedBlobPrefixSize + TagSize
	if len(b) < min {
		return SealedBlob{}, errTooShort("sealed blob", min, len(b))
	}
	if b[0] != VersionByte {
		return SealedBlob{}, errVersion(b[0])
	}
	var s SealedBlob
	copy(s.EphemeralPublicKey[:], b[1:33])
	copy(s.Nonce[:], b[33:57])
	s.Ciphertext = b[57:]
	return s, nil
}

func errTooShort(what string, want, got int) error {
	return fmt.Errorf("%s: need at least %d bytes, got %d", what, want, got)
}

func errVersion(v byte) error {
	return fmt.Errorf("unsupported version byte 0x%02x (want 0x%02x)", v, VersionByte)
}
