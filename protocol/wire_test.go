package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestConstants(t *testing.T) {
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"Version", Version, "quietly/1"},
		{"VersionByte", VersionByte, 1},
		{"HeaderSize", HeaderSize, 40},
		{"NormalMessageHeaderSize", NormalMessageHeaderSize, 42},
		{"InitialMessageHeaderSize", InitialMessageHeaderSize, 146},
		{"SealedPayloadPrefixSize", SealedPayloadPrefixSize, 41},
		{"SealedBlobPrefixSize", SealedBlobPrefixSize, 57},
		{"RatchetNonceSize", RatchetNonceSize, 12},
		{"SealedNonceSize", SealedNonceSize, 24},
		{"TagSize", TagSize, 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestDomainSeparate(t *testing.T) {
	got := DomainSeparate("quietly/1 x3dh", []byte{1, 2, 3})
	want := []byte("quietly/1 x3dh\x00\x01\x02\x03")
	if !bytes.Equal(got, want) {
		t.Fatalf("DomainSeparate = %x, want %x", got, want)
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	var pk [X25519KeySize]byte
	for i := range pk {
		pk[i] = byte(i)
	}
	in := Header{RatchetPublicKey: pk, PN: 0x11223344, N: 0xaabbccdd}

	enc := in.Encode(nil)
	if len(enc) != HeaderSize {
		t.Fatalf("encoded header length = %d, want %d", len(enc), HeaderSize)
	}
	out, err := DecodeHeader(enc)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v != %+v", out, in)
	}

	// Independent offset check against §9.2.
	if binary.BigEndian.Uint32(enc[32:36]) != in.PN {
		t.Errorf("pn offset wrong")
	}
	if binary.BigEndian.Uint32(enc[36:40]) != in.N {
		t.Errorf("n offset wrong")
	}

	if _, err := DecodeHeader(enc[:HeaderSize-1]); err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestNormalMessageRoundTrip(t *testing.T) {
	var pk [X25519KeySize]byte
	pk[0] = 0x7f
	h := Header{RatchetPublicKey: pk, PN: 2, N: 9}
	ct := []byte("ciphertext-with-tag")
	enc := EncodeNormalMessage(h, ct)
	if len(enc) != NormalMessageHeaderSize+len(ct) {
		t.Fatalf("encoded length = %d", len(enc))
	}
	if enc[0] != VersionByte || enc[1] != MsgTypeNormal {
		t.Fatalf("bad version/type prefix: %x", enc[:2])
	}
	out, err := DecodeNormalMessage(enc)
	if err != nil {
		t.Fatalf("DecodeNormalMessage: %v", err)
	}
	if out.Header != h || !bytes.Equal(out.Ciphertext, ct) {
		t.Fatalf("round trip mismatch")
	}

	bad := append([]byte(nil), enc...)
	bad[1] = MsgTypeInitial
	if _, err := DecodeNormalMessage(bad); err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestInitialMessageOffsetsAndRoundTrip(t *testing.T) {
	var ikdh, iksig, ek [32]byte
	for i := range ikdh {
		ikdh[i] = byte(i + 1)
	}
	for i := range iksig {
		iksig[i] = 0xaa
	}
	for i := range ek {
		ek[i] = 0xbb
	}
	var pk [X25519KeySize]byte
	pk[0] = 0xcc
	ct := bytes.Repeat([]byte{0xdd}, TagSize) // at least a full tag
	in := InitialMessage{
		IdentityKeyDH:   ikdh,
		IdentityKeySig:  iksig,
		EphemeralKey:    ek,
		SignedPreKeyID:  42,
		OneTimePreKeyID: 7,
		Header:          Header{RatchetPublicKey: pk, PN: 1, N: 3},
		Ciphertext:      ct,
	}

	enc := EncodeInitialMessage(in)
	if len(enc) != InitialMessageHeaderSize+len(in.Ciphertext) {
		t.Fatalf("encoded length = %d", len(enc))
	}

	// Independent offset checks against §9.2.
	if enc[0] != VersionByte || enc[1] != MsgTypeInitial {
		t.Fatalf("bad version/type prefix")
	}
	if enc[2] != 0x01 || enc[33] != 0x20 { // IK_A_dh spans [2,34); last byte = 32
		t.Fatalf("IK_A_dh offset wrong")
	}
	if enc[34] != 0xaa || enc[65] != 0xaa { // IK_A_sig spans [34,66)
		t.Fatalf("IK_A_sig offset wrong")
	}
	if enc[66] != 0xbb || enc[97] != 0xbb { // EK_A spans [66,98)
		t.Fatalf("EK_A offset wrong")
	}
	if binary.BigEndian.Uint32(enc[98:102]) != 42 {
		t.Fatalf("spk_id offset wrong")
	}
	if binary.BigEndian.Uint32(enc[102:106]) != 7 {
		t.Fatalf("otpk_id offset wrong")
	}

	out, err := DecodeInitialMessage(enc)
	if err != nil {
		t.Fatalf("DecodeInitialMessage: %v", err)
	}
	if out.IdentityKeyDH != in.IdentityKeyDH || out.IdentityKeySig != in.IdentityKeySig ||
		out.EphemeralKey != in.EphemeralKey || out.SignedPreKeyID != in.SignedPreKeyID ||
		out.OneTimePreKeyID != in.OneTimePreKeyID || out.Header != in.Header ||
		!bytes.Equal(out.Ciphertext, in.Ciphertext) {
		t.Fatalf("round trip mismatch")
	}

	if _, err := DecodeInitialMessage(enc[:InitialMessageHeaderSize-1]); err == nil {
		t.Fatal("expected error for short initial message")
	}
}

func TestSealedPayloadRoundTrip(t *testing.T) {
	var uid [UUIDSize]byte
	uid[0] = 0x01
	var gid [GroupIDSize]byte
	in := SealedPayload{
		SenderUserID:   uid,
		SenderDeviceID: 0x0203,
		SessionType:    SessionTypePairwise,
		GroupID:        gid,
		MsgType:        MsgTypeNormal,
		Inner:          []byte{9, 8, 7},
	}
	enc := EncodeSealedPayload(in)
	if len(enc) != SealedPayloadPrefixSize+len(in.Inner) {
		t.Fatalf("encoded length = %d", len(enc))
	}
	if binary.BigEndian.Uint16(enc[17:19]) != 0x0203 {
		t.Fatalf("sender_device_id offset wrong")
	}
	if binary.BigEndian.Uint32(enc[37:41]) != 3 {
		t.Fatalf("inner_len offset wrong")
	}

	out, err := DecodeSealedPayload(enc)
	if err != nil {
		t.Fatalf("DecodeSealedPayload: %v", err)
	}
	if out.SenderUserID != in.SenderUserID || out.SenderDeviceID != in.SenderDeviceID ||
		out.SessionType != in.SessionType || out.GroupID != in.GroupID ||
		out.MsgType != in.MsgType || !bytes.Equal(out.Inner, in.Inner) {
		t.Fatalf("round trip mismatch")
	}
}

func TestSealedPayloadRejectsInnerLenMismatch(t *testing.T) {
	enc := EncodeSealedPayload(SealedPayload{Inner: []byte{1, 2, 3}})
	// Truncate the inner bytes so inner_len no longer matches.
	if _, err := DecodeSealedPayload(enc[:len(enc)-1]); err == nil {
		t.Fatal("expected error for inner_len mismatch")
	}
	if _, err := DecodeSealedPayload(enc[:SealedPayloadPrefixSize-1]); err == nil {
		t.Fatal("expected error for short sealed payload")
	}
}

func TestDecodeSealedPayloadRejectsInvalidEnum(t *testing.T) {
	enc := EncodeSealedPayload(SealedPayload{
		SessionType: SessionTypePairwise,
		MsgType:     MsgTypeNormal,
		Inner:       []byte("x"),
	})

	badSession := append([]byte(nil), enc...)
	badSession[19] = 0xff
	if _, err := DecodeSealedPayload(badSession); err == nil {
		t.Fatal("invalid session type accepted")
	}

	badMsg := append([]byte(nil), enc...)
	badMsg[36] = 0xff
	if _, err := DecodeSealedPayload(badMsg); err == nil {
		t.Fatal("invalid message type accepted")
	}
}

func TestSealedBlobRoundTrip(t *testing.T) {
	var epk [X25519KeySize]byte
	epk[0] = 0x01
	var nonce [SealedNonceSize]byte
	nonce[23] = 0xff
	in := SealedBlob{
		EphemeralPublicKey: epk,
		Nonce:              nonce,
		Ciphertext:         []byte("tagged-ciphertext"),
	}
	enc := EncodeSealedBlob(in)
	if len(enc) != SealedBlobPrefixSize+len(in.Ciphertext) {
		t.Fatalf("encoded length = %d", len(enc))
	}
	if enc[0] != VersionByte || enc[1] != 0x01 || enc[32] != 0x00 {
		t.Fatalf("E_pub offset wrong")
	}
	out, err := DecodeSealedBlob(enc)
	if err != nil {
		t.Fatalf("DecodeSealedBlob: %v", err)
	}
	if out.EphemeralPublicKey != in.EphemeralPublicKey || out.Nonce != in.Nonce ||
		!bytes.Equal(out.Ciphertext, in.Ciphertext) {
		t.Fatalf("round trip mismatch")
	}

	// A sealed blob must be at least prefix + tag.
	if _, err := DecodeSealedBlob(enc[:SealedBlobPrefixSize+TagSize-1]); err == nil {
		t.Fatal("expected error for short sealed blob")
	}
}

func TestRejectsWrongVersion(t *testing.T) {
	var pk [X25519KeySize]byte
	h := Header{RatchetPublicKey: pk}
	normal := EncodeNormalMessage(h, []byte("x"))
	normal[0] = 0x02
	if _, err := DecodeNormalMessage(normal); err == nil {
		t.Fatal("expected error for wrong version")
	}
}
