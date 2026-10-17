package protocol

import (
	"bytes"
	"testing"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

func testUserDevice(t *testing.T) (UserDevice, *IdentityKeys) {
	t.Helper()
	ik, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	var uid [UUIDSize]byte
	if err := cryptocore.RandomBytes(uid[:]); err != nil {
		t.Fatal(err)
	}
	return UserDevice{UserID: uid, DeviceID: 3}, ik
}

func TestSealedSenderRoundTrip(t *testing.T) {
	sender, _ := GenerateIdentityKeys()
	recipientDev, recipientIK := testUserDevice(t)

	inner := []byte("ratchet message bytes")
	var senderUID [UUIDSize]byte
	copy(senderUID[:], []byte("sender-user"))

	payload := SealedPayload{
		SenderUserID:   senderUID,
		SenderDeviceID: 1,
		SessionType:    SessionTypePairwise,
		MsgType:        MsgTypeNormal,
		Inner:          inner,
	}

	blob, err := SealSealedSender(sender.DHPriv, recipientDev, recipientIK.DHPub, payload)
	if err != nil {
		t.Fatalf("SealSealedSender: %v", err)
	}

	got, err := OpenSealedSender(recipientIK.DHPriv, recipientDev, blob)
	if err != nil {
		t.Fatalf("OpenSealedSender: %v", err)
	}
	if got.SenderUserID != payload.SenderUserID {
		t.Fatal("sender user id mismatch")
	}
	if got.SenderDeviceID != payload.SenderDeviceID {
		t.Fatal("sender device id mismatch")
	}
	if got.SessionType != payload.SessionType || got.MsgType != payload.MsgType {
		t.Fatal("session/msg type mismatch")
	}
	if !bytes.Equal(got.Inner, inner) {
		t.Fatal("inner message mismatch")
	}
}

func TestSealedSenderRejectsTampering(t *testing.T) {
	sender, _ := GenerateIdentityKeys()
	recipientDev, recipientIK := testUserDevice(t)

	payload := SealedPayload{SenderDeviceID: 1, MsgType: MsgTypeNormal, Inner: []byte("inner")}
	blob, err := SealSealedSender(sender.DHPriv, recipientDev, recipientIK.DHPub, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the ciphertext.
	tampered := blob
	tampered.Ciphertext = append([]byte(nil), blob.Ciphertext...)
	tampered.Ciphertext[0] ^= 0x01
	if _, err := OpenSealedSender(recipientIK.DHPriv, recipientDev, tampered); err == nil {
		t.Fatal("tampered sealed blob opened")
	}

	// Wrong recipient private key.
	_, otherIK := testUserDevice(t)
	if _, err := OpenSealedSender(otherIK.DHPriv, recipientDev, blob); err == nil {
		t.Fatal("sealed blob opened under the wrong recipient key")
	}

	// Wrong recipient device id (AAD mismatch).
	wrongDev := recipientDev
	wrongDev.DeviceID++
	if _, err := OpenSealedSender(recipientIK.DHPriv, wrongDev, blob); err == nil {
		t.Fatal("sealed blob opened under the wrong device id")
	}
}

// TestEndToEnd drives the full stack: X3DH, an initial ratchet message sealed
// to the recipient, decryption, a sealed reply, and its decryption.
func TestEndToEnd(t *testing.T) {
	ikA, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	ikB, spkB, otpkB, bundleB, err := GeneratePreKeyBundle(true)
	if err != nil {
		t.Fatal(err)
	}
	var bobUID, aliceUID [UUIDSize]byte
	cryptocore.RandomBytes(bobUID[:])
	cryptocore.RandomBytes(aliceUID[:])
	bobDev := UserDevice{UserID: bobUID, DeviceID: 1}
	aliceDev := UserDevice{UserID: aliceUID, DeviceID: 1}

	// --- Alice initiates ---
	skA, adA, ekA, err := X3DHInitiate(ikA, bundleB)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewInitiatorSession(skA, adA, bundleB.SignedPreKey)
	if err != nil {
		t.Fatal(err)
	}
	h0, c0, err := alice.Encrypt([]byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}

	// Build the initial message and seal it to Bob.
	initial := EncodeInitialMessage(InitialMessage{
		IdentityKeyDH:   toArray32(ikA.DHPub),
		IdentityKeySig:  toArray32(ikA.SigPub),
		EphemeralKey:    toArray32(ekA.PublicKey),
		SignedPreKeyID:  bundleB.SignedPreKeyID,
		OneTimePreKeyID: bundleB.OneTimePreKeyID,
		Header:          h0,
		Ciphertext:      c0,
	})
	blob0, err := SealSealedSender(ikA.DHPriv, bobDev, ikB.DHPub, SealedPayload{
		SenderUserID:   aliceUID,
		SenderDeviceID: 1,
		SessionType:    SessionTypePairwise,
		MsgType:        MsgTypeInitial,
		Inner:          initial,
	})
	if err != nil {
		t.Fatal(err)
	}

	// --- Bob opens the sealed blob and decrypts the initial message ---
	payload0, err := OpenSealedSender(ikB.DHPriv, bobDev, blob0)
	if err != nil {
		t.Fatalf("OpenSealedSender: %v", err)
	}
	if payload0.SenderUserID != aliceUID {
		t.Fatal("sender identity mismatch")
	}
	initMsg, err := DecodeInitialMessage(payload0.Inner)
	if err != nil {
		t.Fatal(err)
	}

	skB, adB, err := X3DHRespond(ikB, spkB, otpkB, initMsg.IdentityKeyDH[:], initMsg.IdentityKeySig[:], initMsg.EphemeralKey[:])
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewResponderSession(skB, adB, spkB)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bob.Decrypt(initMsg.Header, initMsg.Ciphertext)
	if err != nil {
		t.Fatalf("bob decrypt initial: %v", err)
	}
	if string(pt) != "hello bob" {
		t.Fatalf("got %q, want %q", pt, "hello bob")
	}

	// --- Bob replies with a normal message, sealed to Alice ---
	h1, c1, err := bob.Encrypt([]byte("hi alice"))
	if err != nil {
		t.Fatal(err)
	}
	normal := EncodeNormalMessage(h1, c1)
	blob1, err := SealSealedSender(ikB.DHPriv, aliceDev, ikA.DHPub, SealedPayload{
		SenderUserID:   bobUID,
		SenderDeviceID: 1,
		SessionType:    SessionTypePairwise,
		MsgType:        MsgTypeNormal,
		Inner:          normal,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload1, err := OpenSealedSender(ikA.DHPriv, aliceDev, blob1)
	if err != nil {
		t.Fatalf("alice OpenSealedSender: %v", err)
	}
	norm, err := DecodeNormalMessage(payload1.Inner)
	if err != nil {
		t.Fatal(err)
	}
	pt1, err := alice.Decrypt(norm.Header, norm.Ciphertext)
	if err != nil {
		t.Fatalf("alice decrypt reply: %v", err)
	}
	if string(pt1) != "hi alice" {
		t.Fatalf("got %q, want %q", pt1, "hi alice")
	}
}
