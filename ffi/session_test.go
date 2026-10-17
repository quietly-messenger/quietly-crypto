package main

import (
	"testing"

	"github.com/quietly-messenger/quietly-crypto/protocol"
)

func TestSessionHelpersEndToEnd(t *testing.T) {
	ikA, err := protocol.GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	ikB, spkB, otpkB, bundleB, err := protocol.GeneratePreKeyBundle(true)
	if err != nil {
		t.Fatal(err)
	}
	aliceDev := protocol.UserDevice{UserID: [16]byte{1}, DeviceID: 1}
	bobDev := protocol.UserDevice{UserID: [16]byte{2}, DeviceID: 2}

	// --- Initiator establishes and seals the initial message. ---
	aliceS, initial, err := initiatorSession(ikA, bundleB, []byte("hello bob"))
	if err != nil {
		t.Fatalf("initiatorSession: %v", err)
	}
	blob0, err := protocol.SealSealedSender(ikA.DHPriv, bobDev, ikB.DHPub, protocol.SealedPayload{
		SenderUserID:   aliceDev.UserID,
		SenderDeviceID: 1,
		SessionType:    protocol.SessionTypePairwise,
		MsgType:        protocol.MsgTypeInitial,
		Inner:          initial,
	})
	if err != nil {
		t.Fatalf("seal initial: %v", err)
	}

	// --- Responder opens and establishes. ---
	payload0, err := protocol.OpenSealedSender(ikB.DHPriv, bobDev, blob0)
	if err != nil {
		t.Fatalf("open initial: %v", err)
	}
	bobS, firstPT, err := responderSession(ikB, spkB, otpkB, payload0.Inner)
	if err != nil {
		t.Fatalf("responderSession: %v", err)
	}
	if string(firstPT) != "hello bob" {
		t.Fatalf("first plaintext = %q", firstPT)
	}

	// --- Responder replies, sealed back to the initiator. ---
	h1, c1, err := bobS.Encrypt([]byte("hi alice"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob1, err := protocol.SealSealedSender(ikB.DHPriv, aliceDev, ikA.DHPub, protocol.SealedPayload{
		SenderUserID:   bobDev.UserID,
		SenderDeviceID: 2,
		SessionType:    protocol.SessionTypePairwise,
		MsgType:        protocol.MsgTypeNormal,
		Inner:          protocol.EncodeNormalMessage(h1, c1),
	})
	if err != nil {
		t.Fatalf("seal reply: %v", err)
	}
	payload1, err := protocol.OpenSealedSender(ikA.DHPriv, aliceDev, blob1)
	if err != nil {
		t.Fatalf("open reply: %v", err)
	}
	norm, err := protocol.DecodeNormalMessage(payload1.Inner)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	pt, err := aliceS.Decrypt(norm.Header, norm.Ciphertext)
	if err != nil {
		t.Fatalf("decrypt reply: %v", err)
	}
	if string(pt) != "hi alice" {
		t.Fatalf("reply plaintext = %q", pt)
	}
}

func TestSessionRegistry(t *testing.T) {
	ik, err := protocol.GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, bundle, err := protocol.GeneratePreKeyBundle(false)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := initiatorSession(ik, bundle, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}

	h := sessions.add(s)
	if sessions.get(h) != s {
		t.Fatal("get after add returned the wrong session")
	}
	sessions.remove(h)
	if sessions.get(h) != nil {
		t.Fatal("get after remove should return nil")
	}
	// Removing twice is a no-op.
	sessions.remove(h)
}
