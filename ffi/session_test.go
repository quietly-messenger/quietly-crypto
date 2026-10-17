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

// testSession builds a minimal established session for registry tests.
func testSession(t *testing.T) *protocol.Session {
	t.Helper()
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
	return s
}

// TestSessionRegistryIsBoundedAndMasked covers the audit F-13 hardening: the
// registry evicts the oldest session once its cap is reached, and handles are
// XOR-masked so they neither start at 1 nor follow the counter.
func TestSessionRegistryIsBoundedAndMasked(t *testing.T) {
	const max = 4
	r := &sessionRegistry{
		mask:     0x5eed5eed5eed5eed,
		sessions: make(map[uint64]*protocol.Session),
		max:      max,
	}

	var handles []uint64
	for i := 0; i < max+2; i++ {
		handles = append(handles, r.add(testSession(t)))
	}

	if len(r.sessions) != max {
		t.Fatalf("registry holds %d sessions, want the cap %d", len(r.sessions), max)
	}
	if r.get(handles[0]) != nil || r.get(handles[1]) != nil {
		t.Fatal("oldest sessions were not evicted")
	}
	if r.get(handles[max+1]) == nil {
		t.Fatal("newest session missing")
	}

	// Raw counter values must not resolve, and no handle may equal the counter
	// position: predictable handles are the F-13 concern.
	if r.get(1) != nil || r.get(2) != nil {
		t.Fatal("raw counter values resolve to sessions: mask not applied")
	}
	for i, h := range handles {
		if h == uint64(i+1) {
			t.Fatalf("handle %d equals the raw counter (mask not applied)", h)
		}
	}

	// Removing an evicted handle is a no-op; removing a live one drops it.
	r.remove(handles[0])
	if r.get(handles[max+1]) == nil {
		t.Fatal("remove dropped the wrong session")
	}
	r.remove(handles[max+1])
	if r.get(handles[max+1]) != nil {
		t.Fatal("removal did not drop the session")
	}
}
