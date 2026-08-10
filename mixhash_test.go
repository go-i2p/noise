package noise

import (
	"bytes"
	"testing"
)

// TestMixHashAffectsChannelBinding verifies that calling MixHash between
// handshake messages changes the resulting handshake hash (channel binding).
func TestMixHashAffectsChannelBinding(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	// Run two identical XK handshakes, but call MixHash on one of them
	// between messages 1 and 2. The channel bindings must differ.
	cbWithout := runXKHandshake(t, cs, nil)
	cbWith := runXKHandshake(t, cs, []byte("extra transcript data"))

	if bytes.Equal(cbWithout, cbWith) {
		t.Fatal("MixHash had no effect on channel binding")
	}
}

// TestMixHashBothSidesMustAgree verifies that both peers must call MixHash
// with the same data for the handshake to succeed.
func TestMixHashBothSidesMustAgree(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXK,
		Initiator:     true,
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXK,
		Initiator:     false,
		StaticKeypair: staticR,
	})

	// Message 1: I -> R
	msg1, _, _, _ := hsI.WriteMessage(nil, nil)
	_, _, _, err := hsR.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("ReadMessage 1: %v", err)
	}

	// Only initiator calls MixHash, so the hashes diverge
	hsI.MixHash([]byte("only initiator sees this"))

	// Message 2: R -> I, should fail because h no longer matches
	msg2, _, _, _ := hsR.WriteMessage(nil, nil)
	_, _, _, err = hsI.ReadMessage(nil, msg2)
	if err == nil {
		t.Fatal("expected handshake failure when MixHash is asymmetric")
	}
}

// runXKHandshake completes an XK handshake. If mixData is non-nil, both sides
// call MixHash with it between messages 1 and 2. Returns the initiator's
// channel binding.
func runXKHandshake(t *testing.T, cs CipherSuite, mixData []byte) []byte {
	t.Helper()

	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXK,
		Initiator:     true,
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXK,
		Initiator:     false,
		StaticKeypair: staticR,
	})

	// Message 1: I -> R
	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage 1: %v", err)
	}
	_, _, _, err = hsR.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("ReadMessage 1: %v", err)
	}

	// Optional MixHash between messages
	if mixData != nil {
		hsI.MixHash(mixData)
		hsR.MixHash(mixData)
	}

	// Message 2: R -> I
	msg2, _, _, err := hsR.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage 2: %v", err)
	}
	_, _, _, err = hsI.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("ReadMessage 2: %v", err)
	}

	// Message 3: I -> R (final)
	msg3, csI1, csI2, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage 3: %v", err)
	}
	_, csR1, csR2, err := hsR.ReadMessage(nil, msg3)
	if err != nil {
		t.Fatalf("ReadMessage 3: %v", err)
	}

	if csI1 == nil || csI2 == nil || csR1 == nil || csR2 == nil {
		t.Fatal("handshake did not complete")
	}

	return hsI.ChannelBinding()
}
