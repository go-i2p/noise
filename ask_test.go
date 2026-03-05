package noise

import (
	"bytes"
	"crypto/hmac"
	"testing"
)

// TestSplitWithASKDerivation verifies that SplitWithASK derives correct
// Additional Symmetric Keys per Noise spec §10.3.
func TestSplitWithASKDerivation(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, err := NewHandshakeState(Config{
		CipherSuite:                  cs,
		Random:                       rngI,
		Pattern:                      HandshakeXK,
		Initiator:                    true,
		StaticKeypair:                staticI,
		PeerStatic:                   staticR.Public,
		AdditionalSymmetricKeyLabels: [][]byte{[]byte("ask")},
	})
	if err != nil {
		t.Fatalf("NewHandshakeState initiator: %v", err)
	}

	hsR, err := NewHandshakeState(Config{
		CipherSuite:                  cs,
		Random:                       rngR,
		Pattern:                      HandshakeXK,
		Initiator:                    false,
		StaticKeypair:                staticR,
		AdditionalSymmetricKeyLabels: [][]byte{[]byte("ask")},
	})
	if err != nil {
		t.Fatalf("NewHandshakeState responder: %v", err)
	}

	// Message 1: I -> R
	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("WriteMessage 1: %v", err)
	}
	_, _, _, err = hsR.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("ReadMessage 1: %v", err)
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
		t.Fatal("handshake did not complete: CipherStates are nil")
	}

	// Verify ASK keys were derived
	askI := hsI.AdditionalSymmetricKeys()
	askR := hsR.AdditionalSymmetricKeys()

	if len(askI) != 1 {
		t.Fatalf("initiator ASK count: got %d, want 1", len(askI))
	}
	if len(askR) != 1 {
		t.Fatalf("responder ASK count: got %d, want 1", len(askR))
	}

	// Both sides must derive the same ASK
	if !bytes.Equal(askI[0], askR[0]) {
		t.Fatalf("ASK mismatch:\n  initiator: %x\n  responder: %x", askI[0], askR[0])
	}

	// ASK must be 32 bytes (SHA-256 output)
	if len(askI[0]) != 32 {
		t.Fatalf("ASK length: got %d, want 32", len(askI[0]))
	}

	// ASK must not be all zeros
	allZero := true
	for _, b := range askI[0] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("ASK is all zeros")
	}
}

// TestSplitWithASKMultipleLabels verifies multiple labels each produce a
// distinct key.
func TestSplitWithASKMultipleLabels(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	labels := [][]byte{[]byte("ask"), []byte("extra"), []byte("third")}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:                  cs,
		Random:                       rngI,
		Pattern:                      HandshakeXK,
		Initiator:                    true,
		StaticKeypair:                staticI,
		PeerStatic:                   staticR.Public,
		AdditionalSymmetricKeyLabels: labels,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:                  cs,
		Random:                       rngR,
		Pattern:                      HandshakeXK,
		Initiator:                    false,
		StaticKeypair:                staticR,
		AdditionalSymmetricKeyLabels: labels,
	})

	// Complete XK handshake (3 messages)
	msg1, _, _, _ := hsI.WriteMessage(nil, nil)
	hsR.ReadMessage(nil, msg1)
	msg2, _, _, _ := hsR.WriteMessage(nil, nil)
	hsI.ReadMessage(nil, msg2)
	msg3, _, _, _ := hsI.WriteMessage(nil, nil)
	hsR.ReadMessage(nil, msg3)

	askI := hsI.AdditionalSymmetricKeys()
	askR := hsR.AdditionalSymmetricKeys()

	if len(askI) != 3 {
		t.Fatalf("ASK count: got %d, want 3", len(askI))
	}

	// All keys must match between initiator and responder
	for i := range askI {
		if !bytes.Equal(askI[i], askR[i]) {
			t.Fatalf("ASK[%d] mismatch", i)
		}
	}

	// All keys must be distinct
	for i := 0; i < len(askI); i++ {
		for j := i + 1; j < len(askI); j++ {
			if bytes.Equal(askI[i], askI[j]) {
				t.Fatalf("ASK[%d] == ASK[%d], labels should produce distinct keys", i, j)
			}
		}
	}
}

// TestSplitWithASKNoLabels verifies that without labels, AdditionalSymmetricKeys
// returns nil and the handshake completes normally (backward compatibility).
func TestSplitWithASKNoLabels(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg1, _, _, _ := hsI.WriteMessage(nil, nil)
	hsR.ReadMessage(nil, msg1)
	msg2, csI1, csI2, _ := hsR.WriteMessage(nil, nil)
	_, csR1, csR2, _ := hsI.ReadMessage(nil, msg2)

	if csI1 == nil || csI2 == nil || csR1 == nil || csR2 == nil {
		t.Fatal("handshake did not complete")
	}

	askI := hsI.AdditionalSymmetricKeys()
	askR := hsR.AdditionalSymmetricKeys()

	if askI != nil {
		t.Fatalf("initiator ASK should be nil without labels, got %d keys", len(askI))
	}
	if askR != nil {
		t.Fatalf("responder ASK should be nil without labels, got %d keys", len(askR))
	}
}

// TestSplitWithASKMatchesManualDerivation verifies the ASK output matches a
// manual HMAC computation, ensuring spec compliance.
func TestSplitWithASKMatchesManualDerivation(t *testing.T) {
	// We'll test at the SymmetricState level directly.
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	ss := SymmetricState{}
	ss.cs = cs
	ss.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))

	// Mix a known value so ck is deterministic
	ss.MixHash([]byte("test prologue"))
	ss.MixKey(bytes.Repeat([]byte{0x42}, 32))

	// Save ck before split for manual derivation
	ckCopy := make([]byte, len(ss.ck))
	copy(ckCopy, ss.ck)

	label := []byte("ask")
	_, _, asks := ss.SplitWithASK(label)

	if len(asks) != 1 {
		t.Fatalf("expected 1 ASK, got %d", len(asks))
	}

	// Manually derive: temp_key = HMAC(ck, zerolen)
	tempMAC := hmac.New(cs.Hash, ckCopy)
	tempMAC.Write(nil)
	tempKey := tempMAC.Sum(nil)

	// ask = HMAC(temp_key, label || 0x01)
	askMAC := hmac.New(cs.Hash, tempKey)
	askMAC.Write(label)
	askMAC.Write([]byte{0x01})
	expected := askMAC.Sum(nil)

	if !bytes.Equal(asks[0], expected) {
		t.Fatalf("ASK does not match manual derivation:\n  got:    %x\n  expect: %x", asks[0], expected)
	}
}
