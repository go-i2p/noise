package noise

import (
	"testing"
)

// TestZeroKeyPreventsEncrypt verifies that after calling ZeroKey(), Encrypt
// returns an error.
func TestZeroKeyPreventsEncrypt(t *testing.T) {
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
	msg2, _, _, _ := hsR.WriteMessage(nil, nil)
	_, csEnc, _, _ := hsI.ReadMessage(nil, msg2)

	// Encrypt should work before ZeroKey
	_, err := csEnc.Encrypt(nil, nil, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt before ZeroKey failed: %v", err)
	}

	// Zero the key
	csEnc.ZeroKey()

	// Encrypt should fail after ZeroKey
	_, err = csEnc.Encrypt(nil, nil, []byte("hello"))
	if err == nil {
		t.Fatal("Encrypt after ZeroKey should have failed")
	}
}

// TestZeroKeyPreventsDecrypt verifies that after calling ZeroKey(), Decrypt
// returns an error.
func TestZeroKeyPreventsDecrypt(t *testing.T) {
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
	msg2, _, _, _ := hsR.WriteMessage(nil, nil)
	_, _, csDec, _ := hsI.ReadMessage(nil, msg2)

	// Zero the key
	csDec.ZeroKey()

	// Decrypt should fail after ZeroKey
	_, err := csDec.Decrypt(nil, nil, make([]byte, 32))
	if err == nil {
		t.Fatal("Decrypt after ZeroKey should have failed")
	}
}

// TestZeroKeyZerosKeyMaterial verifies that ZeroKey actually zeroes the key
// bytes, not just sets the invalid flag.
func TestZeroKeyZerosKeyMaterial(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	// Create a CipherState with a known non-zero key via UnsafeNewCipherState.
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipherState := UnsafeNewCipherState(cs, key, 0)

	// Confirm key is non-zero before ZeroKey
	keyBefore := cipherState.UnsafeKey()
	allZero := true
	for _, b := range keyBefore {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("key should not be all zeros before ZeroKey")
	}

	cipherState.ZeroKey()

	// Read back via UnsafeKey — should be all zeros
	keyAfter := cipherState.UnsafeKey()
	for i, b := range keyAfter {
		if b != 0 {
			t.Fatalf("key byte %d is %02x after ZeroKey, expected 0", i, b)
		}
	}
}

// TestZeroKeyIdempotent verifies that calling ZeroKey multiple times does not
// panic.
func TestZeroKeyIdempotent(t *testing.T) {
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
	msg2, _, _, _ := hsR.WriteMessage(nil, nil)
	_, csEnc, _, _ := hsI.ReadMessage(nil, msg2)

	// Should not panic
	csEnc.ZeroKey()
	csEnc.ZeroKey()
	csEnc.ZeroKey()
}
