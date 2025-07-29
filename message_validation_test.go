package noise

import (
	"bytes"
	"testing"
)

// TestReadMessageOversizedInputValidation validates that ReadMessage properly rejects
// oversized messages to prevent DoS attacks. This ensures Finding #4 remains fixed.
func TestReadMessageOversizedInputValidation(t *testing.T) {
	// Create a basic handshake configuration
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	hs, err := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      new(RandomInc),
		Pattern:     HandshakeNN,
		Initiator:   false, // This is the responder
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create an oversized message that exceeds MaxMsgLen
	oversizedMessage := make([]byte, MaxMsgLen+1)
	for i := range oversizedMessage {
		oversizedMessage[i] = byte(i % 256)
	}

	// Attempt to read the oversized message
	out := make([]byte, 0, len(oversizedMessage))
	_, _, _, err = hs.ReadMessage(out, oversizedMessage)

	// This should fail with the expected error message
	if err == nil {
		t.Fatal("ReadMessage should reject oversized messages but accepted one")
	}

	expected := "noise: message exceeds maximum length"
	if err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err.Error())
	}
}

// TestReadMessageMaxSizeMessageValidation validates that ReadMessage accepts messages
// exactly at the MaxMsgLen limit. This ensures valid large messages are not rejected.
func TestReadMessageMaxSizeMessageValidation(t *testing.T) {
	// Create a basic handshake configuration
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	hs, err := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      new(RandomInc),
		Pattern:     HandshakeNN,
		Initiator:   false, // This is the responder
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a message exactly at MaxMsgLen
	maxSizeMessage := make([]byte, MaxMsgLen)
	for i := range maxSizeMessage {
		maxSizeMessage[i] = byte(i % 256)
	}

	// Attempt to read the max-size message
	out := make([]byte, 0, len(maxSizeMessage))
	_, _, _, err = hs.ReadMessage(out, maxSizeMessage)

	// This might fail for protocol reasons, but should NOT fail due to length validation
	// We just want to ensure it doesn't fail with a "too long" error
	if err != nil && (bytes.Contains([]byte(err.Error()), []byte("too long")) ||
		bytes.Contains([]byte(err.Error()), []byte("exceeds maximum length"))) {
		t.Errorf("ReadMessage rejected max-size message due to length validation: %v", err)
	}
}
