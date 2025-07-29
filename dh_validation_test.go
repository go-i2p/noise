package noise

import (
	"testing"
)

func TestDH25519_InvalidPublicKeyValidation(t *testing.T) {
	dh := dh25519{}
	
	// Generate a valid private key for testing
	privkey := make([]byte, 32)
	for i := range privkey {
		privkey[i] = byte(i + 1) // Simple non-zero private key
	}
	
	// Test cases for invalid public keys
	testCases := []struct {
		name         string
		pubkey       []byte
		shouldReject bool
		description  string
	}{
		{
			name:         "all-zero point",
			pubkey:       make([]byte, 32), // all zeros
			shouldReject: true,
			description:  "Low order point (identity)",
		},
		{
			name:         "point of order 2",
			pubkey:       []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			shouldReject: true,
			description:  "Low order point",
		},
		{
			name:         "wrong length - too short",
			pubkey:       make([]byte, 31),
			shouldReject: true,
			description:  "Invalid length",
		},
		{
			name:         "wrong length - too long",
			pubkey:       make([]byte, 33),
			shouldReject: true,
			description:  "Invalid length",
		},
		{
			name:         "invalid high bit set",
			pubkey:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			shouldReject: false, // X25519 clamps the high bit, so this is actually valid behavior
			description:  "High bit gets clamped per X25519 spec",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := dh.DH(privkey, tc.pubkey)
			
			if tc.shouldReject {
				if err == nil {
					t.Errorf("Expected DH to reject %s (%s), but it succeeded with result length %d", tc.name, tc.description, len(result))
					// Check if result is weak
					allZeros := true
					for _, b := range result {
						if b != 0 {
							allZeros = false
							break
						}
					}
					if allZeros {
						t.Errorf("WARNING: DH result is all zeros for %s - potential security issue", tc.name)
					}
				} else {
					t.Logf("GOOD: DH correctly rejected %s: %v", tc.name, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected DH to accept valid point, but it failed: %v", err)
				}
			}
		})
	}
}

func TestDH25519_ValidPublicKeyAccepted(t *testing.T) {
	dh := dh25519{}
	
	// Generate valid keypairs
	keypair1, err := dh.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair1: %v", err)
	}
	
	keypair2, err := dh.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair2: %v", err)
	}
	
	// Valid DH operations should work
	result1, err := dh.DH(keypair1.Private, keypair2.Public)
	if err != nil {
		t.Errorf("Valid DH operation failed: %v", err)
	}
	
	result2, err := dh.DH(keypair2.Private, keypair1.Public)
	if err != nil {
		t.Errorf("Valid DH operation failed: %v", err)
	}
	
	// Results should be the same (DH property)
	if len(result1) != len(result2) {
		t.Errorf("DH results have different lengths: %d vs %d", len(result1), len(result2))
	}
	
	for i := range result1 {
		if result1[i] != result2[i] {
			t.Errorf("DH results differ at byte %d: %02x vs %02x", i, result1[i], result2[i])
		}
	}
}
