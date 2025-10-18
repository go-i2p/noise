package noise

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestHybridCombine tests the HKDF-based combiner function
func TestHybridCombine(t *testing.T) {
	classicalSS := make([]byte, 32)
	pqSS := make([]byte, 32)

	// Fill with test data
	for i := range classicalSS {
		classicalSS[i] = byte(i)
		pqSS[i] = byte(i + 32)
	}

	context := "Test_Context"
	combined := hybridCombine(classicalSS, pqSS, context)

	// Verify output length
	if len(combined) != 32 {
		t.Errorf("Expected 32-byte output, got %d bytes", len(combined))
	}

	// Verify deterministic output
	combined2 := hybridCombine(classicalSS, pqSS, context)
	if !bytes.Equal(combined, combined2) {
		t.Error("hybridCombine is not deterministic")
	}

	// Verify different contexts produce different outputs
	combined3 := hybridCombine(classicalSS, pqSS, "Different_Context")
	if bytes.Equal(combined, combined3) {
		t.Error("Different contexts should produce different outputs")
	}

	// Verify different inputs produce different outputs
	classicalSS[0] ^= 1
	combined4 := hybridCombine(classicalSS, pqSS, context)
	if bytes.Equal(combined, combined4) {
		t.Error("Different inputs should produce different outputs")
	}
}

// TestHybrid25519MLKEM512KeyGeneration tests hybrid keypair generation for MLKEM-512
func TestHybrid25519MLKEM512KeyGeneration(t *testing.T) {
	dh := DHHybrid25519MLKEM512

	key, err := dh.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Verify key lengths
	expectedPrivLen := 32 + MLKEM512PrivateKeySize
	expectedPubLen := 32 + MLKEM512PublicKeySize

	if len(key.Private) != expectedPrivLen {
		t.Errorf("Expected private key length %d, got %d", expectedPrivLen, len(key.Private))
	}

	if len(key.Public) != expectedPubLen {
		t.Errorf("Expected public key length %d, got %d", expectedPubLen, len(key.Public))
	}

	// Verify keys are non-zero
	allZeroPriv := make([]byte, expectedPrivLen)
	allZeroPub := make([]byte, expectedPubLen)

	if bytes.Equal(key.Private, allZeroPriv) {
		t.Error("Private key is all zeros")
	}

	if bytes.Equal(key.Public, allZeroPub) {
		t.Error("Public key is all zeros")
	}
}

// TestHybrid25519MLKEM768KeyGeneration tests hybrid keypair generation for MLKEM-768
func TestHybrid25519MLKEM768KeyGeneration(t *testing.T) {
	dh := DHHybrid25519MLKEM768

	key, err := dh.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Verify key lengths
	expectedPrivLen := 32 + MLKEM768PrivateKeySize
	expectedPubLen := 32 + MLKEM768PublicKeySize

	if len(key.Private) != expectedPrivLen {
		t.Errorf("Expected private key length %d, got %d", expectedPrivLen, len(key.Private))
	}

	if len(key.Public) != expectedPubLen {
		t.Errorf("Expected public key length %d, got %d", expectedPubLen, len(key.Public))
	}
}

// TestHybrid25519MLKEM1024KeyGeneration tests hybrid keypair generation for MLKEM-1024
func TestHybrid25519MLKEM1024KeyGeneration(t *testing.T) {
	dh := DHHybrid25519MLKEM1024

	key, err := dh.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Verify key lengths
	expectedPrivLen := 32 + MLKEM1024PrivateKeySize
	expectedPubLen := 32 + MLKEM1024PublicKeySize

	if len(key.Private) != expectedPrivLen {
		t.Errorf("Expected private key length %d, got %d", expectedPrivLen, len(key.Private))
	}

	if len(key.Public) != expectedPubLen {
		t.Errorf("Expected public key length %d, got %d", expectedPubLen, len(key.Public))
	}
}

// TestHybridClassicalDH tests classical DH portion of hybrid functions
func TestHybridClassicalDH(t *testing.T) {
	testCases := []struct {
		name string
		dh   HybridDHFunc
	}{
		{"MLKEM512", DHHybrid25519MLKEM512},
		{"MLKEM768", DHHybrid25519MLKEM768},
		{"MLKEM1024", DHHybrid25519MLKEM1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate two keypairs
			keyA, err := tc.dh.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair A failed: %v", err)
			}

			keyB, err := tc.dh.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair B failed: %v", err)
			}

			// Perform classical DH
			ssA, err := tc.dh.DH(keyA.Private, keyB.Public)
			if err != nil {
				t.Fatalf("DH A->B failed: %v", err)
			}

			ssB, err := tc.dh.DH(keyB.Private, keyA.Public)
			if err != nil {
				t.Fatalf("DH B->A failed: %v", err)
			}

			// Verify shared secrets match
			if !bytes.Equal(ssA, ssB) {
				t.Error("Classical DH shared secrets do not match")
			}

			// Verify output is 32 bytes (Curve25519 output)
			if len(ssA) != 32 {
				t.Errorf("Expected 32-byte shared secret, got %d bytes", len(ssA))
			}
		})
	}
}

// TestHybridKEMEncapsulateDecapsulate tests KEM portion of hybrid functions
func TestHybridKEMEncapsulateDecapsulate(t *testing.T) {
	testCases := []struct {
		name string
		dh   HybridDHFunc
	}{
		{"MLKEM512", DHHybrid25519MLKEM512},
		{"MLKEM768", DHHybrid25519MLKEM768},
		{"MLKEM1024", DHHybrid25519MLKEM1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate keypair
			key, err := tc.dh.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair failed: %v", err)
			}

			// Encapsulate
			ct, ss1, err := tc.dh.KEMEncapsulate(key.Public, nil)
			if err != nil {
				t.Fatalf("KEMEncapsulate failed: %v", err)
			}

			// Verify ciphertext length
			if len(ct) != tc.dh.KEMCiphertextLen() {
				t.Errorf("Expected ciphertext length %d, got %d",
					tc.dh.KEMCiphertextLen(), len(ct))
			}

			// Verify shared secret length
			if len(ss1) != tc.dh.KEMSharedSecretLen() {
				t.Errorf("Expected shared secret length %d, got %d",
					tc.dh.KEMSharedSecretLen(), len(ss1))
			}

			// Decapsulate
			ss2, err := tc.dh.KEMDecapsulate(key.Private, ct)
			if err != nil {
				t.Fatalf("KEMDecapsulate failed: %v", err)
			}

			// Verify shared secrets match
			if !bytes.Equal(ss1, ss2) {
				t.Error("KEM shared secrets do not match")
			}

			// Clean up
			secureZero(ss1)
			secureZero(ss2)
		})
	}
}

// TestHybridKEMInvalidInputs tests error handling for invalid KEM inputs
func TestHybridKEMInvalidInputs(t *testing.T) {
	dh := DHHybrid25519MLKEM768

	key, _ := dh.GenerateKeypair(nil)

	// Test invalid public key length for encapsulation
	t.Run("InvalidPublicKeyLength", func(t *testing.T) {
		invalidPub := make([]byte, 100)
		_, _, err := dh.KEMEncapsulate(invalidPub, nil)
		if err == nil {
			t.Error("Expected error for invalid public key length")
		}
	})

	// Test invalid private key length for decapsulation
	t.Run("InvalidPrivateKeyLength", func(t *testing.T) {
		ct, _, _ := dh.KEMEncapsulate(key.Public, nil)
		invalidPriv := make([]byte, 100)
		_, err := dh.KEMDecapsulate(invalidPriv, ct)
		if err == nil {
			t.Error("Expected error for invalid private key length")
		}
	})

	// Test invalid ciphertext length
	t.Run("InvalidCiphertextLength", func(t *testing.T) {
		invalidCT := make([]byte, 100)
		_, err := dh.KEMDecapsulate(key.Private, invalidCT)
		if err == nil {
			t.Error("Expected error for invalid ciphertext length")
		}
	})

	// Test corrupted ciphertext
	// Note: ML-KEM uses error correction (Fujisaki-Okamoto transform) which may
	// successfully decapsulate corrupted ciphertexts, producing different shared secrets.
	// This is by design - we test that the shared secrets differ, not that it errors.
	t.Run("CorruptedCiphertext", func(t *testing.T) {
		ct, ss1, _ := dh.KEMEncapsulate(key.Public, nil)
		defer secureZero(ss1)

		// Corrupt the ciphertext
		corruptedCT := make([]byte, len(ct))
		copy(corruptedCT, ct)
		corruptedCT[0] ^= 1

		ss2, err := dh.KEMDecapsulate(key.Private, corruptedCT)
		if err != nil {
			// Error is acceptable - ciphertext was rejected
			return
		}
		defer secureZero(ss2)

		// If no error, shared secrets should differ (implicit authentication)
		if bytes.Equal(ss1, ss2) {
			t.Error("Corrupted ciphertext produced same shared secret")
		}
	})
}

// TestHybridIsHybrid tests the IsHybrid() method
func TestHybridIsHybrid(t *testing.T) {
	hybridFuncs := []HybridDHFunc{
		DHHybrid25519MLKEM512,
		DHHybrid25519MLKEM768,
		DHHybrid25519MLKEM1024,
	}

	for _, dh := range hybridFuncs {
		if !dh.IsHybrid() {
			t.Errorf("%s.IsHybrid() returned false, expected true", dh.DHName())
		}
	}
}

// TestHybridDHName tests the DHName() method
func TestHybridDHName(t *testing.T) {
	testCases := []struct {
		dh           HybridDHFunc
		expectedName string
	}{
		{DHHybrid25519MLKEM512, "25519+MLKEM512"},
		{DHHybrid25519MLKEM768, "25519+MLKEM768"},
		{DHHybrid25519MLKEM1024, "25519+MLKEM1024"},
	}

	for _, tc := range testCases {
		if tc.dh.DHName() != tc.expectedName {
			t.Errorf("Expected name %s, got %s", tc.expectedName, tc.dh.DHName())
		}
	}
}

// TestHybridDHLen tests the DHLen() method
func TestHybridDHLen(t *testing.T) {
	hybridFuncs := []HybridDHFunc{
		DHHybrid25519MLKEM512,
		DHHybrid25519MLKEM768,
		DHHybrid25519MLKEM1024,
	}

	for _, dh := range hybridFuncs {
		if dh.DHLen() != 32 {
			t.Errorf("%s.DHLen() = %d, expected 32", dh.DHName(), dh.DHLen())
		}
	}
}

// TestHybridKEMSizes tests KEM size methods
func TestHybridKEMSizes(t *testing.T) {
	testCases := []struct {
		name               string
		dh                 HybridDHFunc
		expectedPubKeyLen  int
		expectedPrivKeyLen int
		expectedCTLen      int
		expectedSSLen      int
	}{
		{
			"MLKEM512",
			DHHybrid25519MLKEM512,
			MLKEM512PublicKeySize,
			MLKEM512PrivateKeySize,
			MLKEM512CiphertextSize,
			MLKEM512SharedSecretSize,
		},
		{
			"MLKEM768",
			DHHybrid25519MLKEM768,
			MLKEM768PublicKeySize,
			MLKEM768PrivateKeySize,
			MLKEM768CiphertextSize,
			MLKEM768SharedSecretSize,
		},
		{
			"MLKEM1024",
			DHHybrid25519MLKEM1024,
			MLKEM1024PublicKeySize,
			MLKEM1024PrivateKeySize,
			MLKEM1024CiphertextSize,
			MLKEM1024SharedSecretSize,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dh.KEMPublicKeyLen() != tc.expectedPubKeyLen {
				t.Errorf("KEMPublicKeyLen() = %d, expected %d",
					tc.dh.KEMPublicKeyLen(), tc.expectedPubKeyLen)
			}

			if tc.dh.KEMPrivateKeyLen() != tc.expectedPrivKeyLen {
				t.Errorf("KEMPrivateKeyLen() = %d, expected %d",
					tc.dh.KEMPrivateKeyLen(), tc.expectedPrivKeyLen)
			}

			if tc.dh.KEMCiphertextLen() != tc.expectedCTLen {
				t.Errorf("KEMCiphertextLen() = %d, expected %d",
					tc.dh.KEMCiphertextLen(), tc.expectedCTLen)
			}

			if tc.dh.KEMSharedSecretLen() != tc.expectedSSLen {
				t.Errorf("KEMSharedSecretLen() = %d, expected %d",
					tc.dh.KEMSharedSecretLen(), tc.expectedSSLen)
			}
		})
	}
}

// TestHybridDeterministicKeyGen tests that key generation with same seed produces same keys
// Note: Uses deterministicRNG from pq_kem_test.go
func TestHybridDeterministicKeyGen(t *testing.T) {
	dh := DHHybrid25519MLKEM768

	// Create deterministic RNG with fixed seed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	rng1 := &deterministicRNG{seed: seed}
	rng2 := &deterministicRNG{seed: seed}

	key1, err := dh.GenerateKeypair(rng1)
	if err != nil {
		t.Fatalf("GenerateKeypair 1 failed: %v", err)
	}

	key2, err := dh.GenerateKeypair(rng2)
	if err != nil {
		t.Fatalf("GenerateKeypair 2 failed: %v", err)
	}

	// Keys should be identical with same seed
	if !bytes.Equal(key1.Private, key2.Private) {
		t.Error("Private keys differ with same seed")
	}

	if !bytes.Equal(key1.Public, key2.Public) {
		t.Error("Public keys differ with same seed")
	}
}

// TestHybridCipherSuiteIntegration tests hybrid DH in a CipherSuite
func TestHybridCipherSuiteIntegration(t *testing.T) {
	// Create hybrid cipher suite
	cs := NewCipherSuite(DHHybrid25519MLKEM768, CipherAESGCM, HashSHA256)

	// Verify name includes hybrid components
	name := string(cs.Name())
	if !bytes.Contains([]byte(name), []byte("25519+MLKEM768")) {
		t.Errorf("CipherSuite name should contain '25519+MLKEM768', got: %s", name)
	}

	// Generate keypair using cipher suite
	key, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("CipherSuite.GenerateKeypair failed: %v", err)
	}

	// Verify key length
	expectedPrivLen := 32 + MLKEM768PrivateKeySize
	expectedPubLen := 32 + MLKEM768PublicKeySize

	if len(key.Private) != expectedPrivLen {
		t.Errorf("Expected private key length %d, got %d", expectedPrivLen, len(key.Private))
	}

	if len(key.Public) != expectedPubLen {
		t.Errorf("Expected public key length %d, got %d", expectedPubLen, len(key.Public))
	}
}

// BenchmarkHybrid25519MLKEM768KeyGen benchmarks hybrid key generation
func BenchmarkHybrid25519MLKEM768KeyGen(b *testing.B) {
	dh := DHHybrid25519MLKEM768
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dh.GenerateKeypair(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHybrid25519MLKEM768ClassicalDH benchmarks classical DH
func BenchmarkHybrid25519MLKEM768ClassicalDH(b *testing.B) {
	dh := DHHybrid25519MLKEM768
	keyA, _ := dh.GenerateKeypair(nil)
	keyB, _ := dh.GenerateKeypair(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dh.DH(keyA.Private, keyB.Public)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHybrid25519MLKEM768KEMEncapsulate benchmarks KEM encapsulation
func BenchmarkHybrid25519MLKEM768KEMEncapsulate(b *testing.B) {
	dh := DHHybrid25519MLKEM768
	key, _ := dh.GenerateKeypair(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := dh.KEMEncapsulate(key.Public, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHybrid25519MLKEM768KEMDecapsulate benchmarks KEM decapsulation
func BenchmarkHybrid25519MLKEM768KEMDecapsulate(b *testing.B) {
	dh := DHHybrid25519MLKEM768
	key, _ := dh.GenerateKeypair(nil)
	ct, _, _ := dh.KEMEncapsulate(key.Public, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dh.KEMDecapsulate(key.Private, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHybridCombine benchmarks the hybrid combiner function
func BenchmarkHybridCombine(b *testing.B) {
	classicalSS := make([]byte, 32)
	pqSS := make([]byte, 32)
	rand.Read(classicalSS)
	rand.Read(pqSS)
	context := "Benchmark_Context"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		combined := hybridCombine(classicalSS, pqSS, context)
		_ = combined
	}
}
