package noise

import (
	"testing"

	// Test that MLKEM implementations are accessible
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"

	// Test that MLDSA implementations are accessible
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// TestPQDependencyAvailability verifies that post-quantum cryptography
// dependencies are properly installed and accessible.
func TestPQDependencyAvailability(t *testing.T) {
	t.Run("PQSupported constant", func(t *testing.T) {
		if !PQSupported {
			t.Fatal("PQSupported should be true")
		}
		t.Logf("✅ Post-quantum cryptography support is enabled")
	})

	t.Run("PQVersion constant", func(t *testing.T) {
		if PQVersion == "" {
			t.Fatal("PQVersion should not be empty")
		}
		t.Logf("✅ PQ implementation version: %s", PQVersion)
	})
}

// TestMLKEMAvailability verifies that all MLKEM variants are accessible.
// This test ensures the CIRCL library is properly installed and can be imported.
func TestMLKEMAvailability(t *testing.T) {
	t.Run("MLKEM-512", func(t *testing.T) {
		// Test basic MLKEM-512 functionality
		pub, priv, err := mlkem512.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("Failed to generate MLKEM-512 keypair: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("Generated keys should not be nil")
		}

		// Test encapsulation
		ct := make([]byte, 768) // MLKEM-512 ciphertext size
		ss1 := make([]byte, 32) // Shared secret size
		pub.EncapsulateTo(ct, ss1, nil)

		// Test decapsulation
		ss2 := make([]byte, 32)
		priv.DecapsulateTo(ss2, ct)

		// Verify shared secrets match
		if string(ss1) != string(ss2) {
			t.Fatal("Shared secrets should match")
		}

		t.Logf("✅ MLKEM-512 is working correctly (ct=%d bytes, ss=%d bytes)", len(ct), len(ss1))
	})

	t.Run("MLKEM-768", func(t *testing.T) {
		// Test basic MLKEM-768 functionality (recommended for Noise)
		pub, priv, err := mlkem768.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("Failed to generate MLKEM-768 keypair: %v", err)
		}

		ct := make([]byte, 1088) // MLKEM-768 ciphertext size
		ss1 := make([]byte, 32)  // Shared secret size
		pub.EncapsulateTo(ct, ss1, nil)

		ss2 := make([]byte, 32)
		priv.DecapsulateTo(ss2, ct)

		if string(ss1) != string(ss2) {
			t.Fatal("Shared secrets should match")
		}

		t.Logf("✅ MLKEM-768 is working correctly (ct=%d bytes, ss=%d bytes) [RECOMMENDED]", len(ct), len(ss1))
	})

	t.Run("MLKEM-1024", func(t *testing.T) {
		// Test basic MLKEM-1024 functionality
		pub, priv, err := mlkem1024.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("Failed to generate MLKEM-1024 keypair: %v", err)
		}

		ct := make([]byte, 1568) // MLKEM-1024 ciphertext size
		ss1 := make([]byte, 32)  // Shared secret size
		pub.EncapsulateTo(ct, ss1, nil)

		ss2 := make([]byte, 32)
		priv.DecapsulateTo(ss2, ct)

		if string(ss1) != string(ss2) {
			t.Fatal("Shared secrets should match")
		}

		t.Logf("✅ MLKEM-1024 is working correctly (ct=%d bytes, ss=%d bytes)", len(ct), len(ss1))
	})
}

// TestMLDSAAvailability verifies that all MLDSA variants are accessible.
// This test ensures signature algorithms are properly available.
func TestMLDSAAvailability(t *testing.T) {
	testMessage := []byte("Test message for signature verification")

	t.Run("MLDSA-44", func(t *testing.T) {
		// Test basic MLDSA-44 functionality
		pub, priv, err := mldsa44.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate MLDSA-44 keypair: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("Generated keys should not be nil")
		}

		// Test signing
		sig := make([]byte, mldsa44.SignatureSize)
		err = mldsa44.SignTo(priv, testMessage, nil, false, sig)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Test verification
		if !mldsa44.Verify(pub, testMessage, nil, sig) {
			t.Fatal("Signature verification should succeed")
		}

		// Test verification with wrong message
		if mldsa44.Verify(pub, []byte("wrong message"), nil, sig) {
			t.Fatal("Signature verification should fail for wrong message")
		}

		t.Logf("✅ MLDSA-44 is working correctly (sig=%d bytes)", len(sig))
	})

	t.Run("MLDSA-65", func(t *testing.T) {
		// Test basic MLDSA-65 functionality (recommended)
		pub, priv, err := mldsa65.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate MLDSA-65 keypair: %v", err)
		}

		sig := make([]byte, mldsa65.SignatureSize)
		err = mldsa65.SignTo(priv, testMessage, nil, false, sig)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		if !mldsa65.Verify(pub, testMessage, nil, sig) {
			t.Fatal("Signature verification should succeed")
		}

		if mldsa65.Verify(pub, []byte("wrong message"), nil, sig) {
			t.Fatal("Signature verification should fail for wrong message")
		}

		t.Logf("✅ MLDSA-65 is working correctly (sig=%d bytes) [RECOMMENDED]", len(sig))
	})

	t.Run("MLDSA-87", func(t *testing.T) {
		// Test basic MLDSA-87 functionality
		pub, priv, err := mldsa87.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate MLDSA-87 keypair: %v", err)
		}

		sig := make([]byte, mldsa87.SignatureSize)
		err = mldsa87.SignTo(priv, testMessage, nil, false, sig)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		if !mldsa87.Verify(pub, testMessage, nil, sig) {
			t.Fatal("Signature verification should succeed")
		}

		if mldsa87.Verify(pub, []byte("wrong message"), nil, sig) {
			t.Fatal("Signature verification should fail for wrong message")
		}

		t.Logf("✅ MLDSA-87 is working correctly (sig=%d bytes)", len(sig))
	})
}

// TestCirclLibraryCompatibility verifies that the CIRCL library version
// is compatible with our requirements.
func TestCirclLibraryCompatibility(t *testing.T) {
	t.Run("Library imports without errors", func(t *testing.T) {
		// If we got here, all imports succeeded
		t.Log("✅ All CIRCL library imports successful")
	})

	t.Run("FIPS 203 ML-KEM support", func(t *testing.T) {
		// Verify MLKEM-768 (NIST Level 3) is available
		pub, priv, err := mlkem768.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("FIPS 203 ML-KEM-768 should be available: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("FIPS 203 ML-KEM-768 key generation failed")
		}
		t.Log("✅ FIPS 203 ML-KEM support verified")
	})

	t.Run("FIPS 204 ML-DSA support", func(t *testing.T) {
		// Verify MLDSA-65 (NIST Level 3) is available
		pub, priv, err := mldsa65.GenerateKey(nil)
		if err != nil {
			t.Fatalf("FIPS 204 ML-DSA-65 should be available: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("FIPS 204 ML-DSA-65 key generation failed")
		}
		t.Log("✅ FIPS 204 ML-DSA support verified")
	})
}

// TestNISTSecurityLevels verifies that we have implementations for
// all three NIST security levels.
func TestNISTSecurityLevels(t *testing.T) {
	t.Run("Level 1 (AES-128 equivalent)", func(t *testing.T) {
		// MLKEM-512 provides NIST Level 1
		pub, priv, err := mlkem512.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("NIST Level 1 KEM should be available: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("NIST Level 1 key generation failed")
		}

		// MLDSA-44 provides NIST Level 1
		sigPub, sigPriv, err := mldsa44.GenerateKey(nil)
		if err != nil {
			t.Fatalf("NIST Level 1 signature should be available: %v", err)
		}
		if sigPub == nil || sigPriv == nil {
			t.Fatal("NIST Level 1 signing key generation failed")
		}

		t.Log("✅ NIST Level 1 (AES-128 equivalent) algorithms available")
	})

	t.Run("Level 3 (AES-192 equivalent)", func(t *testing.T) {
		// MLKEM-768 provides NIST Level 3 (RECOMMENDED)
		pub, priv, err := mlkem768.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("NIST Level 3 KEM should be available: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("NIST Level 3 key generation failed")
		}

		// MLDSA-65 provides NIST Level 3 (RECOMMENDED)
		sigPub, sigPriv, err := mldsa65.GenerateKey(nil)
		if err != nil {
			t.Fatalf("NIST Level 3 signature should be available: %v", err)
		}
		if sigPub == nil || sigPriv == nil {
			t.Fatal("NIST Level 3 signing key generation failed")
		}

		t.Log("✅ NIST Level 3 (AES-192 equivalent) algorithms available [RECOMMENDED]")
	})

	t.Run("Level 5 (AES-256 equivalent)", func(t *testing.T) {
		// MLKEM-1024 provides NIST Level 5
		pub, priv, err := mlkem1024.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("NIST Level 5 KEM should be available: %v", err)
		}
		if pub == nil || priv == nil {
			t.Fatal("NIST Level 5 key generation failed")
		}

		// MLDSA-87 provides NIST Level 5
		sigPub, sigPriv, err := mldsa87.GenerateKey(nil)
		if err != nil {
			t.Fatalf("NIST Level 5 signature should be available: %v", err)
		}
		if sigPub == nil || sigPriv == nil {
			t.Fatal("NIST Level 5 signing key generation failed")
		}

		t.Log("✅ NIST Level 5 (AES-256 equivalent) algorithms available")
	})
}
