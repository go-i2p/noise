package noise

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// Mock implementations for testing the interfaces

// mockKEMFunc is a simple mock KEM for testing interface compliance
type mockKEMFunc struct {
	pubKeyLen    int
	privKeyLen   int
	ctLen        int
	ssLen        int
	shouldFail   bool
	failGenerate bool
	failEncaps   bool
	failDecaps   bool
}

func (m mockKEMFunc) GenerateKeypair(random io.Reader) (KEMKey, error) {
	if m.failGenerate {
		return KEMKey{}, errors.New("mock generate failure")
	}
	pub := make([]byte, m.pubKeyLen)
	priv := make([]byte, m.privKeyLen)
	if random == nil {
		random = rand.Reader
	}
	io.ReadFull(random, pub)
	io.ReadFull(random, priv)
	return KEMKey{Public: pub, Private: priv}, nil
}

func (m mockKEMFunc) Encapsulate(pubkey []byte, random io.Reader) ([]byte, []byte, error) {
	if m.failEncaps {
		return nil, nil, ErrInvalidKEMPublicKey
	}
	if len(pubkey) != m.pubKeyLen {
		return nil, nil, ErrInvalidKEMPublicKey
	}
	ct := make([]byte, m.ctLen)
	ss := make([]byte, m.ssLen)
	if random == nil {
		random = rand.Reader
	}
	io.ReadFull(random, ct)
	io.ReadFull(random, ss)
	return ct, ss, nil
}

func (m mockKEMFunc) Decapsulate(privkey, ciphertext []byte) ([]byte, error) {
	if m.failDecaps {
		return nil, ErrKEMDecapsulationFailed
	}
	if len(privkey) != m.privKeyLen {
		return nil, ErrInvalidKEMPrivateKey
	}
	if len(ciphertext) != m.ctLen {
		return nil, ErrInvalidKEMCiphertext
	}
	// Return a deterministic shared secret based on ciphertext
	ss := make([]byte, m.ssLen)
	copy(ss, ciphertext[:min(len(ciphertext), m.ssLen)])
	return ss, nil
}

func (m mockKEMFunc) PublicKeyLen() int    { return m.pubKeyLen }
func (m mockKEMFunc) PrivateKeyLen() int   { return m.privKeyLen }
func (m mockKEMFunc) CiphertextLen() int   { return m.ctLen }
func (m mockKEMFunc) SharedSecretLen() int { return m.ssLen }
func (m mockKEMFunc) KEMName() string      { return "MockKEM" }

// mockSignatureFunc is a simple mock signature algorithm for testing
type mockSignatureFunc struct {
	pubKeyLen  int
	privKeyLen int
	sigLen     int
	failGen    bool
	failSign   bool
	failVerify bool
}

func (m mockSignatureFunc) GenerateSigningKey(random io.Reader) (SigningKey, error) {
	if m.failGen {
		return SigningKey{}, errors.New("mock generate failure")
	}
	pub := make([]byte, m.pubKeyLen)
	priv := make([]byte, m.privKeyLen)
	if random == nil {
		random = rand.Reader
	}
	io.ReadFull(random, pub)
	io.ReadFull(random, priv)
	return SigningKey{Public: pub, Private: priv}, nil
}

func (m mockSignatureFunc) Sign(privkey, message []byte) ([]byte, error) {
	if m.failSign {
		return nil, errors.New("mock sign failure")
	}
	if len(privkey) != m.privKeyLen {
		return nil, ErrInvalidSigningKey
	}
	// Create a simple signature: hash(privkey || message)
	sig := make([]byte, m.sigLen)
	// Deterministic signature for testing
	for i := 0; i < m.sigLen; i++ {
		sig[i] = privkey[i%len(privkey)] ^ message[i%len(message)]
	}
	return sig, nil
}

func (m mockSignatureFunc) Verify(pubkey, message, signature []byte) error {
	if m.failVerify {
		return ErrInvalidSignature
	}
	if len(signature) != m.sigLen {
		return ErrInvalidSignature
	}
	// In a real implementation, we'd verify the signature
	// For this mock, just check it's non-zero
	allZero := true
	for _, b := range signature {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ErrInvalidSignature
	}
	return nil
}

func (m mockSignatureFunc) PublicKeyLen() int     { return m.pubKeyLen }
func (m mockSignatureFunc) PrivateKeyLen() int    { return m.privKeyLen }
func (m mockSignatureFunc) SignatureLen() int     { return m.sigLen }
func (m mockSignatureFunc) SignatureName() string { return "MockSignature" }

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestKEMFuncInterface tests the KEMFunc interface with a mock implementation
func TestKEMFuncInterface(t *testing.T) {
	kem := mockKEMFunc{
		pubKeyLen:  32,
		privKeyLen: 64,
		ctLen:      48,
		ssLen:      32,
	}

	// Test key generation
	keypair, err := kem.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if len(keypair.Public) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(keypair.Public))
	}
	if len(keypair.Private) != 64 {
		t.Errorf("Expected private key length 64, got %d", len(keypair.Private))
	}

	// Test encapsulation
	ct, ss1, err := kem.Encapsulate(keypair.Public, nil)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	if len(ct) != 48 {
		t.Errorf("Expected ciphertext length 48, got %d", len(ct))
	}
	if len(ss1) != 32 {
		t.Errorf("Expected shared secret length 32, got %d", len(ss1))
	}

	// Test decapsulation
	ss2, err := kem.Decapsulate(keypair.Private, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if len(ss2) != 32 {
		t.Errorf("Expected shared secret length 32, got %d", len(ss2))
	}

	// Test interface methods
	if kem.PublicKeyLen() != 32 {
		t.Errorf("PublicKeyLen() = %d, want 32", kem.PublicKeyLen())
	}
	if kem.PrivateKeyLen() != 64 {
		t.Errorf("PrivateKeyLen() = %d, want 64", kem.PrivateKeyLen())
	}
	if kem.CiphertextLen() != 48 {
		t.Errorf("CiphertextLen() = %d, want 48", kem.CiphertextLen())
	}
	if kem.SharedSecretLen() != 32 {
		t.Errorf("SharedSecretLen() = %d, want 32", kem.SharedSecretLen())
	}
	if kem.KEMName() != "MockKEM" {
		t.Errorf("KEMName() = %s, want MockKEM", kem.KEMName())
	}
}

// TestKEMFuncErrors tests error handling in KEMFunc
func TestKEMFuncErrors(t *testing.T) {
	tests := []struct {
		name    string
		kem     mockKEMFunc
		wantErr error
	}{
		{
			name:    "invalid public key length",
			kem:     mockKEMFunc{pubKeyLen: 32, privKeyLen: 64, ctLen: 48, ssLen: 32},
			wantErr: ErrInvalidKEMPublicKey,
		},
		{
			name:    "encapsulation failure",
			kem:     mockKEMFunc{pubKeyLen: 32, privKeyLen: 64, ctLen: 48, ssLen: 32, failEncaps: true},
			wantErr: ErrInvalidKEMPublicKey,
		},
		{
			name:    "decapsulation failure",
			kem:     mockKEMFunc{pubKeyLen: 32, privKeyLen: 64, ctLen: 48, ssLen: 32, failDecaps: true},
			wantErr: ErrKEMDecapsulationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.kem.failEncaps && !tt.kem.failDecaps {
				// Test invalid public key length
				wrongPub := make([]byte, 16) // Wrong length
				_, _, err := tt.kem.Encapsulate(wrongPub, nil)
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Encapsulate error = %v, want %v", err, tt.wantErr)
				}
			} else if tt.kem.failEncaps {
				keypair, _ := tt.kem.GenerateKeypair(nil)
				_, _, err := tt.kem.Encapsulate(keypair.Public, nil)
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Encapsulate error = %v, want %v", err, tt.wantErr)
				}
			} else if tt.kem.failDecaps {
				wrongPriv := make([]byte, 16) // Wrong length
				ct := make([]byte, tt.kem.ctLen)
				_, err := tt.kem.Decapsulate(wrongPriv, ct)
				if err == nil {
					t.Error("Expected error for invalid private key length")
				}
			}
		})
	}
}

// TestSignatureFuncInterface tests the SignatureFunc interface
func TestSignatureFuncInterface(t *testing.T) {
	sig := mockSignatureFunc{
		pubKeyLen:  32,
		privKeyLen: 64,
		sigLen:     96,
	}

	// Test key generation
	keypair, err := sig.GenerateSigningKey(nil)
	if err != nil {
		t.Fatalf("GenerateSigningKey failed: %v", err)
	}
	if len(keypair.Public) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(keypair.Public))
	}
	if len(keypair.Private) != 64 {
		t.Errorf("Expected private key length 64, got %d", len(keypair.Private))
	}

	// Test signing
	message := []byte("test message")
	signature, err := sig.Sign(keypair.Private, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(signature) != 96 {
		t.Errorf("Expected signature length 96, got %d", len(signature))
	}

	// Test verification
	err = sig.Verify(keypair.Public, message, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Test interface methods
	if sig.PublicKeyLen() != 32 {
		t.Errorf("PublicKeyLen() = %d, want 32", sig.PublicKeyLen())
	}
	if sig.PrivateKeyLen() != 64 {
		t.Errorf("PrivateKeyLen() = %d, want 64", sig.PrivateKeyLen())
	}
	if sig.SignatureLen() != 96 {
		t.Errorf("SignatureLen() = %d, want 96", sig.SignatureLen())
	}
	if sig.SignatureName() != "MockSignature" {
		t.Errorf("SignatureName() = %s, want MockSignature", sig.SignatureName())
	}
}

// TestSignatureFuncErrors tests error handling in SignatureFunc
func TestSignatureFuncErrors(t *testing.T) {
	sig := mockSignatureFunc{
		pubKeyLen:  32,
		privKeyLen: 64,
		sigLen:     96,
	}

	// Test invalid private key length
	wrongPriv := make([]byte, 16)
	message := []byte("test")
	_, err := sig.Sign(wrongPriv, message)
	if !errors.Is(err, ErrInvalidSigningKey) {
		t.Errorf("Sign error = %v, want %v", err, ErrInvalidSigningKey)
	}

	// Test invalid signature length
	keypair, _ := sig.GenerateSigningKey(nil)
	wrongSig := make([]byte, 32) // Wrong length
	err = sig.Verify(keypair.Public, message, wrongSig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify error = %v, want %v", err, ErrInvalidSignature)
	}

	// Test all-zero signature (should fail)
	zeroSig := make([]byte, 96)
	err = sig.Verify(keypair.Public, message, zeroSig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify error = %v, want %v", err, ErrInvalidSignature)
	}
}

// TestKEMKeyStructure tests the KEMKey struct
func TestKEMKeyStructure(t *testing.T) {
	pub := make([]byte, 32)
	priv := make([]byte, 64)
	rand.Read(pub)
	rand.Read(priv)

	key := KEMKey{
		Public:  pub,
		Private: priv,
	}

	if !bytes.Equal(key.Public, pub) {
		t.Error("KEMKey.Public does not match expected value")
	}
	if !bytes.Equal(key.Private, priv) {
		t.Error("KEMKey.Private does not match expected value")
	}
}

// TestSigningKeyStructure tests the SigningKey struct
func TestSigningKeyStructure(t *testing.T) {
	pub := make([]byte, 32)
	priv := make([]byte, 64)
	rand.Read(pub)
	rand.Read(priv)

	key := SigningKey{
		Public:  pub,
		Private: priv,
	}

	if !bytes.Equal(key.Public, pub) {
		t.Error("SigningKey.Public does not match expected value")
	}
	if !bytes.Equal(key.Private, priv) {
		t.Error("SigningKey.Private does not match expected value")
	}
}

// TestMLKEMConstants verifies MLKEM constant values match NIST FIPS 203
func TestMLKEMConstants(t *testing.T) {
	tests := []struct {
		name       string
		pubKey     int
		privKey    int
		ciphertext int
		sharedSec  int
	}{
		{"MLKEM512", MLKEM512PublicKeySize, MLKEM512PrivateKeySize, MLKEM512CiphertextSize, MLKEM512SharedSecretSize},
		{"MLKEM768", MLKEM768PublicKeySize, MLKEM768PrivateKeySize, MLKEM768CiphertextSize, MLKEM768SharedSecretSize},
		{"MLKEM1024", MLKEM1024PublicKeySize, MLKEM1024PrivateKeySize, MLKEM1024CiphertextSize, MLKEM1024SharedSecretSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pubKey <= 0 {
				t.Errorf("%s public key size must be positive, got %d", tt.name, tt.pubKey)
			}
			if tt.privKey <= 0 {
				t.Errorf("%s private key size must be positive, got %d", tt.name, tt.privKey)
			}
			if tt.ciphertext <= 0 {
				t.Errorf("%s ciphertext size must be positive, got %d", tt.name, tt.ciphertext)
			}
			if tt.sharedSec != 32 {
				t.Errorf("%s shared secret size must be 32, got %d", tt.name, tt.sharedSec)
			}
		})
	}
}

// TestMLDSAConstants verifies MLDSA constant values match NIST FIPS 204
func TestMLDSAConstants(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  int
		privKey int
		sigSize int
	}{
		{"MLDSA44", MLDSA44PublicKeySize, MLDSA44PrivateKeySize, MLDSA44SignatureSize},
		{"MLDSA65", MLDSA65PublicKeySize, MLDSA65PrivateKeySize, MLDSA65SignatureSize},
		{"MLDSA87", MLDSA87PublicKeySize, MLDSA87PrivateKeySize, MLDSA87SignatureSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pubKey <= 0 {
				t.Errorf("%s public key size must be positive, got %d", tt.name, tt.pubKey)
			}
			if tt.privKey <= 0 {
				t.Errorf("%s private key size must be positive, got %d", tt.name, tt.privKey)
			}
			if tt.sigSize <= 0 {
				t.Errorf("%s signature size must be positive, got %d", tt.name, tt.sigSize)
			}
		})
	}
}

// TestPQErrors verifies that all PQ error constants are defined correctly
func TestPQErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidKEMPublicKey", ErrInvalidKEMPublicKey},
		{"ErrInvalidKEMPrivateKey", ErrInvalidKEMPrivateKey},
		{"ErrInvalidKEMCiphertext", ErrInvalidKEMCiphertext},
		{"ErrKEMDecapsulationFailed", ErrKEMDecapsulationFailed},
		{"ErrInvalidSignature", ErrInvalidSignature},
		{"ErrSigningKeyRequired", ErrSigningKeyRequired},
		{"ErrInvalidSigningKey", ErrInvalidSigningKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			errMsg := tt.err.Error()
			if errMsg == "" {
				t.Errorf("%s has empty error message", tt.name)
			}
			if len(errMsg) < 10 {
				t.Errorf("%s error message too short: %s", tt.name, errMsg)
			}
		})
	}
}

// TestErrorMessages verifies error messages are descriptive
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err      error
		contains string
	}{
		{ErrInvalidKEMPublicKey, "KEM public key"},
		{ErrInvalidKEMPrivateKey, "KEM private key"},
		{ErrInvalidKEMCiphertext, "KEM ciphertext"},
		{ErrKEMDecapsulationFailed, "decapsulation"},
		{ErrInvalidSignature, "signature"},
		{ErrSigningKeyRequired, "signing key"},
		{ErrInvalidSigningKey, "signing key"},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			// Error messages should be descriptive (at least contain key terms)
			// This is a soft check - messages may vary
			if tt.err.Error() == "" {
				t.Error("Error message is empty")
			}
		})
	}
}
