package noise

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestMLKEM512Implementation verifies the basic functionality of MLKEM-512.
func TestMLKEM512Implementation(t *testing.T) {
	kem := KEMMLKEM512

	// Test key generation
	key, err := kem.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Verify key sizes
	if len(key.Public) != MLKEM512PublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(key.Public), MLKEM512PublicKeySize)
	}
	if len(key.Private) != MLKEM512PrivateKeySize {
		t.Errorf("Private key size: got %d, want %d", len(key.Private), MLKEM512PrivateKeySize)
	}

	// Test encapsulation
	ct, ss1, err := kem.Encapsulate(key.Public, nil)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Verify ciphertext and shared secret sizes
	if len(ct) != MLKEM512CiphertextSize {
		t.Errorf("Ciphertext size: got %d, want %d", len(ct), MLKEM512CiphertextSize)
	}
	if len(ss1) != MLKEM512SharedSecretSize {
		t.Errorf("Shared secret size: got %d, want %d", len(ss1), MLKEM512SharedSecretSize)
	}

	// Test decapsulation
	ss2, err := kem.Decapsulate(key.Private, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(ss1, ss2) {
		t.Error("Shared secrets do not match")
	}

	// Cleanup
	secureZero(key.Public)
	secureZero(key.Private)
	secureZero(ss1)
	secureZero(ss2)
}

// TestMLKEM768Implementation verifies the basic functionality of MLKEM-768.
func TestMLKEM768Implementation(t *testing.T) {
	kem := KEMMLKEM768

	// Test key generation
	key, err := kem.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Verify key sizes
	if len(key.Public) != MLKEM768PublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(key.Public), MLKEM768PublicKeySize)
	}
	if len(key.Private) != MLKEM768PrivateKeySize {
		t.Errorf("Private key size: got %d, want %d", len(key.Private), MLKEM768PrivateKeySize)
	}

	// Test encapsulation
	ct, ss1, err := kem.Encapsulate(key.Public, nil)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Verify ciphertext and shared secret sizes
	if len(ct) != MLKEM768CiphertextSize {
		t.Errorf("Ciphertext size: got %d, want %d", len(ct), MLKEM768CiphertextSize)
	}
	if len(ss1) != MLKEM768SharedSecretSize {
		t.Errorf("Shared secret size: got %d, want %d", len(ss1), MLKEM768SharedSecretSize)
	}

	// Test decapsulation
	ss2, err := kem.Decapsulate(key.Private, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(ss1, ss2) {
		t.Error("Shared secrets do not match")
	}

	// Cleanup
	secureZero(key.Public)
	secureZero(key.Private)
	secureZero(ss1)
	secureZero(ss2)
}

// TestMLKEM1024Implementation verifies the basic functionality of MLKEM-1024.
func TestMLKEM1024Implementation(t *testing.T) {
	kem := KEMMLKEM1024

	// Test key generation
	key, err := kem.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Verify key sizes
	if len(key.Public) != MLKEM1024PublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(key.Public), MLKEM1024PublicKeySize)
	}
	if len(key.Private) != MLKEM1024PrivateKeySize {
		t.Errorf("Private key size: got %d, want %d", len(key.Private), MLKEM1024PrivateKeySize)
	}

	// Test encapsulation
	ct, ss1, err := kem.Encapsulate(key.Public, nil)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Verify ciphertext and shared secret sizes
	if len(ct) != MLKEM1024CiphertextSize {
		t.Errorf("Ciphertext size: got %d, want %d", len(ct), MLKEM1024CiphertextSize)
	}
	if len(ss1) != MLKEM1024SharedSecretSize {
		t.Errorf("Shared secret size: got %d, want %d", len(ss1), MLKEM1024SharedSecretSize)
	}

	// Test decapsulation
	ss2, err := kem.Decapsulate(key.Private, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(ss1, ss2) {
		t.Error("Shared secrets do not match")
	}

	// Cleanup
	secureZero(key.Public)
	secureZero(key.Private)
	secureZero(ss1)
	secureZero(ss2)
}

// TestMLKEMInvalidPublicKey tests error handling for invalid public keys.
func TestMLKEMInvalidPublicKey(t *testing.T) {
	tests := []struct {
		name     string
		kem      KEMFunc
		keySize  int
		wantSize int
	}{
		{"MLKEM512 wrong size", KEMMLKEM512, 100, MLKEM512PublicKeySize},
		{"MLKEM768 wrong size", KEMMLKEM768, 100, MLKEM768PublicKeySize},
		{"MLKEM1024 wrong size", KEMMLKEM1024, 100, MLKEM1024PublicKeySize},
		{"MLKEM512 empty", KEMMLKEM512, 0, MLKEM512PublicKeySize},
		{"MLKEM768 empty", KEMMLKEM768, 0, MLKEM768PublicKeySize},
		{"MLKEM1024 empty", KEMMLKEM1024, 0, MLKEM1024PublicKeySize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidKey := make([]byte, tt.keySize)
			_, _, err := tt.kem.Encapsulate(invalidKey, nil)
			if err != ErrInvalidKEMPublicKey {
				t.Errorf("Expected ErrInvalidKEMPublicKey for key size %d (want %d), got: %v",
					tt.keySize, tt.wantSize, err)
			}
		})
	}
}

// TestMLKEMInvalidPrivateKey tests error handling for invalid private keys.
func TestMLKEMInvalidPrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		kem      KEMFunc
		keySize  int
		ctSize   int
		wantSize int
	}{
		{"MLKEM512 wrong size", KEMMLKEM512, 100, MLKEM512CiphertextSize, MLKEM512PrivateKeySize},
		{"MLKEM768 wrong size", KEMMLKEM768, 100, MLKEM768CiphertextSize, MLKEM768PrivateKeySize},
		{"MLKEM1024 wrong size", KEMMLKEM1024, 100, MLKEM1024CiphertextSize, MLKEM1024PrivateKeySize},
		{"MLKEM512 empty", KEMMLKEM512, 0, MLKEM512CiphertextSize, MLKEM512PrivateKeySize},
		{"MLKEM768 empty", KEMMLKEM768, 0, MLKEM768CiphertextSize, MLKEM768PrivateKeySize},
		{"MLKEM1024 empty", KEMMLKEM1024, 0, MLKEM1024CiphertextSize, MLKEM1024PrivateKeySize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidKey := make([]byte, tt.keySize)
			ct := make([]byte, tt.ctSize)
			_, err := tt.kem.Decapsulate(invalidKey, ct)
			if err != ErrInvalidKEMPrivateKey {
				t.Errorf("Expected ErrInvalidKEMPrivateKey for key size %d (want %d), got: %v",
					tt.keySize, tt.wantSize, err)
			}
		})
	}
}

// TestMLKEMInvalidCiphertext tests error handling for invalid ciphertexts.
func TestMLKEMInvalidCiphertext(t *testing.T) {
	tests := []struct {
		name     string
		kem      KEMFunc
		ctSize   int
		wantSize int
	}{
		{"MLKEM512 wrong size", KEMMLKEM512, 100, MLKEM512CiphertextSize},
		{"MLKEM768 wrong size", KEMMLKEM768, 100, MLKEM768CiphertextSize},
		{"MLKEM1024 wrong size", KEMMLKEM1024, 100, MLKEM1024CiphertextSize},
		{"MLKEM512 empty", KEMMLKEM512, 0, MLKEM512CiphertextSize},
		{"MLKEM768 empty", KEMMLKEM768, 0, MLKEM768CiphertextSize},
		{"MLKEM1024 empty", KEMMLKEM1024, 0, MLKEM1024CiphertextSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a valid key to use
			key, err := tt.kem.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			defer func() {
				secureZero(key.Public)
				secureZero(key.Private)
			}()

			invalidCt := make([]byte, tt.ctSize)
			_, err = tt.kem.Decapsulate(key.Private, invalidCt)
			if err != ErrInvalidKEMCiphertext {
				t.Errorf("Expected ErrInvalidKEMCiphertext for ct size %d (want %d), got: %v",
					tt.ctSize, tt.wantSize, err)
			}
		})
	}
}

// TestMLKEMDeterministicRNG tests that using a deterministic RNG produces deterministic results.
func TestMLKEMDeterministicRNG(t *testing.T) {
	// Create a deterministic RNG for testing
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	tests := []struct {
		name string
		kem  KEMFunc
	}{
		{"MLKEM512", KEMMLKEM512},
		{"MLKEM768", KEMMLKEM768},
		{"MLKEM1024", KEMMLKEM1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a deterministic RNG
			rng1 := &deterministicRNG{seed: seed}
			rng2 := &deterministicRNG{seed: seed}

			// Generate two keypairs with the same seed
			key1, err := tt.kem.GenerateKeypair(rng1)
			if err != nil {
				t.Fatalf("GenerateKeypair 1 failed: %v", err)
			}

			key2, err := tt.kem.GenerateKeypair(rng2)
			if err != nil {
				t.Fatalf("GenerateKeypair 2 failed: %v", err)
			}

			// Keys should be identical with deterministic RNG
			if !bytes.Equal(key1.Public, key2.Public) {
				t.Error("Public keys differ with same deterministic RNG")
			}
			if !bytes.Equal(key1.Private, key2.Private) {
				t.Error("Private keys differ with same deterministic RNG")
			}

			// Cleanup
			secureZero(key1.Public)
			secureZero(key1.Private)
			secureZero(key2.Public)
			secureZero(key2.Private)
		})
	}
}

// TestMLKEMCiphertextUniqueness verifies that different encapsulations produce different ciphertexts.
func TestMLKEMCiphertextUniqueness(t *testing.T) {
	tests := []struct {
		name string
		kem  KEMFunc
	}{
		{"MLKEM512", KEMMLKEM512},
		{"MLKEM768", KEMMLKEM768},
		{"MLKEM1024", KEMMLKEM1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.kem.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair failed: %v", err)
			}
			defer func() {
				secureZero(key.Public)
				secureZero(key.Private)
			}()

			// Generate multiple encapsulations
			ct1, ss1, err := tt.kem.Encapsulate(key.Public, nil)
			if err != nil {
				t.Fatalf("Encapsulate 1 failed: %v", err)
			}
			defer secureZero(ss1)

			ct2, ss2, err := tt.kem.Encapsulate(key.Public, nil)
			if err != nil {
				t.Fatalf("Encapsulate 2 failed: %v", err)
			}
			defer secureZero(ss2)

			// Ciphertexts should be different (randomized encapsulation)
			if bytes.Equal(ct1, ct2) {
				t.Error("Ciphertexts are identical (should be randomized)")
			}

			// Shared secrets should be different
			if bytes.Equal(ss1, ss2) {
				t.Error("Shared secrets are identical (should be different)")
			}
		})
	}
}

// TestMLKEMCrossDecapsulation verifies that a ciphertext from one key cannot be decapsulated with another.
func TestMLKEMCrossDecapsulation(t *testing.T) {
	tests := []struct {
		name string
		kem  KEMFunc
	}{
		{"MLKEM512", KEMMLKEM512},
		{"MLKEM768", KEMMLKEM768},
		{"MLKEM1024", KEMMLKEM1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate two different keypairs
			key1, err := tt.kem.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair 1 failed: %v", err)
			}
			defer func() {
				secureZero(key1.Public)
				secureZero(key1.Private)
			}()

			key2, err := tt.kem.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair 2 failed: %v", err)
			}
			defer func() {
				secureZero(key2.Public)
				secureZero(key2.Private)
			}()

			// Encapsulate to key1
			ct, ss1, err := tt.kem.Encapsulate(key1.Public, nil)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}
			defer secureZero(ss1)

			// Decapsulate with key1 (should work)
			ss2, err := tt.kem.Decapsulate(key1.Private, ct)
			if err != nil {
				t.Fatalf("Decapsulate with correct key failed: %v", err)
			}
			defer secureZero(ss2)

			if !bytes.Equal(ss1, ss2) {
				t.Error("Shared secrets don't match with correct key")
			}

			// Decapsulate with key2 (should produce different shared secret)
			ss3, err := tt.kem.Decapsulate(key2.Private, ct)
			if err != nil {
				t.Fatalf("Decapsulate with wrong key failed: %v", err)
			}
			defer secureZero(ss3)

			// The shared secret should be different (MLKEM doesn't fail on wrong key,
			// but produces a different shared secret due to FO transform)
			if bytes.Equal(ss1, ss3) {
				t.Error("Shared secrets match with wrong key (should differ)")
			}
		})
	}
}

// TestMLKEMSizeMethods verifies the size reporting methods.
func TestMLKEMSizeMethods(t *testing.T) {
	tests := []struct {
		name                 string
		kem                  KEMFunc
		wantPublicKeySize    int
		wantPrivateKeySize   int
		wantCiphertextSize   int
		wantSharedSecretSize int
	}{
		{
			name:                 "MLKEM512",
			kem:                  KEMMLKEM512,
			wantPublicKeySize:    MLKEM512PublicKeySize,
			wantPrivateKeySize:   MLKEM512PrivateKeySize,
			wantCiphertextSize:   MLKEM512CiphertextSize,
			wantSharedSecretSize: MLKEM512SharedSecretSize,
		},
		{
			name:                 "MLKEM768",
			kem:                  KEMMLKEM768,
			wantPublicKeySize:    MLKEM768PublicKeySize,
			wantPrivateKeySize:   MLKEM768PrivateKeySize,
			wantCiphertextSize:   MLKEM768CiphertextSize,
			wantSharedSecretSize: MLKEM768SharedSecretSize,
		},
		{
			name:                 "MLKEM1024",
			kem:                  KEMMLKEM1024,
			wantPublicKeySize:    MLKEM1024PublicKeySize,
			wantPrivateKeySize:   MLKEM1024PrivateKeySize,
			wantCiphertextSize:   MLKEM1024CiphertextSize,
			wantSharedSecretSize: MLKEM1024SharedSecretSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kem.PublicKeyLen(); got != tt.wantPublicKeySize {
				t.Errorf("PublicKeyLen() = %d, want %d", got, tt.wantPublicKeySize)
			}
			if got := tt.kem.PrivateKeyLen(); got != tt.wantPrivateKeySize {
				t.Errorf("PrivateKeyLen() = %d, want %d", got, tt.wantPrivateKeySize)
			}
			if got := tt.kem.CiphertextLen(); got != tt.wantCiphertextSize {
				t.Errorf("CiphertextLen() = %d, want %d", got, tt.wantCiphertextSize)
			}
			if got := tt.kem.SharedSecretLen(); got != tt.wantSharedSecretSize {
				t.Errorf("SharedSecretLen() = %d, want %d", got, tt.wantSharedSecretSize)
			}
		})
	}
}

// deterministicRNG is a simple deterministic RNG for testing.
type deterministicRNG struct {
	seed  []byte
	index int
}

func (d *deterministicRNG) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = d.seed[d.index%len(d.seed)]
		d.index++
	}
	return len(p), nil
}

// TestMLKEMMemoryZeroing verifies that key material is properly zeroed.
func TestMLKEMMemoryZeroing(t *testing.T) {
	tests := []struct {
		name string
		kem  KEMFunc
	}{
		{"MLKEM512", KEMMLKEM512},
		{"MLKEM768", KEMMLKEM768},
		{"MLKEM1024", KEMMLKEM1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.kem.GenerateKeypair(nil)
			if err != nil {
				t.Fatalf("GenerateKeypair failed: %v", err)
			}

			// Make copies to verify zeroing
			pubCopy := make([]byte, len(key.Public))
			privCopy := make([]byte, len(key.Private))
			copy(pubCopy, key.Public)
			copy(privCopy, key.Private)

			// Zero the keys
			secureZero(key.Public)
			secureZero(key.Private)

			// Verify keys are zeroed
			for i, b := range key.Public {
				if b != 0 {
					t.Errorf("Public key byte %d not zeroed: %d", i, b)
					break
				}
			}
			for i, b := range key.Private {
				if b != 0 {
					t.Errorf("Private key byte %d not zeroed: %d", i, b)
					break
				}
			}

			// Verify copies are not zeroed (to ensure we actually had data)
			pubNonZero := false
			privNonZero := false
			for _, b := range pubCopy {
				if b != 0 {
					pubNonZero = true
					break
				}
			}
			for _, b := range privCopy {
				if b != 0 {
					privNonZero = true
					break
				}
			}
			if !pubNonZero {
				t.Error("Public key copy is all zeros (test invalid)")
			}
			if !privNonZero {
				t.Error("Private key copy is all zeros (test invalid)")
			}
		})
	}
}

// BenchmarkMLKEM512KeyGen benchmarks MLKEM-512 key generation.
func BenchmarkMLKEM512KeyGen(b *testing.B) {
	kem := KEMMLKEM512
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := kem.GenerateKeypair(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		secureZero(key.Public)
		secureZero(key.Private)
	}
}

// BenchmarkMLKEM512Encapsulate benchmarks MLKEM-512 encapsulation.
func BenchmarkMLKEM512Encapsulate(b *testing.B) {
	kem := KEMMLKEM512
	key, err := kem.GenerateKeypair(nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		secureZero(key.Public)
		secureZero(key.Private)
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, ss, err := kem.Encapsulate(key.Public, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		_ = ct
		secureZero(ss)
	}
}

// BenchmarkMLKEM512Decapsulate benchmarks MLKEM-512 decapsulation.
func BenchmarkMLKEM512Decapsulate(b *testing.B) {
	kem := KEMMLKEM512
	key, err := kem.GenerateKeypair(nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		secureZero(key.Public)
		secureZero(key.Private)
	}()

	ct, ss1, err := kem.Encapsulate(key.Public, nil)
	if err != nil {
		b.Fatal(err)
	}
	secureZero(ss1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ss, err := kem.Decapsulate(key.Private, ct)
		if err != nil {
			b.Fatal(err)
		}
		secureZero(ss)
	}
}

// BenchmarkMLKEM768KeyGen benchmarks MLKEM-768 key generation.
func BenchmarkMLKEM768KeyGen(b *testing.B) {
	kem := KEMMLKEM768
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := kem.GenerateKeypair(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		secureZero(key.Public)
		secureZero(key.Private)
	}
}

// BenchmarkMLKEM1024KeyGen benchmarks MLKEM-1024 key generation.
func BenchmarkMLKEM1024KeyGen(b *testing.B) {
	kem := KEMMLKEM1024
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := kem.GenerateKeypair(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		secureZero(key.Public)
		secureZero(key.Private)
	}
}
