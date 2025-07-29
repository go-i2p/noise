package noise

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"testing"
	"unsafe"
)

// TestMemoryZeroingIssue validates that sensitive key material is not properly zeroed
// This test demonstrates the security vulnerability before we fix it
func TestMemoryZeroingIssue(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	
	// Generate a keypair to test with
	key, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	
	// Store reference to the private key memory location
	privateKeyData := make([]byte, len(key.Private))
	copy(privateKeyData, key.Private)
	privateKeyPtr := (*byte)(unsafe.Pointer(&key.Private[0]))
	
	// Perform a DH operation to generate shared secret
	peerKey, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	
	sharedSecret, err := cs.DH(key.Private, peerKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	
	// Store reference to shared secret memory
	sharedSecretData := make([]byte, len(sharedSecret))
	copy(sharedSecretData, sharedSecret)
	sharedSecretPtr := (*byte)(unsafe.Pointer(&sharedSecret[0]))
	
	// Clear our local references
	key.Private = nil
	sharedSecret = nil
	
	// Force garbage collection
	runtime.GC()
	runtime.GC()
	
	// Check if the sensitive data is still in memory at the original locations
	// This demonstrates the vulnerability - sensitive data remains in memory
	privateKeyStillInMemory := make([]byte, len(privateKeyData))
	for i := 0; i < len(privateKeyData); i++ {
		privateKeyStillInMemory[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(privateKeyPtr)) + uintptr(i)))
	}
	
	sharedSecretStillInMemory := make([]byte, len(sharedSecretData))
	for i := 0; i < len(sharedSecretData); i++ {
		sharedSecretStillInMemory[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(sharedSecretPtr)) + uintptr(i)))
	}
	
	// These assertions demonstrate the security issue: sensitive data remains in memory
	if bytes.Equal(privateKeyStillInMemory, privateKeyData) {
		t.Logf("SECURITY ISSUE: Private key data still in memory: %x", privateKeyStillInMemory[:8])
	}
	
	if bytes.Equal(sharedSecretStillInMemory, sharedSecretData) {
		t.Logf("SECURITY ISSUE: Shared secret still in memory: %x", sharedSecretStillInMemory[:8])
	}
	
	// The test "passes" but logs the security issues - this validates the vulnerability exists
	// After we implement secure zeroing, these checks should show that memory has been cleared
}

// TestCipherStateKeyMaterial tests that CipherState doesn't zero key material
func TestCipherStateKeyMaterial(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	
	// Create a cipher state with a known key
	var testKey [32]byte
	copy(testKey[:], "this_is_a_test_key_32_bytes!")
	
	cipher := cs.Cipher(testKey)
	cipherState := &CipherState{
		cs: cs,
		c:  cipher,
		k:  testKey,
		n:  0,
	}
	
	// Store reference to the key
	originalKey := make([]byte, 32)
	copy(originalKey, testKey[:])
	keyPtr := (*byte)(unsafe.Pointer(&cipherState.k[0]))
	
	// Use the cipher state
	plaintext := []byte("hello world")
	ciphertext, err := cipherState.Encrypt(nil, nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	
	// Reset nonce for decryption since it was incremented during encryption
	cipherState.n = 0
	
	// Decrypt to verify it works
	decrypted, err := cipherState.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("encryption/decryption failed")
	}
	
	// Clear our reference
	cipherState = nil
	
	// Force garbage collection
	runtime.GC()
	runtime.GC()
	
	// Check if the key data is still in memory
	keyStillInMemory := make([]byte, 32)
	for i := 0; i < 32; i++ {
		keyStillInMemory[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(keyPtr)) + uintptr(i)))
	}
	
	if bytes.Equal(keyStillInMemory, originalKey) {
		t.Logf("SECURITY ISSUE: CipherState key still in memory: %x", keyStillInMemory[:8])
	}
}

// TestHKDFIntermediateSecrets tests that HKDF doesn't zero intermediate secrets
func TestHKDFIntermediateSecrets(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	
	chainingKey := make([]byte, 32)
	inputKeyMaterial := make([]byte, 32)
	copy(chainingKey, "chaining_key_32_bytes_long!!")
	copy(inputKeyMaterial, "input_key_material_32_bytes!")
	
	// Call HKDF which should generate intermediate secrets
	out1, out2, out3 := hkdf(cs.Hash, 3, nil, nil, nil, chainingKey, inputKeyMaterial)
	
	// Store references
	out1Data := make([]byte, len(out1))
	out2Data := make([]byte, len(out2))
	out3Data := make([]byte, len(out3))
	copy(out1Data, out1)
	copy(out2Data, out2)
	copy(out3Data, out3)
	
	out1Ptr := (*byte)(unsafe.Pointer(&out1[0]))
	out2Ptr := (*byte)(unsafe.Pointer(&out2[0]))
	out3Ptr := (*byte)(unsafe.Pointer(&out3[0]))
	
	// Clear references
	out1 = nil
	out2 = nil
	out3 = nil
	
	// Force garbage collection
	runtime.GC()
	runtime.GC()
	
	// Check if outputs are still in memory
	checkMemory := func(ptr *byte, original []byte, name string) {
		stillInMemory := make([]byte, len(original))
		for i := 0; i < len(original); i++ {
			stillInMemory[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)))
		}
		if bytes.Equal(stillInMemory, original) {
			t.Logf("SECURITY ISSUE: HKDF %s still in memory: %x", name, stillInMemory[:8])
		}
	}
	
	checkMemory(out1Ptr, out1Data, "output1")
	checkMemory(out2Ptr, out2Data, "output2") 
	checkMemory(out3Ptr, out3Data, "output3")
}
