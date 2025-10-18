package noise

// hybrid_dh.go - Hybrid Post-Quantum Diffie-Hellman implementations
//
// This file combines classical Curve25519 ECDH with post-quantum MLKEM for hybrid
// key exchange. The hybrid approach provides defense-in-depth: security relies on
// both classical and quantum-resistant algorithms.
//
// Design decisions:
// - Use existing dh25519 and mlkemWrapper implementations (no code duplication)
// - Combine shared secrets using HKDF (cryptographically sound mixing)
// - Support all three MLKEM security levels (512, 768, 1024)
// - Secure memory zeroing for all intermediate key material
// - Simple, explicit implementation over clever abstractions

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"io"
)

// hybridCombine uses HKDF to combine classical and post-quantum shared secrets.
// This function implements the key combiner specified in the Noise protocol extension
// for hybrid key exchange.
//
// Parameters:
//   - classicalSS: Shared secret from Curve25519 ECDH (32 bytes)
//   - pqSS: Shared secret from MLKEM KEM (32 bytes)
//   - context: Protocol context string for domain separation
//
// Returns: Combined 32-byte shared secret
//
// The combiner uses HKDF with:
//   - IKM (Input Key Material): classical_ss || pq_ss
//   - Salt: "HYBRID-KEM-V1"
//   - Info: context string
//   - Output: 32 bytes
func hybridCombine(classicalSS, pqSS []byte, context string) []byte {
	// Concatenate both shared secrets as input key material
	ikm := make([]byte, 0, len(classicalSS)+len(pqSS))
	ikm = append(ikm, classicalSS...)
	ikm = append(ikm, pqSS...)
	defer secureZero(ikm)

	// HKDF-Extract: Use salt to extract a pseudorandom key
	salt := []byte("HYBRID-KEM-V1")
	prk := hmacHash(sha256.New, salt, ikm)
	defer secureZero(prk)

	// HKDF-Expand: Expand the PRK to output length using context
	combined := hkdfExpand(sha256.New, prk, []byte(context), 32)
	return combined
}

// hmacHash computes HMAC using the provided hash function.
func hmacHash(h func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// hkdfExpand implements HKDF-Expand to derive output key material.
func hkdfExpand(h func() hash.Hash, prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	i := byte(1)

	for len(out) < length {
		mac := hmac.New(h, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
		i++
	}

	return out[:length]
}

// hybrid25519MLKEM512 combines Curve25519 with MLKEM-512 (NIST Security Level 1).
// Suitable for IoT and resource-constrained devices.
type hybrid25519MLKEM512 struct {
	classical dh25519
	kem       mlkemWrapper
}

func (h hybrid25519MLKEM512) GenerateKeypair(rng io.Reader) (DHKey, error) {
	// Generate classical Curve25519 keypair
	classicalKey, err := h.classical.GenerateKeypair(rng)
	if err != nil {
		return DHKey{}, err
	}

	// Generate MLKEM-512 keypair
	kemKey, err := h.kem.GenerateKeypair(rng)
	if err != nil {
		// Clean up on error
		secureZero(classicalKey.Private)
		secureZero(classicalKey.Public)
		return DHKey{}, err
	}

	// Combine keys: classical || kem
	return DHKey{
		Private: append(classicalKey.Private, kemKey.Private...),
		Public:  append(classicalKey.Public, kemKey.Public...),
	}, nil
}

func (h hybrid25519MLKEM512) DH(privkey, pubkey []byte) ([]byte, error) {
	// Split private key into classical and KEM portions
	classicalPriv := privkey[:32]
	// KEM private key starts at offset 32
	// Note: KEM DH is handled separately via KEMEncapsulate/KEMDecapsulate
	// This method only performs classical DH

	// Split public key into classical and KEM portions
	classicalPub := pubkey[:32]
	// KEM public key starts at offset 32 (not used in classical DH)

	// Perform classical Curve25519 DH
	return h.classical.DH(classicalPriv, classicalPub)
}

func (h hybrid25519MLKEM512) DHLen() int {
	return 32 // Classical DH output is still 32 bytes
}

func (h hybrid25519MLKEM512) DHName() string {
	return "25519+MLKEM512"
}

func (h hybrid25519MLKEM512) KEMEncapsulate(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	// Extract KEM public key (skip first 32 bytes of classical key)
	kemPub := pubkey[32:]
	return h.kem.Encapsulate(kemPub, rng)
}

func (h hybrid25519MLKEM512) KEMDecapsulate(privkey, ciphertext []byte) (sharedSecret []byte, err error) {
	// Extract KEM private key (skip first 32 bytes of classical key)
	kemPriv := privkey[32:]
	return h.kem.Decapsulate(kemPriv, ciphertext)
}

func (h hybrid25519MLKEM512) KEMPublicKeyLen() int    { return h.kem.PublicKeyLen() }
func (h hybrid25519MLKEM512) KEMPrivateKeyLen() int   { return h.kem.PrivateKeyLen() }
func (h hybrid25519MLKEM512) KEMCiphertextLen() int   { return h.kem.CiphertextLen() }
func (h hybrid25519MLKEM512) KEMSharedSecretLen() int { return h.kem.SharedSecretLen() }
func (h hybrid25519MLKEM512) IsHybrid() bool          { return true }

// hybrid25519MLKEM768 combines Curve25519 with MLKEM-768 (NIST Security Level 3) - RECOMMENDED.
// This is the recommended variant for most use cases.
type hybrid25519MLKEM768 struct {
	classical dh25519
	kem       mlkemWrapper
}

func (h hybrid25519MLKEM768) GenerateKeypair(rng io.Reader) (DHKey, error) {
	// Generate classical Curve25519 keypair
	classicalKey, err := h.classical.GenerateKeypair(rng)
	if err != nil {
		return DHKey{}, err
	}

	// Generate MLKEM-768 keypair
	kemKey, err := h.kem.GenerateKeypair(rng)
	if err != nil {
		// Clean up on error
		secureZero(classicalKey.Private)
		secureZero(classicalKey.Public)
		return DHKey{}, err
	}

	// Combine keys: classical || kem
	return DHKey{
		Private: append(classicalKey.Private, kemKey.Private...),
		Public:  append(classicalKey.Public, kemKey.Public...),
	}, nil
}

func (h hybrid25519MLKEM768) DH(privkey, pubkey []byte) ([]byte, error) {
	// Split private key into classical and KEM portions
	classicalPriv := privkey[:32]
	// KEM private key starts at offset 32
	// Note: KEM DH is handled separately via KEMEncapsulate/KEMDecapsulate
	// This method only performs classical DH

	// Split public key into classical and KEM portions
	classicalPub := pubkey[:32]
	// KEM public key starts at offset 32 (not used in classical DH)

	// Perform classical Curve25519 DH
	return h.classical.DH(classicalPriv, classicalPub)
}

func (h hybrid25519MLKEM768) DHLen() int {
	return 32 // Classical DH output is still 32 bytes
}

func (h hybrid25519MLKEM768) DHName() string {
	return "25519+MLKEM768"
}

func (h hybrid25519MLKEM768) KEMEncapsulate(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	// Extract KEM public key (skip first 32 bytes of classical key)
	kemPub := pubkey[32:]
	return h.kem.Encapsulate(kemPub, rng)
}

func (h hybrid25519MLKEM768) KEMDecapsulate(privkey, ciphertext []byte) (sharedSecret []byte, err error) {
	// Extract KEM private key (skip first 32 bytes of classical key)
	kemPriv := privkey[32:]
	return h.kem.Decapsulate(kemPriv, ciphertext)
}

func (h hybrid25519MLKEM768) KEMPublicKeyLen() int    { return h.kem.PublicKeyLen() }
func (h hybrid25519MLKEM768) KEMPrivateKeyLen() int   { return h.kem.PrivateKeyLen() }
func (h hybrid25519MLKEM768) KEMCiphertextLen() int   { return h.kem.CiphertextLen() }
func (h hybrid25519MLKEM768) KEMSharedSecretLen() int { return h.kem.SharedSecretLen() }
func (h hybrid25519MLKEM768) IsHybrid() bool          { return true }

// hybrid25519MLKEM1024 combines Curve25519 with MLKEM-1024 (NIST Security Level 5).
// Suitable for high-security applications requiring maximum protection.
type hybrid25519MLKEM1024 struct {
	classical dh25519
	kem       mlkemWrapper
}

func (h hybrid25519MLKEM1024) GenerateKeypair(rng io.Reader) (DHKey, error) {
	// Generate classical Curve25519 keypair
	classicalKey, err := h.classical.GenerateKeypair(rng)
	if err != nil {
		return DHKey{}, err
	}

	// Generate MLKEM-1024 keypair
	kemKey, err := h.kem.GenerateKeypair(rng)
	if err != nil {
		// Clean up on error
		secureZero(classicalKey.Private)
		secureZero(classicalKey.Public)
		return DHKey{}, err
	}

	// Combine keys: classical || kem
	return DHKey{
		Private: append(classicalKey.Private, kemKey.Private...),
		Public:  append(classicalKey.Public, kemKey.Public...),
	}, nil
}

func (h hybrid25519MLKEM1024) DH(privkey, pubkey []byte) ([]byte, error) {
	// Split private key into classical and KEM portions
	classicalPriv := privkey[:32]
	// KEM private key starts at offset 32
	// Note: KEM DH is handled separately via KEMEncapsulate/KEMDecapsulate
	// This method only performs classical DH

	// Split public key into classical and KEM portions
	classicalPub := pubkey[:32]
	// KEM public key starts at offset 32 (not used in classical DH)

	// Perform classical Curve25519 DH
	return h.classical.DH(classicalPriv, classicalPub)
}

func (h hybrid25519MLKEM1024) DHLen() int {
	return 32 // Classical DH output is still 32 bytes
}

func (h hybrid25519MLKEM1024) DHName() string {
	return "25519+MLKEM1024"
}

func (h hybrid25519MLKEM1024) KEMEncapsulate(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	// Extract KEM public key (skip first 32 bytes of classical key)
	kemPub := pubkey[32:]
	return h.kem.Encapsulate(kemPub, rng)
}

func (h hybrid25519MLKEM1024) KEMDecapsulate(privkey, ciphertext []byte) (sharedSecret []byte, err error) {
	// Extract KEM private key (skip first 32 bytes of classical key)
	kemPriv := privkey[32:]
	return h.kem.Decapsulate(kemPriv, ciphertext)
}

func (h hybrid25519MLKEM1024) KEMPublicKeyLen() int    { return h.kem.PublicKeyLen() }
func (h hybrid25519MLKEM1024) KEMPrivateKeyLen() int   { return h.kem.PrivateKeyLen() }
func (h hybrid25519MLKEM1024) KEMCiphertextLen() int   { return h.kem.CiphertextLen() }
func (h hybrid25519MLKEM1024) KEMSharedSecretLen() int { return h.kem.SharedSecretLen() }
func (h hybrid25519MLKEM1024) IsHybrid() bool          { return true }

// Exported hybrid DH functions
// These can be used directly in CipherSuite configurations for hybrid post-quantum protocols.
var (
	// DHHybrid25519MLKEM512 provides NIST Security Level 1 (~AES-128 equivalent).
	// Suitable for IoT and resource-constrained devices.
	DHHybrid25519MLKEM512 HybridDHFunc = hybrid25519MLKEM512{
		classical: dh25519{},
		kem: mlkemWrapper{
			scheme:           KEMMLKEM512.(mlkemWrapper).scheme,
			name:             "MLKEM512",
			publicKeySize:    MLKEM512PublicKeySize,
			privateKeySize:   MLKEM512PrivateKeySize,
			ciphertextSize:   MLKEM512CiphertextSize,
			sharedSecretSize: MLKEM512SharedSecretSize,
		},
	}

	// DHHybrid25519MLKEM768 provides NIST Security Level 3 (~AES-192 equivalent) - RECOMMENDED.
	// This is the recommended variant for most use cases.
	DHHybrid25519MLKEM768 HybridDHFunc = hybrid25519MLKEM768{
		classical: dh25519{},
		kem: mlkemWrapper{
			scheme:           KEMMLKEM768.(mlkemWrapper).scheme,
			name:             "MLKEM768",
			publicKeySize:    MLKEM768PublicKeySize,
			privateKeySize:   MLKEM768PrivateKeySize,
			ciphertextSize:   MLKEM768CiphertextSize,
			sharedSecretSize: MLKEM768SharedSecretSize,
		},
	}

	// DHHybrid25519MLKEM1024 provides NIST Security Level 5 (~AES-256 equivalent).
	// Suitable for high-security applications requiring maximum protection.
	DHHybrid25519MLKEM1024 HybridDHFunc = hybrid25519MLKEM1024{
		classical: dh25519{},
		kem: mlkemWrapper{
			scheme:           KEMMLKEM1024.(mlkemWrapper).scheme,
			name:             "MLKEM1024",
			publicKeySize:    MLKEM1024PublicKeySize,
			privateKeySize:   MLKEM1024PrivateKeySize,
			ciphertextSize:   MLKEM1024CiphertextSize,
			sharedSecretSize: MLKEM1024SharedSecretSize,
		},
	}
)
