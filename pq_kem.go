package noise

// pq_kem.go - Post-Quantum Key Encapsulation Mechanism (KEM) implementations
//
// This file provides wrappers around the Cloudflare CIRCL library's ML-KEM
// (Module-Lattice-Based Key Encapsulation Mechanism) implementations, conforming
// to NIST FIPS 203. These wrappers implement the KEMFunc interface defined in types.go.
//
// Design decisions:
// - Use CIRCL library instead of custom crypto (well-tested, FIPS-compliant)
// - Implement all three security levels (512, 768, 1024) for flexibility
// - MLKEM-768 is recommended as it provides NIST Security Level 3 (~AES-192)
// - Secure memory zeroing is applied to sensitive key material
// - Use CIRCL's kem.Scheme interface to avoid code duplication

import (
	"crypto/rand"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// mlkemWrapper is a generic wrapper around CIRCL's kem.Scheme interface.
// It eliminates code duplication while keeping the implementation explicit.
type mlkemWrapper struct {
	scheme           kem.Scheme
	name             string
	publicKeySize    int
	privateKeySize   int
	ciphertextSize   int
	sharedSecretSize int
}

// GenerateKeypair generates a new KEM keypair.
// If rng is nil, crypto/rand.Reader is used for cryptographically secure randomness.
func (m mlkemWrapper) GenerateKeypair(rng io.Reader) (KEMKey, error) {
	if rng == nil {
		rng = rand.Reader
	}

	// Generate a random seed for deterministic key generation
	seed := make([]byte, m.scheme.SeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return KEMKey{}, err
	}

	// Derive keypair from seed
	pub, priv := m.scheme.DeriveKeyPair(seed)

	// Securely zero the seed
	secureZero(seed)

	// Convert to byte slices for our KEMKey structure
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return KEMKey{}, err
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		secureZero(pubBytes) // Clean up on error
		return KEMKey{}, err
	}

	return KEMKey{
		Public:  pubBytes,
		Private: privBytes,
	}, nil
}

// Encapsulate generates a shared secret and encapsulates it for the given public key.
// Returns the ciphertext and shared secret. The shared secret must be securely zeroed
// after use by the caller.
func (m mlkemWrapper) Encapsulate(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte, err error) {
	if rng == nil {
		rng = rand.Reader
	}

	// Validate public key length
	if len(pubkey) != m.publicKeySize {
		return nil, nil, ErrInvalidKEMPublicKey
	}

	// Unmarshal the public key
	pub, err := m.scheme.UnmarshalBinaryPublicKey(pubkey)
	if err != nil {
		return nil, nil, ErrInvalidKEMPublicKey
	}

	// Generate random seed for encapsulation
	seed := make([]byte, m.scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, nil, err
	}

	// Perform deterministic encapsulation with the random seed
	ct, ss, err := m.scheme.EncapsulateDeterministically(pub, seed)

	// Securely zero the seed
	secureZero(seed)

	if err != nil {
		return nil, nil, err
	}

	return ct, ss, nil
}

// Decapsulate recovers the shared secret from the ciphertext using the private key.
// The returned shared secret must be securely zeroed after use by the caller.
func (m mlkemWrapper) Decapsulate(privkey, ciphertext []byte) (sharedSecret []byte, err error) {
	// Validate private key length
	if len(privkey) != m.privateKeySize {
		return nil, ErrInvalidKEMPrivateKey
	}

	// Validate ciphertext length
	if len(ciphertext) != m.ciphertextSize {
		return nil, ErrInvalidKEMCiphertext
	}

	// Unmarshal the private key
	priv, err := m.scheme.UnmarshalBinaryPrivateKey(privkey)
	if err != nil {
		return nil, ErrInvalidKEMPrivateKey
	}

	// Perform decapsulation
	ss, err := m.scheme.Decapsulate(priv, ciphertext)
	if err != nil {
		return nil, ErrKEMDecapsulationFailed
	}

	return ss, nil
}

func (m mlkemWrapper) PublicKeyLen() int    { return m.publicKeySize }
func (m mlkemWrapper) PrivateKeyLen() int   { return m.privateKeySize }
func (m mlkemWrapper) CiphertextLen() int   { return m.ciphertextSize }
func (m mlkemWrapper) SharedSecretLen() int { return m.sharedSecretSize }
func (m mlkemWrapper) KEMName() string      { return m.name }

// Exported KEM function instances
// These can be used directly in CipherSuite configurations for hybrid protocols.
var (
	// KEMMLKEM512 provides NIST Security Level 1 (~AES-128 equivalent)
	// Suitable for IoT and resource-constrained devices.
	KEMMLKEM512 KEMFunc = mlkemWrapper{
		scheme:           mlkem512.Scheme(),
		name:             "MLKEM512",
		publicKeySize:    MLKEM512PublicKeySize,
		privateKeySize:   MLKEM512PrivateKeySize,
		ciphertextSize:   MLKEM512CiphertextSize,
		sharedSecretSize: MLKEM512SharedSecretSize,
	}

	// KEMMLKEM768 provides NIST Security Level 3 (~AES-192 equivalent) - RECOMMENDED
	// This is the recommended variant for most use cases, providing a good
	// balance between security and performance.
	KEMMLKEM768 KEMFunc = mlkemWrapper{
		scheme:           mlkem768.Scheme(),
		name:             "MLKEM768",
		publicKeySize:    MLKEM768PublicKeySize,
		privateKeySize:   MLKEM768PrivateKeySize,
		ciphertextSize:   MLKEM768CiphertextSize,
		sharedSecretSize: MLKEM768SharedSecretSize,
	}

	// KEMMLKEM1024 provides NIST Security Level 5 (~AES-256 equivalent)
	// Suitable for high-security applications requiring maximum protection.
	KEMMLKEM1024 KEMFunc = mlkemWrapper{
		scheme:           mlkem1024.Scheme(),
		name:             "MLKEM1024",
		publicKeySize:    MLKEM1024PublicKeySize,
		privateKeySize:   MLKEM1024PrivateKeySize,
		ciphertextSize:   MLKEM1024CiphertextSize,
		sharedSecretSize: MLKEM1024SharedSecretSize,
	}
)
