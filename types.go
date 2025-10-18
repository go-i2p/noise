package noise

import (
	"hash"
	"io"
)

// A DHFunc implements Diffie-Hellman key agreement.
// Moved from: cipher_suite.go
type DHFunc interface {
	// GenerateKeypair generates a new keypair using random as a source of
	// entropy.
	GenerateKeypair(random io.Reader) (DHKey, error)

	// DH performs a Diffie-Hellman calculation between the provided private and
	// public keys and returns the result.
	DH(privkey, pubkey []byte) ([]byte, error)

	// DHLen is the number of bytes returned by DH.
	DHLen() int

	// DHName is the name of the DH function.
	DHName() string
}

// KEMFunc implements a Key Encapsulation Mechanism (KEM) for post-quantum cryptography.
// KEMs provide a way to establish shared secrets that is quantum-resistant.
// Unlike traditional DH, KEM uses encapsulation (public key -> ciphertext + shared secret)
// and decapsulation (private key + ciphertext -> shared secret).
type KEMFunc interface {
	// GenerateKeypair generates a new KEM keypair using random as a source of entropy.
	GenerateKeypair(random io.Reader) (KEMKey, error)

	// Encapsulate generates a shared secret and encapsulates it for the given public key.
	// Returns the ciphertext and the shared secret.
	Encapsulate(pubkey []byte, random io.Reader) (ciphertext, sharedSecret []byte, err error)

	// Decapsulate recovers the shared secret from the ciphertext using the private key.
	Decapsulate(privkey, ciphertext []byte) (sharedSecret []byte, err error)

	// PublicKeyLen returns the length in bytes of KEM public keys.
	PublicKeyLen() int

	// PrivateKeyLen returns the length in bytes of KEM private keys.
	PrivateKeyLen() int

	// CiphertextLen returns the length in bytes of KEM ciphertexts.
	CiphertextLen() int

	// SharedSecretLen returns the length in bytes of KEM shared secrets.
	SharedSecretLen() int

	// KEMName returns the name of the KEM algorithm (e.g., "MLKEM768").
	KEMName() string
}

// HybridDHFunc combines classical Diffie-Hellman with post-quantum KEM for defense in depth.
// This provides both classical security (against classical computers) and post-quantum security
// (against quantum computers). The shared secrets from both primitives are combined using HKDF.
//
// Design rationale: Hybrid approach ensures security if either primitive is broken.
// Classical DH provides proven security today, while PQ KEM provides quantum resistance.
type HybridDHFunc interface {
	DHFunc // Embed classical DH interface for backwards compatibility

	// KEMEncapsulate generates a shared secret using the KEM portion of a hybrid key.
	// The pubkey should be a hybrid public key (classical || KEM portions).
	KEMEncapsulate(pubkey []byte, random io.Reader) (ciphertext, sharedSecret []byte, err error)

	// KEMDecapsulate recovers the KEM shared secret from a ciphertext.
	// The privkey should be a hybrid private key (classical || KEM portions).
	KEMDecapsulate(privkey, ciphertext []byte) (sharedSecret []byte, err error)

	// KEMPublicKeyLen returns the length of the KEM public key portion.
	KEMPublicKeyLen() int

	// KEMPrivateKeyLen returns the length of the KEM private key portion.
	KEMPrivateKeyLen() int

	// KEMCiphertextLen returns the length of KEM ciphertexts.
	KEMCiphertextLen() int

	// KEMSharedSecretLen returns the length of KEM shared secrets.
	KEMSharedSecretLen() int

	// IsHybrid returns true to indicate this is a hybrid function.
	// This allows runtime detection of hybrid vs classical-only DH functions.
	IsHybrid() bool
}

// SignatureFunc provides digital signature capabilities for authentication.
// This is used for post-quantum signature schemes like ML-DSA (FIPS 204).
// Signatures can be integrated into Noise handshake patterns for additional
// authentication properties beyond what DH provides.
//
// Design rationale: Signatures provide non-repudiation and can be useful
// in protocols requiring explicit authentication evidence.
type SignatureFunc interface {
	// GenerateSigningKey generates a new signing keypair using random as a source of entropy.
	GenerateSigningKey(random io.Reader) (SigningKey, error)

	// Sign creates a signature over the given message using the private key.
	Sign(privkey, message []byte) (signature []byte, err error)

	// Verify checks that a signature is valid for the given message and public key.
	// Returns an error if verification fails.
	Verify(pubkey, message, signature []byte) error

	// PublicKeyLen returns the length in bytes of signature public keys.
	PublicKeyLen() int

	// PrivateKeyLen returns the length in bytes of signature private keys.
	PrivateKeyLen() int

	// SignatureLen returns the length in bytes of signatures.
	SignatureLen() int

	// SignatureName returns the name of the signature algorithm (e.g., "MLDSA65").
	SignatureName() string
}

// A HashFunc implements a cryptographic hash function.
// Moved from: cipher_suite.go
type HashFunc interface {
	// Hash returns a hash state.
	Hash() hash.Hash

	// HashName is the name of the hash function.
	HashName() string
}

// A CipherFunc implements an AEAD symmetric cipher.
// Moved from: cipher_suite.go
type CipherFunc interface {
	// Cipher initializes the algorithm with the provided key and returns a Cipher.
	Cipher(k [32]byte) Cipher

	// CipherName is the name of the cipher.
	CipherName() string
}

// A Cipher is a AEAD cipher that has been initialized with a key.
// Moved from: cipher_suite.go
type Cipher interface {
	// Encrypt encrypts the provided plaintext with a nonce and then appends the
	// ciphertext to out along with an authentication tag over the ciphertext
	// and optional authenticated data.
	Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte

	// Decrypt authenticates the ciphertext and optional authenticated data and
	// then decrypts the provided ciphertext using the provided nonce and
	// appends it to out.
	Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error)
}

// A CipherSuite is a set of cryptographic primitives used in a Noise protocol.
// It should be constructed with NewCipherSuite.
// Moved from: cipher_suite.go
type CipherSuite interface {
	DHFunc
	CipherFunc
	HashFunc
	Name() []byte
}
