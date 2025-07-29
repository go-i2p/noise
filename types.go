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
