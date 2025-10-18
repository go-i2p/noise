package noise

import (
	"errors"
	"math"
)

// MaxNonce is the maximum value of n that is allowed. ErrMaxNonce is returned
// by Encrypt and Decrypt after this has been reached. 2^64-1 is reserved for rekeys.
// Moved from: state.go
const MaxNonce = uint64(math.MaxUint64) - 1

// MaxMsgLen is the maximum number of bytes that can be sent in a single Noise
// message.
// Moved from: state.go
const MaxMsgLen = 65535

// MessagePattern constants define the types of operations in a Noise handshake.
// Moved from: state.go
const (
	MessagePatternS MessagePattern = iota
	MessagePatternE
	MessagePatternDHEE
	MessagePatternDHES
	MessagePatternDHSE
	MessagePatternDHSS
	MessagePatternPSK
)

// MLKEM (Module-Lattice-Based Key Encapsulation Mechanism) constants.
// These values are defined in NIST FIPS 203 and represent the sizes of
// keys, ciphertexts, and shared secrets for each security level.
//
// MLKEM-512: NIST Security Level 1 (~AES-128 equivalent)
// MLKEM-768: NIST Security Level 3 (~AES-192 equivalent) - RECOMMENDED
// MLKEM-1024: NIST Security Level 5 (~AES-256 equivalent)
const (
	// MLKEM-512 sizes (NIST Security Level 1)
	MLKEM512PublicKeySize    = 800
	MLKEM512PrivateKeySize   = 1632
	MLKEM512CiphertextSize   = 768
	MLKEM512SharedSecretSize = 32

	// MLKEM-768 sizes (NIST Security Level 3) - Recommended for most use cases
	MLKEM768PublicKeySize    = 1184
	MLKEM768PrivateKeySize   = 2400
	MLKEM768CiphertextSize   = 1088
	MLKEM768SharedSecretSize = 32

	// MLKEM-1024 sizes (NIST Security Level 5)
	MLKEM1024PublicKeySize    = 1568
	MLKEM1024PrivateKeySize   = 3168
	MLKEM1024CiphertextSize   = 1568
	MLKEM1024SharedSecretSize = 32
)

// MLDSA (Module-Lattice-Based Digital Signature Algorithm) constants.
// These values are defined in NIST FIPS 204 and represent the sizes of
// keys and signatures for each security level.
//
// MLDSA-44: NIST Security Level 2 (~AES-128 equivalent)
// MLDSA-65: NIST Security Level 3 (~AES-192 equivalent) - RECOMMENDED
// MLDSA-87: NIST Security Level 5 (~AES-256 equivalent)
const (
	// MLDSA-44 sizes (NIST Security Level 2)
	MLDSA44PublicKeySize  = 1312
	MLDSA44PrivateKeySize = 2560
	MLDSA44SignatureSize  = 2420

	// MLDSA-65 sizes (NIST Security Level 3) - Recommended for most use cases
	MLDSA65PublicKeySize  = 1952
	MLDSA65PrivateKeySize = 4032
	MLDSA65SignatureSize  = 3309

	// MLDSA-87 sizes (NIST Security Level 5)
	MLDSA87PublicKeySize  = 2592
	MLDSA87PrivateKeySize = 4896
	MLDSA87SignatureSize  = 4627
)

// Error constants used throughout the package.
// Moved from: state.go
var ErrMaxNonce = errors.New("noise: cipherstate has reached maximum n, a new handshake must be performed")
var ErrCipherSuiteCopied = errors.New("noise: CipherSuite has been copied, state is invalid")
var ErrShortMessage = errors.New("noise: message is too short")

// Post-quantum cryptography error constants.
// These errors are returned when PQ operations fail or receive invalid inputs.
var (
	// ErrInvalidKEMPublicKey indicates that a KEM public key has invalid format or length.
	ErrInvalidKEMPublicKey = errors.New("noise: invalid KEM public key")

	// ErrInvalidKEMPrivateKey indicates that a KEM private key has invalid format or length.
	ErrInvalidKEMPrivateKey = errors.New("noise: invalid KEM private key")

	// ErrInvalidKEMCiphertext indicates that a KEM ciphertext has invalid format or length.
	ErrInvalidKEMCiphertext = errors.New("noise: invalid KEM ciphertext")

	// ErrKEMDecapsulationFailed indicates that KEM decapsulation operation failed.
	// This can occur with malformed ciphertexts or key mismatches.
	ErrKEMDecapsulationFailed = errors.New("noise: KEM decapsulation failed")

	// ErrInvalidSignature indicates that signature verification failed.
	ErrInvalidSignature = errors.New("noise: signature verification failed")

	// ErrSigningKeyRequired indicates that a signing key is required but not provided.
	ErrSigningKeyRequired = errors.New("noise: signing key required for this operation")

	// ErrInvalidSigningKey indicates that a signing key has invalid format or length.
	ErrInvalidSigningKey = errors.New("noise: invalid signing key")
)
