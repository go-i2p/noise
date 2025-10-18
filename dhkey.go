package noise

// A DHKey is a keypair used for Diffie-Hellman key agreement.
// Moved from: cipher_suite.go
type DHKey struct {
	Private []byte
	Public  []byte
}

// KEMKey is a keypair used for Key Encapsulation Mechanism operations.
// KEMs are a fundamental primitive in post-quantum cryptography, providing
// a quantum-resistant method for establishing shared secrets.
type KEMKey struct {
	Private []byte
	Public  []byte
}

// SigningKey is a keypair used for digital signatures.
// This is used with post-quantum signature algorithms like ML-DSA.
type SigningKey struct {
	Private []byte
	Public  []byte
}
