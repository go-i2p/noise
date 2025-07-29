package noise

// A DHKey is a keypair used for Diffie-Hellman key agreement.
// Moved from: cipher_suite.go
type DHKey struct {
	Private []byte
	Public  []byte
}
