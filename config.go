package noise

import "io"

// A Config provides the details necessary to process a Noise handshake. It is
// never modified by this package, and can be reused.
// Moved from: state.go
type Config struct {
	// CipherSuite is the set of cryptographic primitives that will be used.
	CipherSuite CipherSuite

	// Random is the source for cryptographically appropriate random bytes. If
	// zero, it is automatically configured.
	Random io.Reader

	// Pattern is the pattern for the handshake.
	Pattern HandshakePattern

	// Initiator must be true if the first message in the handshake will be sent
	// by this peer.
	Initiator bool

	// Prologue is an optional message that has already be communicated and must
	// be identical on both sides for the handshake to succeed.
	Prologue []byte

	// PresharedKey is the optional preshared key for the handshake.
	PresharedKey []byte

	// PresharedKeyPlacement specifies the placement position of the PSK token
	// when PresharedKey is specified
	PresharedKeyPlacement int

	// StaticKeypair is this peer's static keypair, required if part of the
	// handshake.
	StaticKeypair DHKey

	// EphemeralKeypair is this peer's ephemeral keypair that was provided as
	// a pre-message in the handshake.
	EphemeralKeypair DHKey

	// PeerStatic is the static public key of the remote peer that was provided
	// as a pre-message in the handshake.
	PeerStatic []byte

	// PeerEphemeral is the ephemeral public key of the remote peer that was
	// provided as a pre-message in the handshake.
	PeerEphemeral []byte
}
