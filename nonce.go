package noise

import "encoding/binary"

// BuildNonce constructs a 12-byte AEAD nonce from the given 64-bit counter value.
// The nonce is encoded as 4 zero bytes followed by the counter in little-endian
// byte order, matching the Noise Protocol Framework convention for use with
// AEAD ciphers that require 96-bit nonces (e.g., ChaChaPoly, AESGCM).
func BuildNonce(n uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}
