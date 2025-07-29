package noise

import (
	"math"
)

// A CipherState provides symmetric encryption and decryption after a successful
// handshake.
// Moved from: state.go
type CipherState struct {
	cs CipherSuite
	c  Cipher
	k  [32]byte
	n  uint64

	invalid bool
}

// UnsafeNewCipherState reconstructs a CipherState from exported components.
// It is important that, when resuming from an exported state, care is taken
// to synchronize the nonce state and not allow rollbacks.
// Moved from: state.go
func UnsafeNewCipherState(cs CipherSuite, k [32]byte, n uint64) *CipherState {
	return &CipherState{
		cs: cs,
		c:  cs.Cipher(k),
		k:  k,
		n:  n,
	}
}

// Encrypt encrypts the plaintext and then appends the ciphertext and an
// authentication tag across the ciphertext and optional authenticated data to
// out. This method automatically increments the nonce after every call, so
// messages must be decrypted in the same order. ErrMaxNonce is returned after
// the maximum nonce of 2^64-2 is reached.
// Moved from: state.go
func (s *CipherState) Encrypt(out, ad, plaintext []byte) ([]byte, error) {
	if s.invalid {
		return nil, ErrCipherSuiteCopied
	}
	if s.n > MaxNonce {
		return nil, ErrMaxNonce
	}
	out = s.c.Encrypt(out, s.n, ad, plaintext)
	s.n++
	return out, nil
}

// Decrypt checks the authenticity of the ciphertext and authenticated data and
// then decrypts and appends the plaintext to out. This method automatically
// increments the nonce after every call, messages must be provided in the same
// order that they were encrypted with no missing messages. ErrMaxNonce is
// returned after the maximum nonce of 2^64-2 is reached.
// Moved from: state.go
func (s *CipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	if s.invalid {
		return nil, ErrCipherSuiteCopied
	}
	if s.n > MaxNonce {
		return nil, ErrMaxNonce
	}
	out, err := s.c.Decrypt(out, s.n, ad, ciphertext)
	if err != nil {
		return nil, err
	}
	s.n++
	return out, nil
}

// Cipher returns the low-level symmetric encryption primitive. It should only
// be used if nonces need to be managed manually, for example with a network
// protocol that can deliver out-of-order messages. This is dangerous, users
// must ensure that they are incrementing a nonce after every encrypt operation.
// After calling this method, it is an error to call Encrypt/Decrypt on the
// CipherState.
// Moved from: state.go
func (s *CipherState) Cipher() Cipher {
	s.invalid = true
	return s.c
}

// Nonce returns the current value of n. This can be used to determine if a
// new handshake should be performed due to approaching MaxNonce.
// Moved from: state.go
func (s *CipherState) Nonce() uint64 {
	return s.n
}

// SetNonce sets the current value of n.
// Moved from: state.go
func (s *CipherState) SetNonce(n uint64) {
	s.n = n
}

// UnsafeKey returns the current value of k. This exports the current key for the
// CipherState. Intended to be used alongside UnsafeNewCipherState to resume a
// CipherState at a later point.
// Moved from: state.go
func (s *CipherState) UnsafeKey() [32]byte {
	return s.k
}

// Rekey advances the key material and securely zeros intermediate values.
// Moved from: state.go
func (s *CipherState) Rekey() {
	var zeros [32]byte
	var out []byte
	out = s.c.Encrypt(out, math.MaxUint64, []byte{}, zeros[:])
	copy(s.k[:], out[:32])
	s.c = s.cs.Cipher(s.k)

	// Securely zero intermediate data
	secureZero(out)
}
