package noise

// A symmetricState provides symmetric encryption and decryption during handshake.
// Moved from: state.go
type symmetricState struct {
	CipherState
	hasK bool
	ck   []byte
	h    []byte

	prevCK []byte
	prevH  []byte
}

// InitializeSymmetric initializes the symmetric state with a handshake name.
// Moved from: state.go
func (s *symmetricState) InitializeSymmetric(handshakeName []byte) {
	h := s.cs.Hash()
	if len(handshakeName) <= h.Size() {
		s.h = make([]byte, h.Size())
		copy(s.h, handshakeName)
	} else {
		h.Write(handshakeName)
		s.h = h.Sum(nil)
	}
	s.ck = make([]byte, len(s.h))
	copy(s.ck, s.h)
}

// MixKey mixes the DH output with the chaining key.
// Moved from: state.go
func (s *symmetricState) MixKey(dhOutput []byte) {
	s.n = 0
	s.hasK = true
	var hk []byte
	s.ck, hk, _ = hkdf(s.cs.Hash, 2, s.ck[:0], s.k[:0], nil, s.ck, dhOutput)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)

	// Securely zero the intermediate key material
	secureZero(hk)
	// Note: dhOutput is zeroed by the caller since they own the memory
}

// MixHash mixes data with the handshake hash.
// Moved from: state.go
func (s *symmetricState) MixHash(data []byte) {
	h := s.cs.Hash()
	h.Write(s.h)
	h.Write(data)
	s.h = h.Sum(s.h[:0])
}

// MixKeyAndHash mixes data with both the chaining key and handshake hash.
// Moved from: state.go
func (s *symmetricState) MixKeyAndHash(data []byte) {
	var hk []byte
	var temp []byte
	s.ck, temp, hk = hkdf(s.cs.Hash, 3, s.ck[:0], temp, s.k[:0], s.ck, data)
	s.MixHash(temp)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)
	s.n = 0
	s.hasK = true

	// Securely zero intermediate key material
	secureZero(hk)
	secureZero(temp)
}

// EncryptAndHash encrypts plaintext and mixes with hash.
// Moved from: state.go
func (s *symmetricState) EncryptAndHash(out, plaintext []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(plaintext)
		return append(out, plaintext...), nil
	}
	ciphertext, err := s.Encrypt(out, s.h, plaintext)
	if err != nil {
		return nil, err
	}
	s.MixHash(ciphertext[len(out):])
	return ciphertext, nil
}

// DecryptAndHash decrypts data and mixes with hash.
// Moved from: state.go
func (s *symmetricState) DecryptAndHash(out, data []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(data)
		return append(out, data...), nil
	}
	plaintext, err := s.Decrypt(out, s.h, data)
	if err != nil {
		return nil, err
	}
	s.MixHash(data)
	return plaintext, nil
}

// Split splits the symmetric state into two cipher states.
// Moved from: state.go
func (s *symmetricState) Split() (*CipherState, *CipherState) {
	s1, s2 := &CipherState{cs: s.cs}, &CipherState{cs: s.cs}
	hk1, hk2, _ := hkdf(s.cs.Hash, 2, s1.k[:0], s2.k[:0], nil, s.ck, nil)
	copy(s1.k[:], hk1)
	copy(s2.k[:], hk2)
	s1.c = s.cs.Cipher(s1.k)
	s2.c = s.cs.Cipher(s2.k)

	// Securely zero the intermediate key material
	secureZero(hk1)
	secureZero(hk2)
	// Zero the chaining key as it's no longer needed after split
	secureZero(s.ck)

	return s1, s2
}

// Checkpoint saves the current symmetric state for rollback.
// Moved from: state.go
func (s *symmetricState) Checkpoint() {
	if len(s.ck) > cap(s.prevCK) {
		s.prevCK = make([]byte, len(s.ck))
	}
	s.prevCK = s.prevCK[:len(s.ck)]
	copy(s.prevCK, s.ck)

	if len(s.h) > cap(s.prevH) {
		s.prevH = make([]byte, len(s.h))
	}
	s.prevH = s.prevH[:len(s.h)]
	copy(s.prevH, s.h)
}

// Rollback restores the symmetric state from checkpoint.
// Moved from: state.go
func (s *symmetricState) Rollback() {
	s.ck = s.ck[:len(s.prevCK)]
	copy(s.ck, s.prevCK)
	s.h = s.h[:len(s.prevH)]
	copy(s.h, s.prevH)
}
