// Package noise implements the Noise Protocol Framework.
//
// Noise is a low-level framework for building crypto protocols. Noise protocols
// support mutual and optional authentication, identity hiding, forward secrecy,
// zero round-trip encryption, and other advanced features. For more details,
// visit https://noiseprotocol.org.
package noise

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
)

// A HandshakeState tracks the state of a Noise handshake. It may be discarded
// after the handshake is complete.
type HandshakeState struct {
	ss              symmetricState
	s               DHKey  // local static keypair
	e               DHKey  // local ephemeral keypair
	rs              []byte // remote party's static public key
	re              []byte // remote party's ephemeral public key
	psk             []byte // preshared key, maybe zero length
	willPsk         bool   // indicates if preshared key will be used (even if not yet set)
	messagePatterns [][]MessagePattern
	shouldWrite     bool
	initiator       bool
	msgIdx          int
	rng             io.Reader
	mu              sync.Mutex // Protects handshake state for thread safety
}

// NewHandshakeState starts a new handshake using the provided configuration.
// WARNING: Do not use RandomInc in production - it provides completely predictable
// random numbers and breaks all cryptographic security guarantees.
func NewHandshakeState(c Config) (*HandshakeState, error) {
	hs := &HandshakeState{
		s:               c.StaticKeypair,
		e:               c.EphemeralKeypair,
		rs:              c.PeerStatic,
		messagePatterns: c.Pattern.Messages,
		shouldWrite:     c.Initiator,
		initiator:       c.Initiator,
		rng:             c.Random,
	}
	if hs.rng == nil {
		hs.rng = rand.Reader
	}
	if len(c.PeerEphemeral) > 0 {
		hs.re = make([]byte, len(c.PeerEphemeral))
		copy(hs.re, c.PeerEphemeral)
	}
	hs.ss.cs = c.CipherSuite

	pskModifier := ""
	// NB: for psk{0,1} we must have preshared key set in configuration as its needed in the first
	// message. For psk{2+} we may not know the correct psk yet so it might not be set.
	if len(c.PresharedKey) > 0 || c.PresharedKeyPlacement >= 2 {
		hs.willPsk = true
		if len(c.PresharedKey) > 0 {
			if err := hs.SetPresharedKey(c.PresharedKey); err != nil {
				return nil, err
			}
		}

		pskModifier = fmt.Sprintf("psk%d", c.PresharedKeyPlacement)
		hs.messagePatterns = append([][]MessagePattern(nil), hs.messagePatterns...)
		if c.PresharedKeyPlacement == 0 {
			hs.messagePatterns[0] = append([]MessagePattern{MessagePatternPSK}, hs.messagePatterns[0]...)
		} else {
			hs.messagePatterns[c.PresharedKeyPlacement-1] = append(hs.messagePatterns[c.PresharedKeyPlacement-1], MessagePatternPSK)
		}
	}

	hs.ss.InitializeSymmetric([]byte("Noise_" + c.Pattern.Name + pskModifier + "_" + string(hs.ss.cs.Name())))
	hs.ss.MixHash(c.Prologue)
	for _, m := range c.Pattern.InitiatorPreMessages {
		switch {
		case c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.s.Public)
		case c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.e.Public)
		case !c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.rs)
		case !c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.re)
		}
	}
	for _, m := range c.Pattern.ResponderPreMessages {
		switch {
		case !c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.s.Public)
		case !c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.e.Public)
		case c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.rs)
		case c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.re)
		}
	}
	return hs, nil
}

// WriteMessage appends a handshake message to out. The message will include the
// optional payload if provided. If the handshake is completed by the call, two
// CipherStates will be returned, one is used for encryption of messages to the
// remote peer, the other is used for decryption of messages from the remote
// peer. It is an error to call this method out of sync with the handshake
// pattern.
func (s *HandshakeState) WriteMessage(out, payload []byte) ([]byte, *CipherState, *CipherState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.shouldWrite {
		return nil, nil, nil, errors.New("noise: unexpected call to WriteMessage should be ReadMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		return nil, nil, nil, errors.New("noise: no handshake messages left")
	}
	if len(payload) > MaxMsgLen {
		return nil, nil, nil, errors.New("noise: message is too long")
	}

	var err error
	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE:
			e, err := s.ss.cs.GenerateKeypair(s.rng)
			if err != nil {
				return nil, nil, nil, err
			}
			s.e = e
			out = append(out, s.e.Public...)
			s.ss.MixHash(s.e.Public)
			if s.willPsk {
				s.ss.MixKey(s.e.Public)
			}
		case MessagePatternS:
			if len(s.s.Public) == 0 {
				return nil, nil, nil, errors.New("noise: invalid state, s.Public is nil")
			}
			out, err = s.ss.EncryptAndHash(out, s.s.Public)
			if err != nil {
				return nil, nil, nil, err
			}
		case MessagePatternDHEE:
			dh, err := s.ss.cs.DH(s.e.Private, s.re)
			if err != nil {
				return nil, nil, nil, err
			}
			s.ss.MixKey(dh)
			// Securely zero the DH output after mixing
			secureZero(dh)
		case MessagePatternDHES:
			if s.initiator {
				dh, err := s.ss.cs.DH(s.e.Private, s.rs)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			} else {
				dh, err := s.ss.cs.DH(s.s.Private, s.re)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			}
		case MessagePatternDHSE:
			if s.initiator {
				dh, err := s.ss.cs.DH(s.s.Private, s.re)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			} else {
				dh, err := s.ss.cs.DH(s.e.Private, s.rs)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			}
		case MessagePatternDHSS:
			dh, err := s.ss.cs.DH(s.s.Private, s.rs)
			if err != nil {
				return nil, nil, nil, err
			}
			s.ss.MixKey(dh)
			// Securely zero the DH output after mixing
			secureZero(dh)
		case MessagePatternPSK:
			if len(s.psk) == 0 {
				return nil, nil, nil, errors.New("noise: cannot send psk message without psk set")
			}
			s.ss.MixKeyAndHash(s.psk)
		}
	}
	s.shouldWrite = false
	s.msgIdx++
	out, err = s.ss.EncryptAndHash(out, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.ss.Split()
		return out, cs1, cs2, nil
	}

	return out, nil, nil, nil
}

func (s *HandshakeState) SetPresharedKey(psk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(psk) != 32 {
		return errors.New("noise: specification mandates 256-bit preshared keys")
	}
	// Clear any existing PSK first
	if s.psk != nil {
		secureZero(s.psk)
	}
	s.psk = make([]byte, 32)
	copy(s.psk, psk)
	return nil
}

// ReadMessage processes a received handshake message and appends the payload,
// if any to out. If the handshake is completed by the call, two CipherStates
// will be returned, one is used for encryption of messages to the remote peer,
// the other is used for decryption of messages from the remote peer. It is an
// error to call this method out of sync with the handshake pattern.
func (s *HandshakeState) ReadMessage(out, message []byte) ([]byte, *CipherState, *CipherState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shouldWrite {
		return nil, nil, nil, errors.New("noise: unexpected call to ReadMessage should be WriteMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		return nil, nil, nil, errors.New("noise: no handshake messages left")
	}
	if len(message) > MaxMsgLen {
		return nil, nil, nil, errors.New("noise: message exceeds maximum length")
	}

	rsSet := false
	s.ss.Checkpoint()

	var err error
	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE, MessagePatternS:
			expected := s.ss.cs.DHLen()
			if msg == MessagePatternS && s.ss.hasK {
				expected += 16
			}
			if len(message) < expected {
				return nil, nil, nil, ErrShortMessage
			}
			switch msg {
			case MessagePatternE:
				if cap(s.re) < s.ss.cs.DHLen() {
					s.re = make([]byte, s.ss.cs.DHLen())
				}
				s.re = s.re[:s.ss.cs.DHLen()]
				copy(s.re, message)
				s.ss.MixHash(s.re)
				if s.willPsk {
					s.ss.MixKey(s.re)
				}
			case MessagePatternS:
				if len(s.rs) > 0 {
					return nil, nil, nil, errors.New("noise: invalid state, rs is not nil")
				}
				s.rs, err = s.ss.DecryptAndHash(s.rs[:0], message[:expected])
				rsSet = true
			}
			if err != nil {
				s.ss.Rollback()
				if rsSet {
					s.rs = nil
				}
				return nil, nil, nil, err
			}
			message = message[expected:]
		case MessagePatternDHEE:
			dh, err := s.ss.cs.DH(s.e.Private, s.re)
			if err != nil {
				return nil, nil, nil, err
			}
			s.ss.MixKey(dh)
			// Securely zero the DH output after mixing
			secureZero(dh)
		case MessagePatternDHES:
			if s.initiator {
				dh, err := s.ss.cs.DH(s.e.Private, s.rs)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			} else {
				dh, err := s.ss.cs.DH(s.s.Private, s.re)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			}
		case MessagePatternDHSE:
			if s.initiator {
				dh, err := s.ss.cs.DH(s.s.Private, s.re)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			} else {
				dh, err := s.ss.cs.DH(s.e.Private, s.rs)
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixKey(dh)
				// Securely zero the DH output after mixing
				secureZero(dh)
			}
		case MessagePatternDHSS:
			dh, err := s.ss.cs.DH(s.s.Private, s.rs)
			if err != nil {
				return nil, nil, nil, err
			}
			s.ss.MixKey(dh)
			// Securely zero the DH output after mixing
			secureZero(dh)
		case MessagePatternPSK:
			s.ss.MixKeyAndHash(s.psk)
		}
	}
	out, err = s.ss.DecryptAndHash(out, message)
	if err != nil {
		s.ss.Rollback()
		if rsSet {
			s.rs = nil
		}
		return nil, nil, nil, err
	}
	s.shouldWrite = true
	s.msgIdx++

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.ss.Split()
		return out, cs1, cs2, nil
	}

	return out, nil, nil, nil
}

// ChannelBinding provides a value that uniquely identifies the session and can
// be used as a channel binding. It is an error to call this method before the
// handshake is complete.
func (s *HandshakeState) ChannelBinding() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ss.h
}

// PeerStatic returns the static key provided by the remote peer during
// a handshake. It is an error to call this method if a handshake message
// containing a static key has not been read.
func (s *HandshakeState) PeerStatic() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rs
}

// MessageIndex returns the current handshake message id
func (s *HandshakeState) MessageIndex() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.msgIdx
}

// PeerEphemeral returns the ephemeral key provided by the remote peer during
// a handshake. It is an error to call this method if a handshake message
// containing a static key has not been read.
func (s *HandshakeState) PeerEphemeral() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.re
}

// LocalEphemeral returns the local ephemeral key pair generated during
// a handshake.
func (s *HandshakeState) LocalEphemeral() DHKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.e
}
