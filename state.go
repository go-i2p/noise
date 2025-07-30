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

// initializeHandshakeState creates and initializes the basic HandshakeState structure.
func initializeHandshakeState(c Config) *HandshakeState {
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
	return hs
}

// configurePresharedKey configures the preshared key and modifies message patterns accordingly.
func configurePresharedKey(hs *HandshakeState, c Config) (string, error) {
	pskModifier := ""
	// NB: for psk{0,1} we must have preshared key set in configuration as its needed in the first
	// message. For psk{2+} we may not know the correct psk yet so it might not be set.
	if len(c.PresharedKey) > 0 || c.PresharedKeyPlacement >= 2 {
		hs.willPsk = true
		if len(c.PresharedKey) > 0 {
			if err := hs.SetPresharedKey(c.PresharedKey); err != nil {
				return "", err
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
	return pskModifier, nil
}

// initializeSymmetricState sets up the symmetric state with the protocol name and prologue.
func initializeSymmetricState(hs *HandshakeState, c Config, pskModifier string) {
	hs.ss.InitializeSymmetric([]byte("Noise_" + c.Pattern.Name + pskModifier + "_" + string(hs.ss.cs.Name())))
	hs.ss.MixHash(c.Prologue)
}

// processPreMessages processes both initiator and responder pre-messages for the handshake.
func processPreMessages(hs *HandshakeState, c Config) {
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
}

// NewHandshakeState starts a new handshake using the provided configuration.
// WARNING: Do not use RandomInc in production - it provides completely predictable
// random numbers and breaks all cryptographic security guarantees.
func NewHandshakeState(c Config) (*HandshakeState, error) {
	hs := initializeHandshakeState(c)

	pskModifier, err := configurePresharedKey(hs, c)
	if err != nil {
		return nil, err
	}

	initializeSymmetricState(hs, c, pskModifier)
	processPreMessages(hs, c)

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

	if err := s.validateWriteMessageState(payload); err != nil {
		return nil, nil, nil, err
	}

	out, err := s.processWriteMessagePatterns(out)
	if err != nil {
		return nil, nil, nil, err
	}

	return s.finalizeWriteMessage(out, payload)
}

// validateWriteMessageState checks if the WriteMessage call is valid for the current state.
func (s *HandshakeState) validateWriteMessageState(payload []byte) error {
	if !s.shouldWrite {
		return errors.New("noise: unexpected call to WriteMessage should be ReadMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		return errors.New("noise: no handshake messages left")
	}
	if len(payload) > MaxMsgLen {
		return errors.New("noise: message is too long")
	}
	return nil
}

// processWriteMessagePatterns processes all message patterns for the current message index.
func (s *HandshakeState) processWriteMessagePatterns(out []byte) ([]byte, error) {
	var err error
	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE:
			out, err = s.processEphemeralPattern(out)
		case MessagePatternS:
			out, err = s.processStaticPattern(out)
		case MessagePatternDHEE:
			err = s.performDiffieHellmanEE()
		case MessagePatternDHES:
			err = s.performDiffieHellmanES()
		case MessagePatternDHSE:
			err = s.performDiffieHellmanSE()
		case MessagePatternDHSS:
			err = s.performDiffieHellmanSS()
		case MessagePatternPSK:
			err = s.processPresharedKeyPattern()
		}

		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// processEphemeralPattern handles the ephemeral key exchange pattern.
func (s *HandshakeState) processEphemeralPattern(out []byte) ([]byte, error) {
	e, err := s.ss.cs.GenerateKeypair(s.rng)
	if err != nil {
		return nil, err
	}
	s.e = e
	out = append(out, s.e.Public...)
	s.ss.MixHash(s.e.Public)
	if s.willPsk {
		s.ss.MixKey(s.e.Public)
	}
	return out, nil
}

// processStaticPattern handles the static key exchange pattern.
func (s *HandshakeState) processStaticPattern(out []byte) ([]byte, error) {
	if len(s.s.Public) == 0 {
		return nil, errors.New("noise: invalid state, s.Public is nil")
	}
	return s.ss.EncryptAndHash(out, s.s.Public)
}

// processPresharedKeyPattern handles the preshared key pattern.
func (s *HandshakeState) processPresharedKeyPattern() error {
	if len(s.psk) == 0 {
		return errors.New("noise: cannot send psk message without psk set")
	}
	s.ss.MixKeyAndHash(s.psk)
	return nil
}

// finalizeWriteMessage completes the WriteMessage operation by encrypting payload and handling completion.
func (s *HandshakeState) finalizeWriteMessage(out, payload []byte) ([]byte, *CipherState, *CipherState, error) {
	s.shouldWrite = false
	s.msgIdx++

	out, err := s.ss.EncryptAndHash(out, payload)
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

	if err := s.validateReadMessageState(message); err != nil {
		return nil, nil, nil, err
	}

	rsSet := false
	s.ss.Checkpoint()

	message, rsSet, err := s.processMessagePatterns(message)
	if err != nil {
		s.rollbackOnError(rsSet)
		return nil, nil, nil, err
	}

	out, err = s.ss.DecryptAndHash(out, message)
	if err != nil {
		s.rollbackOnError(rsSet)
		return nil, nil, nil, err
	}

	return s.finalizeReadMessage(out)
}

// validateReadMessageState checks if the ReadMessage call is valid for the current state.
func (s *HandshakeState) validateReadMessageState(message []byte) error {
	if s.shouldWrite {
		return errors.New("noise: unexpected call to ReadMessage should be WriteMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		return errors.New("noise: no handshake messages left")
	}
	if len(message) > MaxMsgLen {
		return errors.New("noise: message exceeds maximum length")
	}
	return nil
}

// processMessagePatterns handles all message pattern types and processes the message accordingly.
func (s *HandshakeState) processMessagePatterns(message []byte) ([]byte, bool, error) {
	rsSet := false

	for _, msg := range s.messagePatterns[s.msgIdx] {
		var err error
		var consumed int

		switch msg {
		case MessagePatternE, MessagePatternS:
			message, consumed, rsSet, err = s.processKeyExchangePattern(msg, message)
		case MessagePatternDHEE:
			err = s.performDiffieHellmanEE()
		case MessagePatternDHES:
			err = s.performDiffieHellmanES()
		case MessagePatternDHSE:
			err = s.performDiffieHellmanSE()
		case MessagePatternDHSS:
			err = s.performDiffieHellmanSS()
		case MessagePatternPSK:
			s.ss.MixKeyAndHash(s.psk)
		}

		if err != nil {
			return nil, rsSet, err
		}

		if consumed > 0 {
			message = message[consumed:]
		}
	}

	return message, rsSet, nil
}

// processKeyExchangePattern handles ephemeral and static key exchange patterns.
func (s *HandshakeState) processKeyExchangePattern(pattern MessagePattern, message []byte) ([]byte, int, bool, error) {
	expected := s.ss.cs.DHLen()
	if pattern == MessagePatternS && s.ss.hasK {
		expected += 16
	}

	if len(message) < expected {
		return nil, 0, false, ErrShortMessage
	}

	var err error
	rsSet := false

	switch pattern {
	case MessagePatternE:
		err = s.processEphemeralKey(message[:expected])
	case MessagePatternS:
		if len(s.rs) > 0 {
			return nil, 0, false, errors.New("noise: invalid state, rs is not nil")
		}
		s.rs, err = s.ss.DecryptAndHash(s.rs[:0], message[:expected])
		rsSet = true
	}

	return message, expected, rsSet, err
}

// processEphemeralKey processes the ephemeral key from the message.
func (s *HandshakeState) processEphemeralKey(keyData []byte) error {
	if cap(s.re) < s.ss.cs.DHLen() {
		s.re = make([]byte, s.ss.cs.DHLen())
	}
	s.re = s.re[:s.ss.cs.DHLen()]
	copy(s.re, keyData)
	s.ss.MixHash(s.re)
	if s.willPsk {
		s.ss.MixKey(s.re)
	}
	return nil
}

// performDiffieHellmanEE performs Diffie-Hellman operation between ephemeral keys.
func (s *HandshakeState) performDiffieHellmanEE() error {
	dh, err := s.ss.cs.DH(s.e.Private, s.re)
	if err != nil {
		return err
	}
	s.ss.MixKey(dh)
	secureZero(dh)
	return nil
}

// performDiffieHellmanES performs Diffie-Hellman operation between ephemeral and static keys.
func (s *HandshakeState) performDiffieHellmanES() error {
	var dh []byte
	var err error

	if s.initiator {
		dh, err = s.ss.cs.DH(s.e.Private, s.rs)
	} else {
		dh, err = s.ss.cs.DH(s.s.Private, s.re)
	}

	if err != nil {
		return err
	}

	s.ss.MixKey(dh)
	secureZero(dh)
	return nil
}

// performDiffieHellmanSE performs Diffie-Hellman operation between static and ephemeral keys.
func (s *HandshakeState) performDiffieHellmanSE() error {
	var dh []byte
	var err error

	if s.initiator {
		dh, err = s.ss.cs.DH(s.s.Private, s.re)
	} else {
		dh, err = s.ss.cs.DH(s.e.Private, s.rs)
	}

	if err != nil {
		return err
	}

	s.ss.MixKey(dh)
	secureZero(dh)
	return nil
}

// performDiffieHellmanSS performs Diffie-Hellman operation between static keys.
func (s *HandshakeState) performDiffieHellmanSS() error {
	dh, err := s.ss.cs.DH(s.s.Private, s.rs)
	if err != nil {
		return err
	}
	s.ss.MixKey(dh)
	secureZero(dh)
	return nil
}

// rollbackOnError handles error rollback and cleanup of state.
func (s *HandshakeState) rollbackOnError(rsSet bool) {
	s.ss.Rollback()
	if rsSet {
		s.rs = nil
	}
}

// finalizeReadMessage completes the read message operation and returns appropriate cipher states.
func (s *HandshakeState) finalizeReadMessage(out []byte) ([]byte, *CipherState, *CipherState, error) {
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
