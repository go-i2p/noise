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

// Error constants used throughout the package.
// Moved from: state.go
var ErrMaxNonce = errors.New("noise: cipherstate has reached maximum n, a new handshake must be performed")
var ErrCipherSuiteCopied = errors.New("noise: CipherSuite has been copied, state is invalid")
var ErrShortMessage = errors.New("noise: message is too short")
