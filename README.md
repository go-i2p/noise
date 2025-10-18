# noise [![Go Reference](https://pkg.go.dev/badge/github.com/go-i2p/noise.svg)](https://pkg.go.dev/github.com/go-i2p/noise) [![CI Status](https://github.com/go-i2p/noise/actions/workflows/ci.yml/badge.svg)](https://github.com/go-i2p/noise/actions)

A Go implementation of the Noise Protocol Framework, forked from flynn/noise and enhanced by go-i2p with improved security features including thread-safe operations, secure memory zeroing, and enhanced concurrency support.

## Description

This package implements the [Noise Protocol Framework](https://noiseprotocol.org), a framework for building crypto protocols supporting mutual and optional authentication, identity hiding, forward secrecy, zero round-trip encryption, and other advanced features.

## Installation

```bash
go get github.com/go-i2p/noise
```

## Requirements

- Go 1.24.2 or later (from `go.mod`)
- `golang.org/x/crypto v0.40.0`

## Usage

### Basic Handshake Example

```go
// From: noise_test.go
package main

import (
    "github.com/go-i2p/noise"
)

func main() {
    // Create cipher suite
    cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
    
    // Generate static keypairs for initiator and responder
    staticI, _ := cs.GenerateKeypair(nil)
    staticR, _ := cs.GenerateKeypair(nil)
    
    // Initialize handshake states
    hsI, _ := noise.NewHandshakeState(noise.Config{
        CipherSuite:   cs,
        Pattern:       noise.HandshakeXX,
        Initiator:     true,
        StaticKeypair: staticI,
    })
    
    hsR, _ := noise.NewHandshakeState(noise.Config{
        CipherSuite:   cs,
        Pattern:       noise.HandshakeXX,
        StaticKeypair: staticR,
    })
    
    // Perform handshake - message 1
    msg, _, _, _ := hsI.WriteMessage(nil, []byte("hello"))
    res, _, _, _ := hsR.ReadMessage(nil, msg)
    
    // Perform handshake - message 2
    msg, _, _, _ = hsR.WriteMessage(nil, []byte("world"))
    res, _, _, _ = hsI.ReadMessage(nil, msg)
    
    // Perform handshake - message 3
    msg, csI0, csI1, _ := hsI.WriteMessage(nil, nil)
    _, csR0, csR1, _ := hsR.ReadMessage(nil, msg)
    
    // Use cipher states for encrypted communication
    encrypted, _ := csI0.Encrypt(nil, nil, []byte("secret"))
    decrypted, _ := csR0.Decrypt(nil, nil, encrypted)
}
```

### Supported Cipher Suites

```go
// Diffie-Hellman functions (from: cipher_suite.go)
noise.DH25519  // Curve25519

// Cipher functions
noise.CipherAESGCM      // AES256-GCM
noise.CipherChaChaPoly  // ChaCha20-Poly1305

// Hash functions
noise.HashSHA256   // SHA-256
noise.HashSHA512   // SHA-512
noise.HashBLAKE2b  // BLAKE2b
noise.HashBLAKE2s  // BLAKE2s
```

### Supported Handshake Patterns

```go
// From: patterns.go
noise.HandshakeNN  // No static keys
noise.HandshakeKN  // Initiator known
noise.HandshakeNK  // Responder known
noise.HandshakeKK  // Both known
noise.HandshakeNX  // Responder transmitted
noise.HandshakeKX  // Initiator known, responder transmitted
noise.HandshakeXN  // Initiator transmitted
noise.HandshakeIN  // Initiator immediate
noise.HandshakeXK  // Responder known, initiator transmitted
noise.HandshakeIK  // Responder known, initiator immediate
noise.HandshakeXX  // Both transmitted
noise.HandshakeIX  // Initiator immediate, responder transmitted
noise.HandshakeN   // One-way (no response)
noise.HandshakeK   // One-way with known keys
noise.HandshakeX   // One-way with transmitted initiator
```

### Preshared Key (PSK) Support

```go
// From: noise_test.go
psk := []byte("supersecretsupersecretsupersecre") // 32 bytes

hsI, _ := noise.NewHandshakeState(noise.Config{
    CipherSuite:           cs,
    Pattern:               noise.HandshakeNN,
    Initiator:             true,
    PresharedKey:          psk,
    PresharedKeyPlacement: 0, // PSK placement position
})
```

### Configuration Options

```go
// From: config.go
config := noise.Config{
    CipherSuite:           cs,           // Cryptographic primitives
    Random:                nil,          // RNG (auto-configured if nil)
    Pattern:               pattern,      // Handshake pattern
    Initiator:             true,         // True if sending first message
    Prologue:              []byte{},     // Optional pre-communicated data
    PresharedKey:          nil,          // Optional PSK (32 bytes)
    PresharedKeyPlacement: 0,            // PSK token placement
    StaticKeypair:         keypair,      // Static keypair if required
    EphemeralKeypair:      ephemeral,    // Pre-message ephemeral key
    PeerStatic:            pubkey,       // Pre-message peer static key
    PeerEphemeral:         ephemeral,    // Pre-message peer ephemeral key
}
```

### Cipher State Operations

```go
// From: cipher_state.go
// After handshake completion, use CipherState for transport encryption

// Encrypt message
ciphertext, err := cs.Encrypt(nil, nil, plaintext)

// Decrypt message
plaintext, err := cs.Decrypt(nil, nil, ciphertext)

// Rekey for forward secrecy
cs.Rekey()

// Set nonce manually (for resumption)
cs.SetNonce(1234)

// Get current nonce
nonce := cs.Nonce()
```

### Thread Safety

All `HandshakeState` and `CipherState` operations are thread-safe through internal mutex protection (from `state.go` and `cipher_state.go`).

## Security Features

- **Secure Memory Zeroing** - Sensitive key material is securely zeroed after use (see `secure_zero.go`)
- **Thread-Safe Operations** - Concurrent access protection with mutexes
- **Nonce Management** - Automatic nonce increment with overflow protection (`MaxNonce = 2^64-2`)
- **State Rollback** - Handshake state rollback on decryption failures

## License

BSD 3-Clause License. Copyright (c) 2015 Prime Directive, Inc. See `LICENSE` file for full text.
