package main

import (
	"bytes"
	"encoding/hex"
	"io"
)

// hexReader creates an io.Reader from a hex-encoded string
// Used for deterministic key generation in test vectors
// Moved from: vectorgen/vectorgen.go
func hexReader(s string) io.Reader {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes.NewBuffer(res)
}
