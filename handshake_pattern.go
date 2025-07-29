package noise

// A HandshakePattern is a list of messages and operations that are used to
// perform a specific Noise handshake.
// Moved from: state.go
type HandshakePattern struct {
	Name                 string
	InitiatorPreMessages []MessagePattern
	ResponderPreMessages []MessagePattern
	Messages             [][]MessagePattern
}
