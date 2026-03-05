package noise

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestHKDF1SHA256_MatchesGeneric(t *testing.T) {
	ck := bytes.Repeat([]byte{0xAA}, 32)
	ikm := bytes.Repeat([]byte{0xBB}, 32)

	generic := HKDF1(sha256.New, ck, ikm)
	result := HKDF1SHA256(ck, ikm)

	if !bytes.Equal(generic, result[:]) {
		t.Fatal("HKDF1SHA256 output does not match HKDF1 with sha256.New")
	}
}

func TestHKDF2SHA256_MatchesGeneric(t *testing.T) {
	ck := bytes.Repeat([]byte{0xCC}, 32)
	ikm := bytes.Repeat([]byte{0xDD}, 32)

	g1, g2 := HKDF2(sha256.New, ck, ikm)
	r1, r2 := HKDF2SHA256(ck, ikm)

	if !bytes.Equal(g1, r1[:]) {
		t.Fatal("HKDF2SHA256 output1 does not match HKDF2 with sha256.New")
	}
	if !bytes.Equal(g2, r2[:]) {
		t.Fatal("HKDF2SHA256 output2 does not match HKDF2 with sha256.New")
	}
}

func TestHKDF1SHA256_ReturnsSized(t *testing.T) {
	ck := make([]byte, 32)
	ikm := make([]byte, 0)
	result := HKDF1SHA256(ck, ikm)
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}
}

func TestHKDF2SHA256_ReturnsSized(t *testing.T) {
	ck := make([]byte, 32)
	ikm := make([]byte, 0)
	r1, r2 := HKDF2SHA256(ck, ikm)
	if len(r1) != 32 || len(r2) != 32 {
		t.Fatalf("expected 32-byte arrays, got %d and %d", len(r1), len(r2))
	}
}

func TestChaChaPoly_SHA256_Name(t *testing.T) {
	cs := ChaChaPoly_SHA256()
	expected := "25519_ChaChaPoly_SHA256"
	if string(cs.Name()) != expected {
		t.Fatalf("expected name %q, got %q", expected, string(cs.Name()))
	}
}

func TestChaChaPoly_SHA256_EqualsManual(t *testing.T) {
	convenience := ChaChaPoly_SHA256()
	manual := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	if string(convenience.Name()) != string(manual.Name()) {
		t.Fatal("ChaChaPoly_SHA256() name differs from manual construction")
	}
	if convenience.DHLen() != manual.DHLen() {
		t.Fatal("DHLen mismatch")
	}
}

func TestChaChaPoly_SHA256_Handshake(t *testing.T) {
	cs := ChaChaPoly_SHA256()

	initStatic, _ := cs.GenerateKeypair(nil)
	respStatic, _ := cs.GenerateKeypair(nil)

	init, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Pattern:       HandshakeNN,
		Initiator:     true,
		StaticKeypair: initStatic,
	})
	resp, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Pattern:       HandshakeNN,
		Initiator:     false,
		StaticKeypair: respStatic,
	})

	// -> e
	msg, _, _, err := init.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = resp.ReadMessage(nil, msg)
	if err != nil {
		t.Fatal(err)
	}

	// <- e, ee
	msg, _, _, err = resp.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = init.ReadMessage(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
}
