package noise

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// Regression tests for the SSU2 data-phase constant-key defect.
//
// hkdf appends into the slices it is given, so handing it a CipherState key
// array (s1.k[:0], s2.k[:0], s.k[:0]) makes the returned slice alias that
// array. The secureZero calls that follow then destroy the live session keys,
// leaving every session with an all-zero key. The AEAD objects are built from a
// by-value copy of the key, so encryption and decryption keep working and the
// failure is silent: it is only visible through UnsafeKey(), which is exactly
// what go-noise's SSU2 data-phase KDF reads.

func isAllZero(k [32]byte) bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// splitHandshake runs a complete NN handshake and returns both sides' split
// cipher states.
func splitHandshake(t *testing.T, suite CipherSuite, seedInc byte) (i1, i2, r1, r2 *CipherState) {
	t.Helper()

	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngI = RandomInc(seedInc)
	*rngR = RandomInc(seedInc + 1)

	hsI, err := NewHandshakeState(Config{
		CipherSuite: suite,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	hsR, err := NewHandshakeState(Config{
		CipherSuite: suite,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	if _, _, _, err = hsR.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("read msg1: %v", err)
	}
	// In HandshakeNN the responder completes the handshake with message 2, so
	// its split cipher states come from WriteMessage, not ReadMessage. Assign
	// with "=" so the named returns r1/r2 are set rather than shadowed.
	var msg2 []byte
	msg2, r1, r2, err = hsR.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("write msg2: %v", err)
	}
	_, i1, i2, err = hsI.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("initiator read msg2: %v", err)
	}
	return i1, i2, r1, r2
}

var suites = map[string]CipherSuite{
	"ChaChaPoly/SHA256":  NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256),
	"ChaChaPoly/BLAKE2s": NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2s),
	"ChaChaPoly/SHA512":  NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA512),
	"AESGCM/SHA256":      NewCipherSuite(DH25519, CipherAESGCM, HashSHA256),
	"AESGCM/BLAKE2s":     NewCipherSuite(DH25519, CipherAESGCM, HashBLAKE2s),
}

// TestSplitUnsafeKeyIsLive asserts the exported key of every CipherState
// returned by Split is non-zero. Before the fix this failed for every 32-byte
// hash (SHA256, BLAKE2s) and passed only for SHA512, whose 64-byte output
// overflowed the 32-byte key array and so avoided the aliasing.
func TestSplitUnsafeKeyIsLive(t *testing.T) {
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			i1, i2, r1, r2 := splitHandshake(t, suite, 1)
			for label, cs := range map[string]*CipherState{
				"initiator-send": i1,
				"initiator-recv": i2,
				"responder-send": r1,
				"responder-recv": r2,
			} {
				if k := cs.UnsafeKey(); isAllZero(k) {
					t.Errorf("%s: UnsafeKey() is all zeros after Split", label)
				}
			}
		})
	}
}

// TestSplitKeysAgreeAcrossParties asserts both peers derive the same two keys
// in the same order, per Noise: Split returns k_ab then k_ba for both roles and
// each caller picks by role. This is the convention go-noise's
// HandshakeHandler.updateCipherStates relies on.
func TestSplitKeysAgreeAcrossParties(t *testing.T) {
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			i1, i2, r1, r2 := splitHandshake(t, suite, 1)
			if i1.UnsafeKey() != r1.UnsafeKey() {
				t.Error("initiator split key 1 != responder split key 1")
			}
			if i2.UnsafeKey() != r2.UnsafeKey() {
				t.Error("initiator split key 2 != responder split key 2")
			}
			if i1.UnsafeKey() == i2.UnsafeKey() {
				t.Error("the two directional keys are identical")
			}

			// Functional form of the same property. This fork returns the
			// directional pair (k_ab, k_ba) for both roles without swapping,
			// so the initiator sends on key 1 and the responder receives on
			// key 1; go-noise's updateCipherStates maps the pair to send/recv
			// by role on that convention.
			pt := []byte("directional")
			ct, err := i1.Encrypt(nil, nil, pt)
			if err != nil {
				t.Fatalf("initiator Encrypt: %v", err)
			}
			got, err := r1.Decrypt(nil, nil, ct)
			if err != nil {
				t.Fatalf("responder Decrypt on key 1: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("cross-decrypt = %q, want %q", got, pt)
			}

			// And in the other direction: responder sends on key 2.
			pt2 := []byte("reverse direction")
			ct2, err := r2.Encrypt(nil, nil, pt2)
			if err != nil {
				t.Fatalf("responder Encrypt: %v", err)
			}
			got2, err := i2.Decrypt(nil, nil, ct2)
			if err != nil {
				t.Fatalf("initiator Decrypt on key 2: %v", err)
			}
			if !bytes.Equal(got2, pt2) {
				t.Errorf("reverse cross-decrypt = %q, want %q", got2, pt2)
			}
		})
	}
}

// TestSplitKeysDifferBetweenSessions is the assertion that specifically kills
// the "public constant" class of bug: two handshakes with different randomness
// must not share a data key.
func TestSplitKeysDifferBetweenSessions(t *testing.T) {
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			a1, a2, _, _ := splitHandshake(t, suite, 1)
			b1, b2, _, _ := splitHandshake(t, suite, 2)
			if a1.UnsafeKey() == b1.UnsafeKey() {
				t.Error("send key repeats across sessions with different randomness")
			}
			if a2.UnsafeKey() == b2.UnsafeKey() {
				t.Error("recv key repeats across sessions with different randomness")
			}
		})
	}
}

// TestSplitMatchesIndependentHKDF2 checks Split's keys against an HKDF
// computed outside the library, so the fix cannot silently change the key
// schedule.
func TestSplitMatchesIndependentHKDF2(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	ss := &SymmetricState{}
	ss.cs = suite
	ss.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))
	ss.MixKey(bytes.Repeat([]byte{0x11}, 32))

	ckCopy := make([]byte, len(ss.ck))
	copy(ckCopy, ss.ck)

	// Noise §5: temp_key = HMAC(ck, ZEROLEN); k1 = HMAC(temp_key, 0x01);
	// k2 = HMAC(temp_key, k1 || 0x02).
	tempMAC := hmac.New(sha256.New, ckCopy)
	tempMAC.Write(nil)
	tempKey := tempMAC.Sum(nil)
	m1 := hmac.New(sha256.New, tempKey)
	m1.Write([]byte{0x01})
	want1 := m1.Sum(nil)
	m2 := hmac.New(sha256.New, tempKey)
	m2.Write(want1)
	m2.Write([]byte{0x02})
	want2 := m2.Sum(nil)

	s1, s2 := ss.Split()
	if got := s1.UnsafeKey(); !bytes.Equal(got[:], want1[:32]) {
		t.Errorf("split key 1 = %x, want %x", got[:], want1)
	}
	if got := s2.UnsafeKey(); !bytes.Equal(got[:], want2[:32]) {
		t.Errorf("split key 2 = %x, want %x", got[:], want2)
	}
}

// TestSplitWithASKKeysAreLive covers the production path used by the I2P
// handshake, which carries the same defect as Split.
func TestSplitWithASKKeysAreLive(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	label := []byte("ask")

	ss := &SymmetricState{}
	ss.cs = suite
	ss.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))
	ss.MixKey(bytes.Repeat([]byte{0x22}, 32))

	s1, s2, asks := ss.SplitWithASK(label)
	if len(asks) != 1 {
		t.Fatalf("expected 1 ASK, got %d", len(asks))
	}
	if isAllZero(s1.UnsafeKey()) {
		t.Error("SplitWithASK: send key is all zeros")
	}
	if isAllZero(s2.UnsafeKey()) {
		t.Error("SplitWithASK: recv key is all zeros")
	}
	if s1.UnsafeKey() == s2.UnsafeKey() {
		t.Error("SplitWithASK: send and recv keys are identical")
	}
}

// TestMixKeyKeepsCipherKeyLive asserts MixKey leaves a real key in the
// SymmetricState's embedded CipherState. MixKey aliases s.k in exactly the same
// way Split does, so the defect class is shared even though no current caller
// reads the key mid-handshake.
func TestMixKeyKeepsCipherKeyLive(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	ss := &SymmetricState{}
	ss.cs = suite
	ss.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))

	ckCopy := make([]byte, len(ss.ck))
	copy(ckCopy, ss.ck)
	ikm := bytes.Repeat([]byte{0x33}, 32)

	ss.MixKey(ikm)

	tempMAC := hmac.New(sha256.New, ckCopy)
	tempMAC.Write(ikm)
	tempKey := tempMAC.Sum(nil)
	m1 := hmac.New(sha256.New, tempKey)
	m1.Write([]byte{0x01})
	wantCK := m1.Sum(nil)
	m2 := hmac.New(sha256.New, tempKey)
	m2.Write(wantCK)
	m2.Write([]byte{0x02})
	wantK := m2.Sum(nil)

	if got := ss.UnsafeKey(); isAllZero(got) {
		t.Error("MixKey: cipher key is all zeros")
	} else if !bytes.Equal(got[:], wantK[:32]) {
		t.Errorf("MixKey: cipher key = %x, want %x", got[:], wantK)
	}
	if got := ss.ChainingKey(); !bytes.Equal(got, wantCK) {
		t.Errorf("MixKey: chaining key = %x, want %x", got, wantCK)
	}
}

// TestMixKeyAndHashKeepsCipherKeyLive is the MixKeyAndHash counterpart; its
// third HKDF output is likewise written into s.k[:0].
func TestMixKeyAndHashKeepsCipherKeyLive(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

	ss := &SymmetricState{}
	ss.cs = suite
	ss.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))

	ckCopy := make([]byte, len(ss.ck))
	copy(ckCopy, ss.ck)
	data := bytes.Repeat([]byte{0x44}, 32)

	ss.MixKeyAndHash(data)

	tempMAC := hmac.New(sha256.New, ckCopy)
	tempMAC.Write(data)
	tempKey := tempMAC.Sum(nil)
	m1 := hmac.New(sha256.New, tempKey)
	m1.Write([]byte{0x01})
	wantCK := m1.Sum(nil)
	m2 := hmac.New(sha256.New, tempKey)
	m2.Write(wantCK)
	m2.Write([]byte{0x02})
	temp := m2.Sum(nil)
	m3 := hmac.New(sha256.New, tempKey)
	m3.Write(temp)
	m3.Write([]byte{0x03})
	wantK := m3.Sum(nil)

	if got := ss.UnsafeKey(); isAllZero(got) {
		t.Error("MixKeyAndHash: cipher key is all zeros")
	} else if !bytes.Equal(got[:], wantK[:32]) {
		t.Errorf("MixKeyAndHash: cipher key = %x, want %x", got[:], wantK)
	}
	if got := ss.ChainingKey(); !bytes.Equal(got, wantCK) {
		t.Errorf("MixKeyAndHash: chaining key = %x, want %x", got, wantCK)
	}
}

// TestSplitKeysRoundTripThroughAEAD confirms the live key and the key inside
// the cipher agree: encrypting with one CipherState and decrypting with a
// CipherState rebuilt from UnsafeKey must work. Before the fix the rebuilt
// state used the zeroed key and failed.
func TestSplitKeysRoundTripThroughAEAD(t *testing.T) {
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			i1, _, _, _ := splitHandshake(t, suite, 1)

			pt := []byte("secret data phase")
			ct, err := i1.Encrypt(nil, nil, pt)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			rebuilt := UnsafeNewCipherState(suite, i1.UnsafeKey(), 0)
			got, err := rebuilt.Decrypt(nil, nil, ct)
			if err != nil {
				t.Fatalf("Decrypt with rebuilt state: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("round trip = %q, want %q", got, pt)
			}
		})
	}
}
