package noise

import (
	"crypto/hmac"
	"hash"
)

// validateHKDFInputs validates the input parameters for HKDF function.
func validateHKDFInputs(outputs int, out1, out2, out3 []byte) {
	if len(out1) > 0 {
		panic("len(out1) > 0")
	}
	if len(out2) > 0 {
		panic("len(out2) > 0")
	}
	if len(out3) > 0 {
		panic("len(out3) > 0")
	}
	if outputs > 3 {
		panic("outputs > 3")
	}
}

// generateTempKey creates the temporary key from chaining key and input key material.
func generateTempKey(h func() hash.Hash, chainingKey, inputKeyMaterial, out2 []byte) []byte {
	tempMAC := hmac.New(h, chainingKey)
	tempMAC.Write(inputKeyMaterial)
	return tempMAC.Sum(out2)
}

// generateFirstOutput generates the first HKDF output.
func generateFirstOutput(h func() hash.Hash, tempKey, out1 []byte) []byte {
	out1MAC := hmac.New(h, tempKey)
	out1MAC.Write([]byte{0x01})
	return out1MAC.Sum(out1)
}

// generateSecondOutput generates the second HKDF output.
func generateSecondOutput(h func() hash.Hash, tempKey, out1, out2 []byte) []byte {
	out2MAC := hmac.New(h, tempKey)
	out2MAC.Write(out1)
	out2MAC.Write([]byte{0x02})
	return out2MAC.Sum(out2)
}

// generateThirdOutput generates the third HKDF output.
func generateThirdOutput(h func() hash.Hash, tempKey, out2, out3 []byte) []byte {
	out3MAC := hmac.New(h, tempKey)
	out3MAC.Write(out2)
	out3MAC.Write([]byte{0x03})
	return out3MAC.Sum(out3)
}

func hkdf(h func() hash.Hash, outputs int, out1, out2, out3, chainingKey, inputKeyMaterial []byte) ([]byte, []byte, []byte) {
	validateHKDFInputs(outputs, out1, out2, out3)

	tempKey := generateTempKey(h, chainingKey, inputKeyMaterial, out2)
	out1 = generateFirstOutput(h, tempKey, out1)

	if outputs == 1 {
		return out1, nil, nil
	}

	out2 = generateSecondOutput(h, tempKey, out1, out2)

	if outputs == 2 {
		return out1, out2, nil
	}

	out3 = generateThirdOutput(h, tempKey, out2, out3)
	return out1, out2, out3
}

// HKDF1 performs HKDF expansion with one output using the provided hash function,
// chaining key, and input key material. It returns a single derived key.
// This implements the single-output variant of HKDF from the Noise Protocol
// Framework §4.
func HKDF1(h func() hash.Hash, chainingKey, inputKeyMaterial []byte) []byte {
	out1, _, _ := hkdf(h, 1, nil, nil, nil, chainingKey, inputKeyMaterial)
	return out1
}

// HKDF2 performs HKDF expansion with two outputs using the provided hash function,
// chaining key, and input key material. It returns two derived keys.
// This implements the two-output variant of HKDF from the Noise Protocol
// Framework §4.
func HKDF2(h func() hash.Hash, chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
	out1, out2, _ := hkdf(h, 2, nil, nil, nil, chainingKey, inputKeyMaterial)
	return out1, out2
}
