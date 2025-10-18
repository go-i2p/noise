package noise

// This file imports post-quantum cryptography dependencies to ensure they are
// available for the hybrid implementation. The imports are currently unused
// but will be utilized in subsequent phases of the PQ implementation.
//
// Design Decision: We use Cloudflare's CIRCL library because:
// - It provides NIST-standardized FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)
// - Well-maintained (>3000 GitHub stars, active development)
// - Constant-time implementations to prevent timing attacks
// - Used in production by Cloudflare's edge network
// - BSD 3-Clause license compatible with this project

import (
	// MLKEM (Key Encapsulation Mechanism) implementations
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem512"
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem768"

	// MLDSA (Digital Signature Algorithm) implementations
	_ "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	_ "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	_ "github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Post-quantum cryptography support status
const (
	// PQSupported indicates whether post-quantum cryptography is available
	PQSupported = true

	// PQVersion indicates the version of PQ implementation
	PQVersion = "1.0.0-alpha"
)
