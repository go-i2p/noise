package noise

import "runtime"

// secureZero securely zeroes the provided byte slice to prevent sensitive data
// from remaining in memory. This function prevents the compiler from optimizing
// away the zeroing operation.
func secureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Force compiler to not optimize away the zeroing
	runtime.KeepAlive(b)
}
