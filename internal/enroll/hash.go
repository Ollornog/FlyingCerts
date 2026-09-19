package enroll

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashSecret hashes a token secret for storage.
//
// Plain SHA-256, and that is a considered choice rather than an oversight. A
// slow hash (bcrypt, argon2) exists to make guessing expensive, which matters
// when the input is a human-chosen password. This input is 32 bytes from
// crypto/rand — there is no dictionary to run, and no amount of stretching
// improves on that. What hashing does buy is that a stolen store yields no
// usable tokens, and SHA-256 delivers exactly that.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
