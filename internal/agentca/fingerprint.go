package agentca

import (
	"crypto/sha256"
	"encoding/hex"
)

// fingerprint renders the SHA-256 of a DER blob as lowercase hex.
//
// Used to bind a bootstrap token to one specific broker: a token that names
// the CA it expects cannot be replayed against a different installation, even
// one that happens to know the same agent name.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
