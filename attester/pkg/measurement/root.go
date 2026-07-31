package measurement

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"strings"
)

// Root represents a measurement of the root hash of a measurement list.
type Root struct {
	// LeafDigest is the hash of the root of the measurement list.
	LeafDigest []byte
}

// GetType returns the type of the measurement, which is [RootType].
func (r *Root) GetType() Type {
	return RootType
}

// Parse initializes the Root struct from a string representation.
// The input string is expected to contain the leaf digest in hexadecimal format.
func (r *Root) Parse(s string) error {
	fields := strings.Fields(s)
	leafDigest, err := hex.DecodeString(fields[0])
	if err != nil {
		return fmt.Errorf("failed to decode leaf digest: %w", err)
	}
	r.LeafDigest = leafDigest
	return nil
}

// GetTemplateHash returns the leaf digest of the Root measurement.
func (r *Root) GetTemplateHash() []byte {
	return r.LeafDigest
}

// IsValid checks if the Root measurement is valid. Since the root hash is a single value,
// it is always considered valid, and this method returns true.
func (r *Root) IsValid(crypto.Hash) bool {
	return true
}
