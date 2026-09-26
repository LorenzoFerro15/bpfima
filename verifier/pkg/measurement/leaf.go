package measurement

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"strings"
)

// Leaf is a leaf of the bpfima Merkle tree: the aggregate of a target measurement
// list at the time it was extended. The Merkle root is the aggregate of all leaves.
type Leaf struct {
	// digest is the target list aggregate recorded as a Merkle leaf.
	digest []byte
}

// ParseLeaf parses a line of the form "<leaf digest> [optional annotations]".
func ParseLeaf(line string) (*Leaf, error) {
	hexDigest, _, _ := strings.Cut(line, Separator)
	if hexDigest == "" {
		return nil, fmt.Errorf("%w: empty leaf digest", ErrMalformedEntry)
	}
	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode leaf digest: %w", ErrMalformedEntry, err)
	}
	return &Leaf{digest: digest}, nil
}

// Type returns [LeafType].
func (l *Leaf) Type() Type {
	return LeafType
}

// TemplateHash returns the leaf digest.
func (l *Leaf) TemplateHash() []byte {
	return l.digest
}

// Digest returns the leaf digest.
func (l *Leaf) Digest() []byte {
	return l.digest
}

// Validate checks that the leaf digest has the size of the hash algorithm.
// A leaf is an opaque digest, so its content cannot be verified in isolation.
func (l *Leaf) Validate(hashAlgo crypto.Hash) error {
	if len(l.digest) != hashAlgo.Size() {
		return fmt.Errorf("%w: leaf digest size: want %d bytes, got %d",
			ErrInvalidEntry, hashAlgo.Size(), len(l.digest))
	}
	return nil
}
