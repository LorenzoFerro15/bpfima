package measurement

import (
	"crypto"
	"errors"
)

// Type identifies the kind of a [Measurement].
type Type uint8

const (
	// LeafType represents a leaf of the Merkle tree (see [Leaf]).
	LeafType Type = iota
	// HashedFileType represents a measurement of a file, including its hash and path.
	HashedFileType
)

var (
	// ErrMalformedEntry is returned when a measurement list line cannot be parsed.
	ErrMalformedEntry = errors.New("malformed measurement entry")
	// ErrInvalidEntry is returned when a parsed measurement fails validation.
	ErrInvalidEntry = errors.New("invalid measurement entry")
)

// Measurement is a single, parsed entry of a measurement list.
type Measurement interface {
	// Type returns the kind of the measurement.
	Type() Type
	// TemplateHash returns the digest that is extended into the list aggregate.
	TemplateHash() []byte
	// Validate checks the measurement integrity using the provided hash algorithm.
	// It returns an error wrapping [ErrInvalidEntry] on failure.
	Validate(hashAlgo crypto.Hash) error
}

// Parser converts a measurement list line into a [Measurement].
type Parser func(line string) (Measurement, error)
