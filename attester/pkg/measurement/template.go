package measurement

import "crypto"

type Type uint8

const (
	// RootType represents a measurement of the root hash of a measurement list.
	RootType Type = iota
	// HashedFileType represents a measurement of a file, including its hash and path.
	HashedFileType
)

// Measurement is an interface that defines the methods required for a measurement type.
type Measurement interface {
	// GetType returns the type of the measurement.
	GetType() Type
	// Parse initializes the measurement from a string representation.
	Parse(string) error
	// GetTemplateHash returns the template hash of the measurement.
	GetTemplateHash() []byte
	// IsValid checks if the measurement is valid based on the provided hash algorithm.
	IsValid(crypto.Hash) bool
}
