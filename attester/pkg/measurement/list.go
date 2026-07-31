package measurement

import (
	"bpfima/pkg/attestation"
	"bpfima/pkg/reader"
	"crypto"
	"errors"
	"fmt"
)

// List holds a measurement list reader, the current parsed entry, and a PCR that
// accumulates the aggregate as entries are processed.
type List struct {
	Entry  Measurement
	Reader reader.ListReader
	PCR    attestation.PCR
}

// newList is the shared constructor used by all public List factory functions.
func newList(entry Measurement, listReader reader.ListReader, hashAlgo crypto.Hash) (*List, error) {
	pcr, err := attestation.NewPCR(hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR: %w", err)
	}
	return &List{
		Entry:  entry,
		Reader: listReader,
		PCR:    *pcr,
	}, nil
}

// NewHashedFileMeasurementList creates a List for HashedFile entries
// (e.g. container or namespace measurement lists).
func NewHashedFileMeasurementList(listReader reader.ListReader, hashAlgo crypto.Hash) (*List, error) {
	return newList(&HashedFile{}, listReader, hashAlgo)
}

// NewRootMeasurementList creates a List for Root entries
// (i.e. the Merkle root history / leaf-digest list).
func NewRootMeasurementList(listReader reader.ListReader, hashAlgo crypto.Hash) (*List, error) {
	return newList(&Root{}, listReader, hashAlgo)
}

// NewMeasurementList creates a List with a caller-provided Measurement type.
func NewMeasurementList(measurement Measurement, listReader reader.ListReader, hashAlgo crypto.Hash) (*List, error) {
	return newList(measurement, listReader, hashAlgo)
}

// ResetAggregate resets the PCR aggregate to its initial all-zero state.
func (ml *List) ResetAggregate() {
	ml.PCR.Reset()
}

// ParseEntry reads the next line from the reader, parses it into the current Entry,
// and validates it. Returns an error if any step fails.
func (ml *List) ParseEntry() error {
	line, err := ml.Reader.ReadLine()
	if err != nil {
		return fmt.Errorf("measurement list read error: %w", err)
	}

	if err = ml.Entry.Parse(line); err != nil {
		return fmt.Errorf("measurement list parse error: %w", err)
	}

	if !ml.Entry.IsValid(ml.PCR.GetHashAlgo()) {
		return errors.New("measurement list entry validation error")
	}
	return nil
}
