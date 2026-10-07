package measurement

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/pcr"
)

// LineReader is the source of a measurement [List] (e.g. a reader.Reader).
type LineReader interface {
	// ReadLine returns the next line without its trailing newline, or [io.EOF] at the end.
	ReadLine() (string, error)
	// Rewind moves the read position back to the start of the list.
	Rewind() error
}

// List iterates over a measurement list, validating each entry and extending
// its template hash into a PCR that holds the list aggregate.
type List struct {
	src       LineReader
	parse     Parser
	aggregate *pcr.PCR
	current   Measurement
}

// NewList creates a List reading entries from src and decoding them with parse.
func NewList(src LineReader, parse Parser, hashAlgo crypto.Hash) (*List, error) {
	aggregate, err := pcr.New(hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create list aggregate: %w", err)
	}
	return &List{src: src, parse: parse, aggregate: aggregate}, nil
}

// NewHashedFileList creates a List of [HashedFile] entries
// (e.g. container or namespace measurement lists).
func NewHashedFileList(src LineReader, hashAlgo crypto.Hash) (*List, error) {
	return NewList(src, func(line string) (Measurement, error) { return ParseHashedFile(line) }, hashAlgo)
}

// HashedFiles reads every entry of a list of [HashedFile] entries (e.g. a
// container measurement list), validating their template hashes.
func HashedFiles(src LineReader, hashAlgo crypto.Hash) ([]*HashedFile, error) {
	list, err := NewHashedFileList(src, hashAlgo)
	if err != nil {
		return nil, err
	}

	var entries []*HashedFile
	for {
		err = list.Next()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		entry, ok := list.Current().(*HashedFile)
		if !ok {
			return nil, fmt.Errorf("%w: not a hashed file", ErrMalformedEntry)
		}
		entries = append(entries, entry)
	}
}

// MarshalHashedFiles returns the measurement list of the entries, one line per
// entry, as the kernel module writes it and [HashedFiles] reads it.
func MarshalHashedFiles(entries ...*HashedFile) []byte {
	var b bytes.Buffer
	for _, entry := range entries {
		b.WriteString(entry.String())
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// NewLeafList creates a List of [Leaf] entries (i.e. the Merkle leaf list).
func NewLeafList(src LineReader, hashAlgo crypto.Hash) (*List, error) {
	return NewList(src, func(line string) (Measurement, error) { return ParseLeaf(line) }, hashAlgo)
}

// Next reads, parses and validates the next entry, then extends its template hash
// into the list aggregate. It returns [io.EOF] when the list is exhausted.
func (l *List) Next() error {
	line, err := l.src.ReadLine()
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if err != nil {
		return fmt.Errorf("measurement list read error: %w", err)
	}

	entry, err := l.parse(line)
	if err != nil {
		return fmt.Errorf("measurement list parse error: %w", err)
	}
	if err = entry.Validate(l.HashAlgo()); err != nil {
		return fmt.Errorf("measurement list validation error: %w", err)
	}

	l.current = entry
	l.aggregate.Extend(entry.TemplateHash())
	return nil
}

// Current returns the entry read by the last successful call to [List.Next], or nil.
func (l *List) Current() Measurement {
	return l.current
}

// Aggregate returns the current list aggregate.
func (l *List) Aggregate() []byte {
	return l.aggregate.Read()
}

// HashAlgo returns the hash algorithm used by the list.
func (l *List) HashAlgo() crypto.Hash {
	return l.aggregate.HashAlgo()
}

// Reset rewinds the list to its first entry and zeroes the aggregate.
func (l *List) Reset() error {
	if err := l.src.Rewind(); err != nil {
		return fmt.Errorf("failed to reset measurement list: %w", err)
	}
	l.aggregate.Reset()
	l.current = nil
	return nil
}
