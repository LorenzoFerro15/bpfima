package reader

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
)

// RawReader is a concrete implementation of the ListReader
// interface that reads measurement lists from raw bytes.
type RawReader struct {
	raw    []byte
	reader *bufio.Reader
	ptr    int64
}

// NewRawReader creates a new RawReader for the specified raw byte slice.
func NewRawReader(raw []byte) *RawReader {
	return &RawReader{
		raw: raw,
	}
}

// GetType returns the type of the reader, which is [Raw].
func (r *RawReader) GetType() Type {
	return Raw
}

// Open initializes the buffered reader for the raw byte slice.
func (r *RawReader) Open() error {
	r.reader = bufio.NewReader(bytes.NewReader(r.raw))
	return nil
}

// SetPosition sets the read position for the raw byte slice. It resets the buffered reader
// to start reading from the specified position. It returns an error if the reader is not ready.
func (r *RawReader) SetPosition(pos int64) error {
	if !r.IsReady() {
		return errors.New("RawReader not open")
	}
	posRaw := r.raw[pos:]
	r.reader.Reset(bytes.NewReader(posRaw))
	r.ptr = pos
	return nil
}

// IsReady checks if the RawReader is ready for reading. It returns true if the raw
// byte slice is not nil and the reader is initialized.
func (r *RawReader) IsReady() bool {
	return r.raw != nil && r.reader != nil
}

// Close releases the resources associated with the RawReader. It sets the reader to nil.
func (r *RawReader) Close() error {
	r.reader = nil
	return nil
}

// ReadLine reads a single line from the raw byte slice. It returns the line as a string
// and any error encountered during reading. The line is returned without the newline character.
func (r *RawReader) ReadLine() (string, error) {
	line, err := r.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read line: %w", err)
	}
	lineLen := len(line)
	r.ptr += int64(lineLen)
	return line[:lineLen-1], nil
}

// Available returns the number of bytes available for reading from the raw byte slice.
func (r *RawReader) Available() int64 {
	return int64(len(r.raw)) - r.ptr
}
