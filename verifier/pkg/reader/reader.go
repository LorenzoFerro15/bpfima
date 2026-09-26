package reader

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Reader reads a measurement list line by line from a seekable source.
// The zero value is not usable; create one with [New], [FromBytes] or [OpenFile].
type Reader struct {
	src    io.ReadSeeker
	closer io.Closer
	buf    *bufio.Reader
}

// New creates a Reader that reads lines from src, starting at its current offset.
func New(src io.ReadSeeker) *Reader {
	return &Reader{src: src, buf: bufio.NewReader(src)}
}

// FromBytes creates a Reader over an in-memory measurement list.
func FromBytes(raw []byte) *Reader {
	return New(bytes.NewReader(raw))
}

// OpenFile opens the measurement list at path for reading.
// The caller must call [Reader.Close] to release the file.
func OpenFile(path string) (*Reader, error) {
	f, err := os.Open(path) //nolint:gosec // path is provided by the caller on purpose
	if err != nil {
		return nil, fmt.Errorf("failed to open measurement list: %w", err)
	}
	r := New(f)
	r.closer = f
	return r, nil
}

// ReadLine returns the next line without its trailing line terminator ("\n" or "\r\n").
// A final line that is not newline-terminated is still returned.
// It returns [io.EOF] when there are no more lines.
func (r *Reader) ReadLine() (string, error) {
	line, err := r.buf.ReadString('\n')
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("failed to read line: %w", err)
		}
		if line == "" {
			return "", io.EOF
		}
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Rewind moves the read position back to the start of the list.
func (r *Reader) Rewind() error {
	if _, err := r.src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind measurement list: %w", err)
	}
	r.buf.Reset(r.src)
	return nil
}

// Close releases the underlying source if the Reader owns it (see [OpenFile]).
func (r *Reader) Close() error {
	if r.closer == nil {
		return nil
	}
	if err := r.closer.Close(); err != nil {
		return fmt.Errorf("failed to close measurement list: %w", err)
	}
	return nil
}
