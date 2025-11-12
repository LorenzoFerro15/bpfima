package reader

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

// FileReader is a concrete implementation of the ListReader
// interface that reads measurement lists from a file.
type FileReader struct {
	path   string
	file   *os.File      // measurement list file descriptor
	reader *bufio.Reader // scanner for measurement list file
	ptr    int64
}

// NewFileReader creates a new FileReader for the specified file path.
func NewFileReader(path string) *FileReader {
	return &FileReader{path: path}
}

// GetType returns the type of the reader, which is [File].
func (r *FileReader) GetType() Type {
	return File
}

// Open opens the measurement list file for reading and initializes the buffered reader.
// It returns an error if the file cannot be opened.
func (r *FileReader) Open() error {
	f, err := os.Open(r.path)
	if err != nil {
		return fmt.Errorf("failed to open measurement list: %w", err)
	}
	r.file = f
	r.reader = bufio.NewReader(f)
	return nil
}

// SetPosition sets the read position for the measurement list file. It seeks to the specified position
// and resets the buffered reader. It returns an error if the file is not open or if seeking fails.
func (r *FileReader) SetPosition(pos int64) error {
	if r.file == nil {
		return errors.New("file is not open")
	}
	_, err := r.file.Seek(pos, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to measurement list: %w", err)
	}
	r.ptr = pos
	r.reader.Reset(r.file)
	return nil
}

// IsReady checks if the FileReader is ready for reading. It returns true if the file is open and the reader is initialized.
func (r *FileReader) IsReady() bool {
	return r.file != nil && r.reader != nil
}

// Close closes the measurement list file and releases associated resources.
// It returns an error if closing the file fails.
func (r *FileReader) Close() error {
	err := r.file.Close()
	if err != nil {
		return fmt.Errorf("failed to close measurement list: %w", err)
	}
	r.reader = nil
	return nil
}

// ReadLine reads the next line from the measurement list file,
// updates the read offset, and returns the line as a string.
// It returns an error if reading the line fails.
func (r *FileReader) ReadLine() (string, error) {
	line, err := r.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read line: %w", err)
	}
	lineLen := len(line)
	r.ptr += int64(lineLen)
	return line[:lineLen-1], nil
}

// Available returns the number of bytes available to read from the measurement list file.
// It returns -1 if the file is not open or if an error occurs while retrieving the file size.
func (r *FileReader) Available() int64 {
	stat, err := r.file.Stat()
	if err != nil {
		return -1
	}
	return stat.Size() - r.ptr
}
