package measurement

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// Separator is the string used to separate the fields of a measurement line
// and the file hash and file path in the template hash computation.
const Separator = " "

// hashedFileFields is the number of fields of a [HashedFile] line:
// template hash, event, file hash and file path.
const hashedFileFields = 4

// HashedFile represents a measurement of a file, including its hash and path.
type HashedFile struct {
	// templateHash is H(fileHash || Separator || filePath).
	templateHash []byte
	// event is the name of the hook that produced the measurement.
	event string
	// fileHash is the hash of the file's content in hexadecimal format.
	fileHash string
	// filePath is the path to the measured file, followed by its process ancestry.
	filePath string
}

// ParseHashedFile parses a line of the form "<template hash> <event> <file hash> <file path>".
// The file path is the remainder of the line, so it may contain spaces.
func ParseHashedFile(line string) (*HashedFile, error) {
	fields := strings.SplitN(line, Separator, hashedFileFields)
	if len(fields) != hashedFileFields {
		return nil, fmt.Errorf("%w: want %d fields, got %d", ErrMalformedEntry, hashedFileFields, len(fields))
	}
	templateHash, err := hex.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode template hash: %w", ErrMalformedEntry, err)
	}
	return &HashedFile{
		templateHash: templateHash,
		event:        fields[1],
		fileHash:     fields[2],
		filePath:     fields[3],
	}, nil
}

// Type returns [HashedFileType].
func (h *HashedFile) Type() Type {
	return HashedFileType
}

// TemplateHash returns the template hash of the measurement.
func (h *HashedFile) TemplateHash() []byte {
	return h.templateHash
}

// Event returns the name of the hook that produced the measurement.
func (h *HashedFile) Event() string {
	return h.event
}

// FileHash returns the hexadecimal hash of the file's content.
func (h *HashedFile) FileHash() string {
	return h.fileHash
}

// FilePath returns the path of the measured file.
func (h *HashedFile) FilePath() string {
	return h.filePath
}

// Validate recomputes the template hash as H(fileHash || Separator || filePath)
// and compares it with the stored one.
func (h *HashedFile) Validate(hashAlgo crypto.Hash) error {
	hash := hashAlgo.New()
	hash.Write([]byte(h.fileHash))
	hash.Write([]byte(Separator))
	hash.Write([]byte(h.filePath))
	if subtle.ConstantTimeCompare(h.templateHash, hash.Sum(nil)) != 1 {
		return fmt.Errorf("%w: template hash mismatch for %s", ErrInvalidEntry, h.filePath)
	}
	return nil
}
