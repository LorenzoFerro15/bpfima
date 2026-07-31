package measurement

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// Separator is the string used to separate the file
// hash and file path in the template hash computation.
const Separator = " "

// HashedFile represents a measurement of a file, including its hash and path.
type HashedFile struct {
	// templateHash is the hash of the file's content and path, computed using a specific hash algorithm.
	templateHash []byte
	// Event is a string representing the event associated with the file measurement.
	event string
	// FileHash is the hash of the file's content in hexadecimal format.
	fileHash string
	// FilePath is the path to the file being measured.
	filePath string
}

// GetType returns the type of the measurement, which is [HashedFileType].
func (h *HashedFile) GetType() Type {
	return HashedFileType
}

// Parse initializes the HashedFile struct from a string representation.
// The input string is expected to contain the template hash, event, file hash, and file path,
// separated by whitespace. The template hash is decoded from hexadecimal format.
func (h *HashedFile) Parse(s string) error {
	fields := strings.Fields(s)
	templateHash, err := hex.DecodeString(fields[0])
	if err != nil {
		return fmt.Errorf("failed to decode template hash: %w", err)
	}
	h.templateHash = templateHash
	h.event = fields[1]
	h.fileHash = fields[2]
	h.filePath = fields[3]
	return nil
}

// GetTemplateHash returns the template hash of the HashedFile measurement.
func (h *HashedFile) GetTemplateHash() []byte {
	return h.templateHash
}

// IsValid checks if the HashedFile measurement is valid by recomputing the template hash
// using the provided hash algorithm and comparing it to the stored template hash.
// It returns true if the computed hash matches the stored template hash, indicating validity.
func (h *HashedFile) IsValid(hashAlgo crypto.Hash) bool {
	hash := hashAlgo.New()
	hash.Write([]byte(h.fileHash))
	hash.Write([]byte(Separator))
	hash.Write([]byte(h.filePath))
	return subtle.ConstantTimeCompare(h.templateHash, hash.Sum(nil)) == 1
}
