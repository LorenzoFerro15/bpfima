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

// DependencySeparator separates the path and the names of the ancestor
// processes in the dependencies of a measurement (see [HashedFile.FilePath]).
const DependencySeparator = ":"

// Names of the events recorded by the bpfima hooks.
const (
	EventBprmCheckSecurity = "bprm_check_security"
	EventFilePostOpen      = "file_post_open"
	EventMmapFile          = "mmap_file"
	EventSocketConnect     = "socket_connect"
	EventInodeSetattr      = "inode_setattr"
)

// fileEvents are the events measuring the content of a file: their file hash
// is the hash of the file at their path.
var fileEvents = map[string]bool{
	EventBprmCheckSecurity: true,
	EventFilePostOpen:      true,
	EventMmapFile:          true,
}

// hashedFileFields is the number of fields of a [HashedFile] line:
// template hash, event, file hash and file path.
const hashedFileFields = 4

// HashedFile represents a measurement of a file, including its hash and path.
//
// Other events are recorded in the same form, with event specific data in
// place of the file hash, e.g. the addresses of a socket connection: see
// [HashedFile.IsFile].
type HashedFile struct {
	// templateHash is H(fileHash || Separator || filePath), or H(fileHash) without a file path.
	templateHash []byte
	// event is the name of the hook that produced the measurement.
	event string
	// fileHash is the hash of the file's content in hexadecimal format.
	fileHash string
	// filePath is the path to the measured file, followed by its process ancestry.
	filePath string
}

// ParseHashedFile parses a line of the form "<template hash> <event> <file hash> [<file path>]".
// The file path is the remainder of the line, so it may contain spaces. It is
// missing when the measurement has no dependencies, e.g. for [EventInodeSetattr].
func ParseHashedFile(line string) (*HashedFile, error) {
	fields := strings.SplitN(line, Separator, hashedFileFields)
	if len(fields) < hashedFileFields-1 {
		return nil, fmt.Errorf("%w: want at least %d fields, got %d",
			ErrMalformedEntry, hashedFileFields-1, len(fields))
	}
	templateHash, err := hex.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode template hash: %w", ErrMalformedEntry, err)
	}
	h := &HashedFile{
		templateHash: templateHash,
		event:        fields[1],
		fileHash:     fields[2],
	}
	if len(fields) == hashedFileFields {
		h.filePath = fields[3]
	}
	return h, nil
}

// NewHashedFile creates the measurement of an event, computing its template
// hash with hashAlgo as the kernel module does. filePath is empty for the
// measurements without dependencies.
func NewHashedFile(hashAlgo crypto.Hash, event, fileHash, filePath string) *HashedFile {
	h := &HashedFile{event: event, fileHash: fileHash, filePath: filePath}
	h.templateHash = h.computeTemplateHash(hashAlgo)
	return h
}

// NewFileMeasurement creates the measurement of the content of the file at path
// by a file event (see [HashedFile.IsFile]), recorded with the names of the
// ancestor processes of the measured process, from its parent.
func NewFileMeasurement(hashAlgo crypto.Hash, event, fileHash, path string, ancestry ...string) *HashedFile {
	dependencies := strings.Join(append([]string{path}, ancestry...), DependencySeparator)
	return NewHashedFile(hashAlgo, event, fileHash, dependencies)
}

// String returns the measurement list line of the measurement.
func (h *HashedFile) String() string {
	line := hex.EncodeToString(h.templateHash) + Separator + h.event + Separator + h.fileHash
	if h.filePath != "" {
		line += Separator + h.filePath
	}
	return line
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

// IsFile reports whether the measurement is of the content of a file, i.e.
// [HashedFile.FileHash] is the hash of the file at [HashedFile.Path]. Other
// measurements, e.g. of socket connections, carry event specific data instead.
func (h *HashedFile) IsFile() bool {
	return fileEvents[h.event]
}

// FileHash returns the hexadecimal hash of the file's content.
func (h *HashedFile) FileHash() string {
	return h.fileHash
}

// FilePath returns the dependencies of the measurement: the path of the
// measured file followed by the names of the ancestor processes, separated by
// [DependencySeparator]. See [HashedFile.Path] and [HashedFile.Ancestry].
func (h *HashedFile) FilePath() string {
	return h.filePath
}

// Path returns the path of the measured file, without the process ancestry.
// The kernel does not escape [DependencySeparator], so a path containing it is
// truncated at its first occurrence.
func (h *HashedFile) Path() string {
	path, _, _ := strings.Cut(h.filePath, DependencySeparator)
	return path
}

// Ancestry returns the names of the ancestor processes of the measured
// process, from its parent, or nil if they were not recorded.
func (h *HashedFile) Ancestry() []string {
	_, ancestry, ok := strings.Cut(h.filePath, DependencySeparator)
	if !ok || ancestry == "" {
		return nil
	}
	return strings.Split(ancestry, DependencySeparator)
}

// Validate recomputes the template hash as H(fileHash || Separator || filePath),
// or H(fileHash) without a file path, and compares it with the stored one.
func (h *HashedFile) Validate(hashAlgo crypto.Hash) error {
	if subtle.ConstantTimeCompare(h.templateHash, h.computeTemplateHash(hashAlgo)) != 1 {
		return fmt.Errorf("%w: template hash mismatch for %s %s", ErrInvalidEntry, h.event, h.filePath)
	}
	return nil
}

// computeTemplateHash returns H(fileHash || Separator || filePath), or H(fileHash) without a file path.
func (h *HashedFile) computeTemplateHash(hashAlgo crypto.Hash) []byte {
	hash := hashAlgo.New()
	hash.Write([]byte(h.fileHash))
	if h.filePath != "" {
		hash.Write([]byte(Separator))
		hash.Write([]byte(h.filePath))
	}
	return hash.Sum(nil)
}
