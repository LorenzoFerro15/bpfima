package reader

// Type represents the type of the ListReader, which can be either [File] or [Raw].
type Type uint8

const (
	// File represents a ListReader that reads measurement lists from a file.
	File Type = iota
	// Raw represents a ListReader that reads measurement lists from raw bytes.
	Raw
)

// ListReader is an interface that defines the methods required for reading measurement lists.
type ListReader interface {
	// GetType returns the type of the ListReader, which can be either [File] or [Raw].
	GetType() Type
	// Open opens the measurement list for reading. It returns an error if the list cannot be opened.
	Open() error
	// IsReady checks if the ListReader is ready for reading. It returns true if the list is open and ready.
	IsReady() bool
	// Close closes the measurement list and releases any associated resources. It returns an error if closing fails.
	Close() error
	// ReadLine reads a single line from the measurement list. It returns the line as a string and any error encountered.
	ReadLine() (string, error)
	// Available returns the number of bytes available to read from the measurement list. It returns -1 if the list is not open or if an error occurs.
	Available() int64
	// SetPosition sets the read offset for the measurement list. It returns an error if the list is not open or if seeking fails.
	SetPosition(pos int64) error
}
