package reader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileReader_ReadLine_EOFWithoutNewline(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "measurements.txt")

	// Write content without a trailing newline on the last line
	content := "line1: measurement_data_1\nline2: measurement_data_2"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	fr := NewFileReader(filePath)
	if err := fr.Open(); err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer fr.Close()

	line1, err := fr.ReadLine()
	if err != nil {
		t.Fatalf("expected first line read success, got: %v", err)
	}
	if line1 != "line1: measurement_data_1" {
		t.Errorf("expected 'line1: measurement_data_1', got '%s'", line1)
	}

	line2, err := fr.ReadLine()
	if err != nil {
		t.Fatalf("expected second line read success despite EOF, got: %v", err)
	}
	if line2 != "line2: measurement_data_2" {
		t.Errorf("expected 'line2: measurement_data_2', got '%s'", line2)
	}
}
