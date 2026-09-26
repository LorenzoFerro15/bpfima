package reader_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/reader"
)

func readAll(t *testing.T, r *reader.Reader) []string {
	t.Helper()
	var lines []string
	for {
		line, err := r.ReadLine()
		if errors.Is(err, io.EOF) {
			return lines
		}
		require.NoError(t, err)
		lines = append(lines, line)
	}
}

func TestReader_ReadLine(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		raw  string
		want []string
	}{
		"empty":                {raw: "", want: nil},
		"terminated":           {raw: "a\nb\n", want: []string{"a", "b"}},
		"unterminated last":    {raw: "a\nb", want: []string{"a", "b"}},
		"blank line preserved": {raw: "a\n\nb\n", want: []string{"a", "", "b"}},
		"crlf":                 {raw: "a\r\nb\r\n", want: []string{"a", "b"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, readAll(t, reader.FromBytes([]byte(tc.raw))))
		})
	}
}

func TestReader_Rewind(t *testing.T) {
	t.Parallel()
	r := reader.FromBytes([]byte("a\nb\n"))
	require.Equal(t, []string{"a", "b"}, readAll(t, r))
	require.NoError(t, r.Rewind())
	require.Equal(t, []string{"a", "b"}, readAll(t, r))
}

func TestOpenFile_unterminatedLastLine(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "measurements")
	require.NoError(t, os.WriteFile(path, []byte("line1\nline2"), 0o600))
	r, err := reader.OpenFile(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	require.Equal(t, []string{"line1", "line2"}, readAll(t, r))
}

func TestOpenFile(t *testing.T) {
	t.Parallel()
	r, err := reader.OpenFile("../../tests/valid_leaf_list")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	require.Len(t, readAll(t, r), 95)
}
