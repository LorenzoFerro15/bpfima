package measurement_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
)

const validHashedFileLine = "5473b4818c91d825ea5bc42b52271c805b5f6ee623630a3f05218b11d6666d2b bprm_check_security " +
	"2eb4659fdde6d415b0d5611500b9ab611e34bbcdeca079b29f1a5270d8ecec35 " +
	"/usr/local/bin/docker-entrypoint.sh:containerd-shim:systemd:swapper/0"

func TestParseHashedFile(t *testing.T) {
	t.Parallel()
	hashedFile, err := measurement.ParseHashedFile(validHashedFileLine)
	require.NoError(t, err)
	require.Equal(t, "bprm_check_security", hashedFile.Event())
	require.Equal(t, "2eb4659fdde6d415b0d5611500b9ab611e34bbcdeca079b29f1a5270d8ecec35", hashedFile.FileHash())
	require.Equal(t, "/usr/local/bin/docker-entrypoint.sh:containerd-shim:systemd:swapper/0", hashedFile.FilePath())
	require.NoError(t, hashedFile.Validate(crypto.SHA256))
}

func TestParseHashedFile_malformed(t *testing.T) {
	t.Parallel()
	for name, line := range map[string]string{
		"empty":          "",
		"missing fields": "5473b4818c91d825 bprm_check_security",
		"bad hex":        "zz bprm_check_security 2eb4 /bin/sh",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := measurement.ParseHashedFile(line)
			require.ErrorIs(t, err, measurement.ErrMalformedEntry)
		})
	}
}

func TestHashedFile_Validate_tampered(t *testing.T) {
	t.Parallel()
	hashedFile, err := measurement.ParseHashedFile(validHashedFileLine + "x")
	require.NoError(t, err)
	require.ErrorIs(t, hashedFile.Validate(crypto.SHA256), measurement.ErrInvalidEntry)
}

// hashedFileLine returns a measurement line of the event, with the template
// hash computed as the kernel does, without dependencies when deps is empty.
func hashedFileLine(event, data, deps string) string {
	input := data
	if deps != "" {
		input += measurement.Separator + deps
	}
	sum := sha256.Sum256([]byte(input))
	line := hex.EncodeToString(sum[:]) + " " + event + " " + data
	if deps != "" {
		line += " " + deps
	}
	return line
}

func TestHashedFile_PathAndAncestry(t *testing.T) {
	t.Parallel()
	hashedFile, err := measurement.ParseHashedFile(validHashedFileLine)
	require.NoError(t, err)
	require.True(t, hashedFile.IsFile())
	require.Equal(t, "/usr/local/bin/docker-entrypoint.sh", hashedFile.Path())
	require.Equal(t, []string{"containerd-shim", "systemd", "swapper/0"}, hashedFile.Ancestry())
}

func TestHashedFile_withoutAncestry(t *testing.T) {
	t.Parallel()
	hashedFile, err := measurement.ParseHashedFile(hashedFileLine(measurement.EventMmapFile, "aa01", "/lib/libc.so.6"))
	require.NoError(t, err)
	require.NoError(t, hashedFile.Validate(crypto.SHA256))
	require.Equal(t, "/lib/libc.so.6", hashedFile.Path())
	require.Nil(t, hashedFile.Ancestry())
}

func TestHashedFile_nonFileEvents(t *testing.T) {
	t.Parallel()
	for name, line := range map[string]string{
		"socket connection": hashedFileLine(measurement.EventSocketConnect,
			"10.0.0.2:41234-10.0.0.1:443", "/usr/bin/curl:sh:containerd-shim"),
		// measurements without dependencies have no file path.
		"attribute change": hashedFileLine(measurement.EventInodeSetattr, "mode=0755", ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hashedFile, err := measurement.ParseHashedFile(line)
			require.NoError(t, err)
			require.NoError(t, hashedFile.Validate(crypto.SHA256))
			require.False(t, hashedFile.IsFile())
		})
	}
}

func TestNewHashedFile(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct{ event, data, deps string }{
		"file":                 {measurement.EventBprmCheckSecurity, "aa01", "/usr/bin/bash:containerd-shim"},
		"without dependencies": {measurement.EventInodeSetattr, "mode=0755", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			created := measurement.NewHashedFile(crypto.SHA256, tt.event, tt.data, tt.deps)
			require.Equal(t, hashedFileLine(tt.event, tt.data, tt.deps), created.String())

			parsed, err := measurement.ParseHashedFile(created.String())
			require.NoError(t, err)
			require.Equal(t, created, parsed)
			require.NoError(t, parsed.Validate(crypto.SHA256))
		})
	}
}

func TestNewFileMeasurement(t *testing.T) {
	t.Parallel()
	m := measurement.NewFileMeasurement(crypto.SHA256, measurement.EventMmapFile,
		"aa01", "/lib/libc.so.6", "bash", "sshd")
	require.Equal(t, "/lib/libc.so.6:bash:sshd", m.FilePath())
	require.Equal(t, "/lib/libc.so.6", m.Path())
	require.Equal(t, []string{"bash", "sshd"}, m.Ancestry())
	require.NoError(t, m.Validate(crypto.SHA256))

	orphan := measurement.NewFileMeasurement(crypto.SHA256, measurement.EventMmapFile, "aa01", "/lib/x.so")
	require.Nil(t, orphan.Ancestry())
}
