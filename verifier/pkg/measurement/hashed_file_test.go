package measurement_test

import (
	"crypto"
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
