package measurement_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"bpfima/pkg/measurement"
)

func TestHashedFile_IsValid(t *testing.T) {
	t.Parallel()
	hashedFile := measurement.HashedFile{}
	err := hashedFile.Parse(
		"5473b4818c91d825ea5bc42b52271c805b5f6ee623630a3f05218b11d6666d2b bprm_check_security 2eb4659fdde6d415b0d5611500b9ab611e34bbcdeca079b29f1a5270d8ecec35 /usr/local/bin/docker-entrypoint.sh:containerd-shim:systemd:swapper/0",
	)
	require.NoError(t, err)
	isValid := hashedFile.IsValid(crypto.SHA256)
	require.True(t, isValid)
}
