package pcr_test

import (
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/pcr"
)

func TestNew_invalidAlgo(t *testing.T) {
	t.Parallel()
	_, err := pcr.New(crypto.MD5)
	require.Error(t, err)
}

func TestPCR_ExtendAndReset(t *testing.T) {
	t.Parallel()
	p, err := pcr.New(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, make([]byte, sha256.Size), p.Read())

	p.Extend([]byte("measurement"))
	want := sha256.Sum256(append(make([]byte, sha256.Size), []byte("measurement")...))
	require.Equal(t, want[:], p.Read())

	p.Reset()
	require.Equal(t, make([]byte, sha256.Size), p.Read())
}
