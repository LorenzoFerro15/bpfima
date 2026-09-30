package measurement_test

import (
	"crypto"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/pcr"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/reader"
)

func TestList_NextAndReset(t *testing.T) {
	t.Parallel()
	list, err := measurement.NewHashedFileList(reader.FromBytes([]byte(validHashedFileLine+"\n")), crypto.SHA256)
	require.NoError(t, err)

	require.NoError(t, list.Next())
	want, err := pcr.New(crypto.SHA256)
	require.NoError(t, err)
	want.Extend(list.Current().TemplateHash())
	require.Equal(t, want.Read(), list.Aggregate())
	require.ErrorIs(t, list.Next(), io.EOF)

	require.NoError(t, list.Reset())
	require.Nil(t, list.Current())
	require.NoError(t, list.Next())
	require.Equal(t, want.Read(), list.Aggregate())
}

func TestList_Next_invalidEntry(t *testing.T) {
	t.Parallel()
	list, err := measurement.NewHashedFileList(reader.FromBytes([]byte(validHashedFileLine+"x\n")), crypto.SHA256)
	require.NoError(t, err)
	require.ErrorIs(t, list.Next(), measurement.ErrInvalidEntry)
}
