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

func TestHashedFiles(t *testing.T) {
	t.Parallel()
	raw := validHashedFileLine + "\n" +
		hashedFileLine(measurement.EventSocketConnect, "10.0.0.2:41234-10.0.0.1:443", "/usr/bin/curl:sh") + "\n"

	entries, err := measurement.HashedFiles(reader.FromBytes([]byte(raw)), crypto.SHA256)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "/usr/local/bin/docker-entrypoint.sh", entries[0].Path())
	require.Equal(t, measurement.EventSocketConnect, entries[1].Event())

	empty, err := measurement.HashedFiles(reader.FromBytes(nil), crypto.SHA256)
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestHashedFiles_invalid(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"tampered":  validHashedFileLine + "x\n",
		"malformed": "5473b4818c91d825 bprm_check_security\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := measurement.HashedFiles(reader.FromBytes([]byte(raw)), crypto.SHA256)
			require.Error(t, err)
		})
	}
}

func TestMarshalHashedFiles(t *testing.T) {
	t.Parallel()
	entries := []*measurement.HashedFile{
		measurement.NewFileMeasurement(crypto.SHA256, measurement.EventBprmCheckSecurity,
			"aa01", "/usr/bin/bash", "containerd-shim", "systemd"),
		measurement.NewHashedFile(crypto.SHA256, measurement.EventInodeSetattr, "mode=0755", ""),
	}

	raw := measurement.MarshalHashedFiles(entries...)
	parsed, err := measurement.HashedFiles(reader.FromBytes(raw), crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, entries, parsed)
	require.Empty(t, measurement.MarshalHashedFiles())
}
