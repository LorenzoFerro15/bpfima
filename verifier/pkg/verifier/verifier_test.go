package verifier_test

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/reader"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/verifier"
)

func TestVerifier_Verify_container_root_success(t *testing.T) {
	t.Parallel()
	targetListReader := reader.NewFileReader("../../tests/valid_container_list")
	err := targetListReader.Open()
	require.NoError(t, err)
	target, err := measurement.NewHashedFileMeasurementList(targetListReader, crypto.SHA256)
	require.NoError(t, err)

	rootListReader := reader.NewFileReader("../../tests/valid_root")
	err = rootListReader.Open()
	require.NoError(t, err)

	expected, err := hex.DecodeString("53F2F6A0573A8076D5B1B714B3AB1F9E29AD7A1C3BC4407F0474D4BC14E8EDF3")
	require.NoError(t, err)

	root, err := measurement.NewRootMeasurementList(rootListReader, crypto.SHA256)
	require.NoError(t, err)

	v, err := verifier.New(target, root, expected)
	require.NoError(t, err)

	err = v.Attest()
	require.NoError(t, err)
}

func TestVerifier_Verify_container_root_success_reset_success(t *testing.T) {
	t.Parallel()
	targetListReader := reader.NewFileReader("../../tests/valid_container_list")
	err := targetListReader.Open()
	require.NoError(t, err)
	target, err := measurement.NewHashedFileMeasurementList(targetListReader, crypto.SHA256)
	require.NoError(t, err)

	rootListReader := reader.NewFileReader("../../tests/valid_root")
	err = rootListReader.Open()
	require.NoError(t, err)

	expected, err := hex.DecodeString("53F2F6A0573A8076D5B1B714B3AB1F9E29AD7A1C3BC4407F0474D4BC14E8EDF3")
	require.NoError(t, err)

	root, err := measurement.NewRootMeasurementList(rootListReader, crypto.SHA256)
	require.NoError(t, err)

	v, err := verifier.New(target, root, expected)
	require.NoError(t, err)

	err = v.Attest()
	require.NoError(t, err)

	err = v.Reset(expected)
	require.NoError(t, err)

	err = v.Attest()
	require.NoError(t, err)
}

func TestVerifier_Verify_container_root_invalid_root(t *testing.T) {
	t.Parallel()
	targetListReader := reader.NewFileReader("../../tests/valid_container_list")
	err := targetListReader.Open()
	require.NoError(t, err)
	target, err := measurement.NewHashedFileMeasurementList(targetListReader, crypto.SHA256)
	require.NoError(t, err)

	rootListReader := reader.NewFileReader("../../tests/valid_root")
	err = rootListReader.Open()
	require.NoError(t, err)

	expected, err := hex.DecodeString("53F2F6A0573A8076D5B1B714B3AB1F9E29AD7A1C3BC4407F0474D4BC14E8EDF1")
	require.NoError(t, err)

	root, err := measurement.NewRootMeasurementList(rootListReader, crypto.SHA256)
	require.NoError(t, err)

	v, err := verifier.New(target, root, expected)
	require.NoError(t, err)

	err = v.Attest()
	require.Error(t, err)
	require.ErrorIs(t, err, verifier.ErrInvalidRoot)
}
