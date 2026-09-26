package verifier_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/pcr"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/reader"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/verifier"
)

const (
	validContainerList   = "../../tests/valid_container_list"
	invalidContainerList = "../../tests/invalid_container_list"
	validLeafList        = "../../tests/valid_leaf_list"
	validExpected        = "53F2F6A0573A8076D5B1B714B3AB1F9E29AD7A1C3BC4407F0474D4BC14E8EDF3"
	invalidExpected      = "53F2F6A0573A8076D5B1B714B3AB1F9E29AD7A1C3BC4407F0474D4BC14E8EDF1"
)

func openList(
	t *testing.T,
	path string,
	newList func(measurement.LineReader, crypto.Hash) (*measurement.List, error),
) *measurement.List {
	t.Helper()
	r, err := reader.OpenFile(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	list, err := newList(r, crypto.SHA256)
	require.NoError(t, err)
	return list
}

func newFileVerifier(t *testing.T, targetPath, expectedHex string) *verifier.Verifier {
	t.Helper()
	expected, err := hex.DecodeString(expectedHex)
	require.NoError(t, err)
	v, err := verifier.New(
		openList(t, targetPath, measurement.NewHashedFileList),
		openList(t, validLeafList, measurement.NewLeafList),
		expected,
	)
	require.NoError(t, err)
	return v
}

func TestVerifier_Attest_success(t *testing.T) {
	t.Parallel()
	require.NoError(t, newFileVerifier(t, validContainerList, validExpected).Attest())
}

func TestVerifier_Attest_resetSuccess(t *testing.T) {
	t.Parallel()
	v := newFileVerifier(t, validContainerList, validExpected)
	require.NoError(t, v.Attest())

	expected, err := hex.DecodeString(validExpected)
	require.NoError(t, err)
	require.NoError(t, v.Reset(expected))
	require.NoError(t, v.Attest())
}

func TestVerifier_Attest_invalidLeaves(t *testing.T) {
	t.Parallel()
	err := newFileVerifier(t, validContainerList, invalidExpected).Attest()
	require.ErrorIs(t, err, verifier.ErrInvalidLeaves)
}

func TestVerifier_Attest_invalidTarget(t *testing.T) {
	t.Parallel()
	err := newFileVerifier(t, invalidContainerList, validExpected).Attest()
	require.ErrorIs(t, err, verifier.ErrInvalidTarget)
	require.ErrorIs(t, err, measurement.ErrInvalidEntry)
}

func TestNew_invalidExpectedSize(t *testing.T) {
	t.Parallel()
	_, err := verifier.New(
		openList(t, validContainerList, measurement.NewHashedFileList),
		openList(t, validLeafList, measurement.NewLeafList),
		[]byte{0x01},
	)
	require.Error(t, err)
}

// chain is a synthetic bpfima state where every leaf comes from the target list.
type chain struct {
	target    string
	leaves    string
	pcrDigest [][]byte // PCR digest after each leaf
}

func newChain(t *testing.T, entries int) chain {
	t.Helper()
	listAgg, err := pcr.New(crypto.SHA256)
	require.NoError(t, err)
	merkleRoot, err := pcr.New(crypto.SHA256)
	require.NoError(t, err)
	tpm, err := pcr.New(crypto.SHA256)
	require.NoError(t, err)

	var target, leaves strings.Builder
	var digests [][]byte
	for i := range entries {
		fileHash := hex.EncodeToString([]byte{byte(i)})
		filePath := fmt.Sprintf("/bin/file-%d", i)
		templateHash := sha256.Sum256([]byte(fileHash + measurement.Separator + filePath))
		fmt.Fprintf(&target, "%x bprm_check_security %s %s\n", templateHash, fileHash, filePath)

		listAgg.Extend(templateHash[:])
		fmt.Fprintf(&leaves, "%x\n", listAgg.Read())
		merkleRoot.Extend(listAgg.Read())
		tpm.Extend(merkleRoot.Read())
		digests = append(digests, tpm.Read())
	}
	return chain{target: target.String(), leaves: leaves.String(), pcrDigest: digests}
}

func (c chain) verifier(t *testing.T, expected []byte) *verifier.Verifier {
	t.Helper()
	target, err := measurement.NewHashedFileList(reader.FromBytes([]byte(c.target)), crypto.SHA256)
	require.NoError(t, err)
	leaves, err := measurement.NewLeafList(reader.FromBytes([]byte(c.leaves)), crypto.SHA256)
	require.NoError(t, err)
	v, err := verifier.New(target, leaves, expected)
	require.NoError(t, err)
	return v
}

func TestVerifier_Attest_lastLeafAtExpectedDigest(t *testing.T) {
	t.Parallel()
	c := newChain(t, 3)
	require.NoError(t, c.verifier(t, c.pcrDigest[2]).Attest())
}

func TestVerifier_Attest_targetNotCoveredByExpectedDigest(t *testing.T) {
	t.Parallel()
	c := newChain(t, 3)
	err := c.verifier(t, c.pcrDigest[1]).Attest()
	require.ErrorIs(t, err, verifier.ErrInvalidTarget)
}

func TestVerifier_AttestLeaves_leavesPastExpectedDigest(t *testing.T) {
	t.Parallel()
	c := newChain(t, 3)
	require.NoError(t, c.verifier(t, c.pcrDigest[1]).AttestLeaves())
}
