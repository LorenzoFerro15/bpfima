package measurement_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
)

const validLeafDigest = "90bfb641227ae78c77736275fc5e5467cef7718265d57b778bcbb89d85b67e83"

func TestParseLeaf(t *testing.T) {
	t.Parallel()
	for name, line := range map[string]string{
		"plain":     validLeafDigest,
		"aggregate": validLeafDigest + " [AGGREGATE:3 entries]",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			leaf, err := measurement.ParseLeaf(line)
			require.NoError(t, err)
			require.NoError(t, leaf.Validate(crypto.SHA256))
		})
	}
}

func TestParseLeaf_malformed(t *testing.T) {
	t.Parallel()
	_, err := measurement.ParseLeaf("")
	require.ErrorIs(t, err, measurement.ErrMalformedEntry)
	_, err = measurement.ParseLeaf("not-hex")
	require.ErrorIs(t, err, measurement.ErrMalformedEntry)
}

func TestLeaf_Validate_wrongSize(t *testing.T) {
	t.Parallel()
	leaf, err := measurement.ParseLeaf(validLeafDigest)
	require.NoError(t, err)
	require.ErrorIs(t, leaf.Validate(crypto.SHA384), measurement.ErrInvalidEntry)
}
