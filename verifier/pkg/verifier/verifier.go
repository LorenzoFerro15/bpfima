package verifier

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/pcr"
)

var (
	// ErrInvalidLeaves is returned when replaying the leaf list never reproduces the expected PCR digest.
	// This can occur if the leaf list is truncated, corrupted, or otherwise invalid.
	ErrInvalidLeaves = errors.New("invalid leaf list")
	// ErrInvalidTarget is returned when a target list entry is invalid, or when its leaf digest is not
	// found in the portion of the leaf list covered by the expected PCR digest.
	ErrInvalidTarget = errors.New("invalid target list")
)

// Verifier holds the state for attesting a target measurement list against the Merkle leaf list
// and a known-good expected TPM PCR digest.
//
// Each time a namespace event is recorded by bpfima:
//  1. The event's template hash extends the target list aggregate: list_agg = H(list_agg || templateHash).
//  2. The new list_agg becomes a leaf of the Merkle tree and is appended to the leaf list.
//  3. The leaf extends the Merkle root: merkle_root = H(merkle_root || leaf).
//  4. The Merkle root extends the physical PCR: pcr = H(pcr || merkle_root).
//
// Steps 1 and 3 are replayed by [measurement.List]; step 4 is replayed by the Verifier.
type Verifier struct {
	// target is the measurement list to be attested (e.g. container/namespace list).
	target *measurement.List
	// leaves is the Merkle leaf list; its aggregate is the Merkle root.
	leaves *measurement.List
	// expected is the PCR digest stored in the TPM at the time attestation is requested.
	expected []byte
	// pcr is a software-emulated TPM PCR that replays the extend sequence for verification.
	pcr *pcr.PCR
	// pcrMatched reports whether the replayed PCR has reached the expected digest.
	// Leaves past that point are not covered by the expected digest.
	pcrMatched bool
}

// New initializes a ready-to-attest Verifier.
//   - target: measurement list to be attested (e.g. container/namespace list)
//   - leaves: Merkle leaf list
//   - expected: PCR digest stored in the TPM at the time attestation is requested
func New(target, leaves *measurement.List, expected []byte) (*Verifier, error) {
	if target.HashAlgo() != leaves.HashAlgo() {
		return nil, fmt.Errorf("hash algorithm mismatch: target uses %s, leaves use %s",
			target.HashAlgo(), leaves.HashAlgo())
	}

	emulated, err := pcr.New(leaves.HashAlgo())
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR: %w", err)
	}

	v := &Verifier{target: target, leaves: leaves, pcr: emulated}
	if err = v.setExpected(expected); err != nil {
		return nil, err
	}
	return v, nil
}

// Reset restores the Verifier to its initial state so that attestation can be re-run
// against a new expected digest. Both lists are rewound and all aggregates are zeroed.
func (v *Verifier) Reset(expected []byte) error {
	if err := v.setExpected(expected); err != nil {
		return err
	}
	for _, list := range []*measurement.List{v.target, v.leaves} {
		if err := list.Reset(); err != nil {
			return fmt.Errorf("reset list: %w", err)
		}
	}
	v.pcr.Reset()
	v.pcrMatched = false
	return nil
}

// Attest performs full attestation of both the target and leaf lists.
//
// Target evaluation:
//  1. Each entry's template hash is validated and extended into a leaf digest.
//  2. Each leaf digest must be present in the leaf list, before the expected digest is reached.
//
// Leaf evaluation (continued after target, or from scratch if the target is empty):
//  1. The leaf list is replayed, extending the virtual PCR with the Merkle root after each leaf.
//  2. The virtual PCR must reach the expected digest (the TPM PCR value at attestation time).
//
// Returns an error wrapping [ErrInvalidTarget] or [ErrInvalidLeaves] on failure.
func (v *Verifier) Attest() error {
	if err := v.AttestTarget(); err != nil {
		return fmt.Errorf("failed to verify target: %w", err)
	}
	if err := v.AttestLeaves(); err != nil {
		return fmt.Errorf("failed to verify leaves: %w", err)
	}
	return nil
}

// AttestTarget validates each entry in the target list and confirms that each
// resulting leaf digest is present, in order, in the leaf list.
//
// Returns an error wrapping [ErrInvalidTarget] if any entry is invalid or its leaf is not found.
func (v *Verifier) AttestTarget() error {
	for {
		err := v.target.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
		if err = v.replayLeaves(v.isLeafFound); err != nil {
			return fmt.Errorf("%w: leaf digest %x not found: %w", ErrInvalidTarget, v.target.Aggregate(), err)
		}
	}
}

// AttestLeaves replays the remaining leaves until the virtual PCR reaches the expected digest.
// Leaves after that point are ignored, since they were appended after the TPM value was read.
//
// Returns an error wrapping [ErrInvalidLeaves] if the expected digest is never reached.
func (v *Verifier) AttestLeaves() error {
	return v.replayLeaves(func() bool { return v.pcrMatched })
}

// replayLeaves extends the virtual PCR with the Merkle root after each leaf until done reports true.
// It never reads past the leaf at which the virtual PCR reaches the expected digest.
func (v *Verifier) replayLeaves(done func() bool) error {
	for !done() {
		if v.pcrMatched {
			return fmt.Errorf("%w: expected digest %x already reached", ErrInvalidLeaves, v.expected)
		}

		err := v.leaves.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: computed digest %x does not match expected %x",
				ErrInvalidLeaves, v.pcr.Read(), v.expected)
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidLeaves, err)
		}

		v.pcr.Extend(v.leaves.Aggregate())
		v.pcrMatched = subtle.ConstantTimeCompare(v.pcr.Read(), v.expected) == 1
	}
	return nil
}

// isLeafFound reports whether the current target aggregate matches the current leaf.
func (v *Verifier) isLeafFound() bool {
	leaf := v.leaves.Current()
	return leaf != nil && subtle.ConstantTimeCompare(v.target.Aggregate(), leaf.TemplateHash()) == 1
}

// setExpected validates and stores the expected PCR digest.
func (v *Verifier) setExpected(expected []byte) error {
	if want := v.leaves.HashAlgo().Size(); len(expected) != want {
		return fmt.Errorf("invalid expected digest size: want %d bytes, got %d", want, len(expected))
	}
	v.expected = expected
	return nil
}
