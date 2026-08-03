package verifier

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/LorenzoFerro15/bpfima/verifier/pkg/attestation"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/measurement"
	"github.com/LorenzoFerro15/bpfima/verifier/pkg/reader"
)

var (
	// ErrInvalidRoot is returned when the Root list does not contain the expected digest.
	// This can occur if the Root list is truncated, corrupted, or otherwise invalid.
	// It can also occur if the Target list contains entries that are not present in the Root list.
	ErrInvalidRoot = errors.New("invalid root list")
	// ErrInvalidTarget is returned when the Target list contains entries that are not present in the Root list.
	// This can occur if the Target list is truncated, corrupted, or otherwise invalid.
	// It can also occur if the Root list does not contain the expected digest.
	ErrInvalidTarget = errors.New("invalid target list")
)

// ValidateLeafFunc checks whether the current Target aggregate matches the current Root list entry.
type ValidateLeafFunc func() bool

// Verifier holds the state for attesting a target measurement list against a root list
// and a known-good expected TPM PCR digest.
type Verifier struct {
	// TargetList is the measurement list to be attested (e.g. container/namespace list).
	TargetList *measurement.List
	// RootList is the Merkle root history list.
	RootList *measurement.List
	// expected is the PCR digest stored in the TPM at the time attestation is requested.
	expected []byte
	// pcr is a software-emulated TPM PCR that replays the extend sequence for verification.
	pcr attestation.PCR
	// validRoot indicates whether the Root list has been successfully validated against the expected digest.
	validRoot bool
}

// New initializes a ready-to-attest Verifier.
//   - targetList: measurement list to be attested (e.g. container/namespace list)
//   - rootList: Merkle root history list
//   - expected: PCR digest stored in the TPM at the time attestation is requested
func New(targetList *measurement.List, rootList *measurement.List, expected []byte) (*Verifier, error) {
	if targetList.PCR.GetHashAlgo() != rootList.PCR.GetHashAlgo() {
		return nil, fmt.Errorf("hash algorithm mismatch: target uses %s, root uses %s",
			targetList.PCR.GetHashAlgo(), rootList.PCR.GetHashAlgo())
	}

	wantSize := rootList.PCR.GetHashAlgo().Size()
	if len(expected) != wantSize {
		return nil, fmt.Errorf("invalid expected digest size: want %d bytes, got %d", wantSize, len(expected))
	}

	if !targetList.Reader.IsReady() {
		return nil, errors.New("target list not open")
	}
	if !rootList.Reader.IsReady() {
		return nil, errors.New("root list not open")
	}

	pcr, err := attestation.NewPCR(rootList.PCR.GetHashAlgo())
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR: %w", err)
	}

	return &Verifier{
		TargetList: targetList,
		RootList:   rootList,
		pcr:        *pcr,
		expected:   expected,
	}, nil
}

// Reset restores the Verifier to its initial state so that attestation can be re-run.
// This resets both list readers to the start and zeroes all PCR aggregates.
// The expected digest must be updated to a new value to continue attestation.
func (v *Verifier) Reset(expected []byte) error {
	if len(expected) != v.RootList.PCR.GetHashAlgo().Size() {
		return fmt.Errorf("invalid expected digest size: want %d bytes, got %d",
			v.RootList.PCR.GetHashAlgo().Size(), len(expected))
	}
	for _, lr := range []reader.ListReader{v.TargetList.Reader, v.RootList.Reader} {
		if err := lr.SetPosition(0); err != nil {
			return fmt.Errorf("reset list: %w", err)
		}
	}
	// Reset virtual PCR to all-zeros per TCG spec:
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf Sec. 17.1
	v.pcr.Reset()
	v.TargetList.ResetAggregate()
	v.RootList.ResetAggregate()
	v.validRoot = false
	v.expected = expected
	return nil
}

// isLeafValid reports whether the current Target aggregate matches the current Root list entry.
func (v *Verifier) isLeafValid() bool {
	return subtle.ConstantTimeCompare(v.TargetList.PCR.Read(), v.RootList.Entry.GetTemplateHash()) == 1
}

// isRootValid reports whether the virtual PCR matches the expected digest.
func (v *Verifier) isRootValid() bool {
	return subtle.ConstantTimeCompare(v.pcr.Read(), v.expected) == 1
}

// AttestTarget validates each entry in the Target list and confirms that each
// computed leaf digest is present in the Root list.
//
//  1. Each entry's TemplateHash is recomputed and validated.
//  2. The valid TemplateHash is extended into the Target aggregate (leaf digest).
//  3. The leaf digest is looked up in the Root list via AttestRoot.
//
// Returns ErrInvalidTarget if any entry is invalid or absent from the Root list.
func (v *Verifier) AttestTarget() error {
	for v.TargetList.Reader.Available() > 0 {
		if err := v.TargetList.ParseEntry(); err != nil {
			return fmt.Errorf("target parse error: %w", err)
		}
		v.TargetList.PCR.Extend(v.TargetList.Entry.GetTemplateHash())
		if err := v.AttestRoot(v.isLeafValid); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
	}
	return nil
}

// AttestRoot scans the Root list, extending the virtual PCR for each entry.
//
// If isLeafValid is non-nil, scanning stops as soon as the current Target aggregate
// is found in the Root list (early-exit path during target attestation).
//
// If isLeafValid is nil, scanning continues to EOF and the final virtual PCR is
// compared against Expected to confirm overall Root list integrity.
//
// Returns ErrInvalidRoot if no match is found or the final virtual PCR does not equal Expected.
func (v *Verifier) AttestRoot(isLeafValid ValidateLeafFunc) error {
	for v.RootList.Reader.Available() > 0 {
		if err := v.RootList.ParseEntry(); err != nil {
			return fmt.Errorf("root parse error: %w", err)
		}
		v.RootList.PCR.Extend(v.RootList.Entry.GetTemplateHash())
		// Each time a namespace event is detected:
		//  1. The event's TemplateHash extends the target list aggregate: list_agg = hash(list_agg || templateHash)
		//  2. The new list_agg becomes a leaf in the Root Merkle tree and is appended to the root list.
		//  3. The leaf extends the root aggregate: root_agg = hash(root_agg || leaf)
		//  4. The root aggregate extends the physical PCR: pcr_new = hash(pcr_old || root_agg)
		//
		// This method performs step 4 using the current root aggregate.
		v.pcr.Extend(v.RootList.PCR.Read())

		switch {
		case isLeafValid != nil && isLeafValid():
			return nil
		case v.isRootValid():
			v.validRoot = true
			if isLeafValid == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: computed digest %x does not match expected %x",
		ErrInvalidRoot, v.RootList.PCR.Read(), v.expected)
}

// Attest performs full attestation of both the Target and Root measurement lists.
//
// Target evaluation:
//  1. Each entry's TemplateHash is validated and extended into a leaf digest.
//  2. Each leaf digest must be present in the Root list.
//
// Root evaluation (continued after Target, or from scratch if Target is empty):
//  1. The Root list is scanned to EOF, extending the virtual PCR for each entry.
//  2. The final virtual PCR must equal Expected (the TPM PCR value at attestation time).
//
// Returns an error wrapping [ErrInvalidTarget] or [ErrInvalidRoot] on failure.
func (v *Verifier) Attest() error {
	if err := v.AttestTarget(); err != nil {
		return fmt.Errorf("failed to verify target: %w", err)
	}
	if !v.validRoot {
		if err := v.AttestRoot(nil); err != nil {
			return fmt.Errorf("failed to verify root: %w", err)
		}
	}
	return nil
}
