package attestation

import (
	"crypto"
	//nolint:gosec // SHA1 is used by TPM PCRs
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"fmt"
)

// PCR is a representation of a Platform Configuration Register (PCR) of a Trusted Platform Module (TPM).
// It maintains an aggregate value that can be extended with new measurements.
type PCR struct {
	// aggregate is the current value of the PCR
	aggregate []byte
	// hashAlgo is the hash algorithm used to compute the PCR value (i.e., PCR bank)
	hashAlgo crypto.Hash
}

// NewPCR creates a new PCR instance with the specified hash algorithm.
// It returns an error if the provided hash algorithm is not supported by TPM PCRs.
func NewPCR(hashAlgo crypto.Hash) (*PCR, error) {
	if !isValidPCRAlgo(hashAlgo) {
		return nil, fmt.Errorf("invalid PCR hash algorithm: %s", hashAlgo.String())
	}

	return &PCR{
		aggregate: make([]byte, hashAlgo.Size()),
		hashAlgo:  hashAlgo,
	}, nil
}

// Extend updates the PCR value by hashing the current PCR value with the provided byte slice.
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf Sec. 17.3 Extend of a PCR
func (p *PCR) Extend(b []byte) {
	hash := p.hashAlgo.New()
	hash.Write(p.aggregate)
	hash.Write(b)
	copy(p.aggregate, hash.Sum(nil))
}

// Read returns the current value of the PCR.
func (p *PCR) Read() []byte {
	return p.aggregate
}

// GetHashAlgo returns the hash algorithm used by the PCR.
func (p *PCR) GetHashAlgo() crypto.Hash {
	return p.hashAlgo
}

// Reset sets the PCR value to all zeros.
func (p *PCR) Reset() {
	for i := range p.aggregate {
		p.aggregate[i] = 0
	}
}

// isValidPCRAlgo checks if the provided hash algorithm is supported by TPM PCRs.
func isValidPCRAlgo(hashAlgo crypto.Hash) bool {
	//nolint:exhaustive // TPM PCRs support a subset of hash algorithms
	switch hashAlgo {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}
