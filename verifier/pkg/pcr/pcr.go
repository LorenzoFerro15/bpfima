package pcr

import (
	"crypto"
	//nolint:gosec // SHA1 is used by TPM PCRs
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

// PCR is a software representation of a Platform Configuration Register (PCR) of a Trusted Platform Module (TPM).
// It maintains an aggregate value that can be extended with new measurements.
type PCR struct {
	// aggregate is the current value of the PCR.
	aggregate []byte
	// hashAlgo is the hash algorithm used to compute the PCR value (i.e., PCR bank).
	hashAlgo crypto.Hash
}

// New creates a zeroed PCR for the specified hash algorithm (PCR bank).
// It returns an error if the hash algorithm is not supported by TPM PCRs.
func New(hashAlgo crypto.Hash) (*PCR, error) {
	if !IsValidAlgo(hashAlgo) {
		return nil, fmt.Errorf("invalid PCR hash algorithm: %s", hashAlgo)
	}

	return &PCR{
		aggregate: make([]byte, hashAlgo.Size()),
		hashAlgo:  hashAlgo,
	}, nil
}

// IsValidAlgo checks if the provided hash algorithm is supported by TPM PCRs.
func IsValidAlgo(hashAlgo crypto.Hash) bool {
	//nolint:exhaustive // TPM PCRs support a subset of hash algorithms
	switch hashAlgo {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

// Extend updates the PCR value as aggregate = H(aggregate || b).
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf Sec. 17.3 Extend of a PCR
func (p *PCR) Extend(b []byte) {
	hash := p.hashAlgo.New()
	hash.Write(p.aggregate)
	hash.Write(b)
	p.aggregate = hash.Sum(p.aggregate[:0])
}

// Read returns a copy of the current value of the PCR.
func (p *PCR) Read() []byte {
	return append([]byte(nil), p.aggregate...)
}

// HashAlgo returns the hash algorithm (PCR bank) used by the PCR.
func (p *PCR) HashAlgo() crypto.Hash {
	return p.hashAlgo
}

// Reset sets the PCR value to all zeros.
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf Sec. 17.1
func (p *PCR) Reset() {
	clear(p.aggregate)
}
