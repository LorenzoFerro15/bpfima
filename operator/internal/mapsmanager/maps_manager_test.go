package mapsmanager

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestPolicyWireLayout(t *testing.T) {
	policy := BpfimaPolicyConfig{MerkleHistoryMaxSize: 1000, MerkleHistoryScope: 1}
	if got := binary.Size(policy); got != 36 {
		t.Fatalf("policy encodes to %d bytes, want kernel ABI size 36", got)
	}
	if unsafe.Offsetof(policy.MerkleHistoryMaxSize) != 24 ||
		unsafe.Offsetof(policy.MerkleHistoryScope) != 28 || unsafe.Offsetof(policy.Reserved) != 32 {
		t.Fatal("policy fields do not match kernel ABI offsets")
	}
}
