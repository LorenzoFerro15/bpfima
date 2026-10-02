package mapsmanager

import (
	"encoding/binary"
	"testing"

	"github.com/LorenzoFerro15/bpfima/api/v1alpha1"
)

// The map values must have the size and layout of the kernel structs, or the
// map updates are rejected
func TestStructSizes(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"bpfima_policy_config", binary.Size(BpfimaPolicyConfig{}), 36},
		{"bpfima_pattern_entry", binary.Size(BPFPatternEntry{}), 68},
		{"bpfima_hook_config", binary.Size(BPFHookConfig{}), 16},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %d bytes, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestPolicyConfigLayout(t *testing.T) {
	cfg := BpfimaPolicyConfig{
		Enabled:              1,
		FilterFlags:          2,
		ActionFlags:          3,
		MinFileSize:          4,
		MaxPathDepth:         5,
		LogLevel:             6,
		MerkleHistoryMaxSize: 7,
		MerkleHistoryScope:   8,
		Reserved:             [1]uint32{9},
	}
	buf, err := binary.Append(nil, binary.NativeEndian, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// offsets of the fields of the kernel struct bpfima_policy_config
	if buf[0] != 1 {
		t.Errorf("enabled at offset 0: got %d, want 1", buf[0])
	}
	for offset, want := range map[int]uint32{4: 2, 8: 3, 12: 4, 16: 5, 20: 6, 24: 7, 32: 9} {
		if got := binary.NativeEndian.Uint32(buf[offset:]); got != want {
			t.Errorf("uint32 at offset %d: got %d, want %d", offset, got, want)
		}
	}
	if buf[28] != 8 {
		t.Errorf("merkle_history_scope at offset 28: got %d, want 8", buf[28])
	}
}

func TestComputeValueKeepsMerkleHistoryUnset(t *testing.T) {
	value := computeValue(
		v1alpha1.PolicyConfig{Enabled: true, LogLevel: 2, MaxPathDepth: 32},
		v1alpha1.FilterConfig{},
		v1alpha1.ActionConfig{ExtendTPM: true},
	)
	if value.MerkleHistoryMaxSize != 0 || value.MerkleHistoryScope != 0 {
		t.Errorf("got merkle history %d/%d, want 0/0", value.MerkleHistoryMaxSize, value.MerkleHistoryScope)
	}
}
