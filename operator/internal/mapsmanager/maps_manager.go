// Package mapsmanager builds complete requests for the authoritative policy map transaction.
package mapsmanager

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/LorenzoFerro15/bpfima/api/v1alpha1"
)

const MaxPatternLen = 64

// Policy filter flags
const (
	PolicyFilterSystemCgroups = 1 << iota
	PolicyFilterProcSys
	PolicyFilterDev
	PolicyFilterReadonlyFiles
	PolicyFilterSmallFiles
	PolicyFilterNonExecutable
	PolicyFilterLibraries
	PolicyFilterTmpFiles
)

// Policy action flags
const (
	PolicyActionExtendTpm = 1 << iota
	PolicyActionLogSecurityfs
	PolicyActionLogKernel
	PolicyActionAlertSuspicious
	PolicyActionBlock
	PolicyActionTrackContainer
	PolicyActionBuildDeps
)

// Hook-specific flags
const (
	HookFlagEnabled = 1 << iota
	HookFlagTrackContainers
	HookFlagMeasureHash
)

// BPFPolicyConfig matches the kernel struct bpfima_policy_config
type BpfimaPolicyConfig struct {
	Enabled              uint8
	_                    [3]byte // padding
	FilterFlags          uint32
	ActionFlags          uint32
	MinFileSize          uint32
	MaxPathDepth         uint32
	LogLevel             uint32
	MerkleHistoryMaxSize uint32
	MerkleHistoryScope   uint8
	_                    [3]byte // padding
	Reserved             [1]uint32
}

// BPFPatternEntry matches the kernel struct bpfima_pattern_entry
type BPFPatternEntry struct {
	Pattern   [64]byte
	Enabled   uint8
	MatchType uint8
	Reserved  uint16
}

// BPFHookConfig matches the kernel struct bpfima_hook_config
type BPFHookConfig struct {
	Flags          uint32
	FilterOverride uint32
	ActionOverride uint32
	Reserved       [1]uint32
}

// Helper functions
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func computeFilterFlags(f v1alpha1.FilterConfig) uint32 {
	var flags uint32
	if f.SystemCgroups {
		flags |= PolicyFilterSystemCgroups
	}
	if f.ProcSys {
		flags |= PolicyFilterProcSys
	}
	if f.Dev {
		flags |= PolicyFilterDev
	}
	if f.ReadonlyFiles {
		flags |= PolicyFilterReadonlyFiles
	}
	if f.SmallFiles {
		flags |= PolicyFilterSmallFiles
	}
	if f.NonExecutable {
		flags |= PolicyFilterNonExecutable
	}
	if f.Libraries {
		flags |= PolicyFilterLibraries
	}
	if f.TmpFiles {
		flags |= PolicyFilterTmpFiles
	}
	return flags
}

func computeActionFlags(a v1alpha1.ActionConfig) uint32 {
	var flags uint32
	if a.ExtendTPM {
		flags |= PolicyActionExtendTpm
	}
	if a.LogSecurityFS {
		flags |= PolicyActionLogSecurityfs
	}
	if a.LogKernel {
		flags |= PolicyActionLogKernel
	}
	if a.AlertSuspicious {
		flags |= PolicyActionAlertSuspicious
	}
	if a.Block {
		flags |= PolicyActionBlock
	}
	if a.TrackContainer {
		flags |= PolicyActionTrackContainer
	}
	if a.BuildDeps {
		flags |= PolicyActionBuildDeps
	}
	return flags
}

func computeValue(policy v1alpha1.PolicyConfig, filters v1alpha1.FilterConfig, actions v1alpha1.ActionConfig) BpfimaPolicyConfig {
	return BpfimaPolicyConfig{
		Enabled:              boolToUint8(policy.Enabled),
		FilterFlags:          computeFilterFlags(filters),
		ActionFlags:          computeActionFlags(actions),
		MinFileSize:          uint32(policy.MinFileSize),
		MaxPathDepth:         uint32(policy.MaxPathDepth),
		LogLevel:             uint32(policy.LogLevel),
		MerkleHistoryMaxSize: 1000,
	}
}

// PolicySnapshot matches the complete C policy map snapshot (1252 bytes).
type PolicySnapshot struct {
	Config  BpfimaPolicyConfig
	Cgroups [8]BPFPatternEntry
	Paths   [8]BPFPatternEntry
	Hooks   [8]BPFHookConfig
}

// PolicyRequest is the versioned, little-endian SecurityFS transaction ABI.
type PolicyRequest struct {
	Version            uint32
	Reserved           uint32
	ExpectedGeneration uint64
	NamespaceID        [128]byte
	Snapshot           PolicySnapshot
	Padding            [4]byte
}

func buildPatterns(entries []v1alpha1.PatternEntry) ([8]BPFPatternEntry, error) {
	var result [8]BPFPatternEntry
	index := 0
	for _, entry := range entries {
		if !entry.Enabled {
			continue
		}
		if index == len(result) || entry.Pattern == "" || len(entry.Pattern) >= MaxPatternLen ||
			entry.MatchType < 0 || entry.MatchType > 3 {
			return result, fmt.Errorf("invalid or excessive policy pattern %q", entry.Pattern)
		}
		result[index].Enabled = 1
		result[index].MatchType = uint8(entry.MatchType)
		copy(result[index].Pattern[:], entry.Pattern)
		index++
	}
	return result, nil
}

func BuildPolicyRequest(policy *v1alpha1.Policy, namespace string, generation uint64) (*PolicyRequest, error) {
	if policy == nil || len(namespace) >= 128 {
		return nil, fmt.Errorf("invalid policy or namespace")
	}
	config := policy.Spec.Policy
	if policy.Spec.Actions.AlertSuspicious || policy.Spec.Actions.Block {
		return nil, fmt.Errorf("appraisal/alert actions are not implemented")
	}
	if config.MinFileSize < 0 || config.MinFileSize > math.MaxUint32 || config.MaxPathDepth < 0 ||
		config.MaxPathDepth > 32 || config.LogLevel < 0 || config.LogLevel > 3 ||
		!policy.Spec.Actions.ExtendTPM || !policy.Spec.Actions.LogSecurityFS {
		return nil, fmt.Errorf("policy values are invalid or disable the mandatory measurement transaction")
	}
	request := &PolicyRequest{Version: 2, ExpectedGeneration: generation}
	copy(request.NamespaceID[:], namespace)
	request.Snapshot.Config = computeValue(config, policy.Spec.Filters, policy.Spec.Actions)
	var err error
	request.Snapshot.Cgroups, err = buildPatterns(policy.Spec.CgroupPatterns)
	if err != nil {
		return nil, err
	}
	request.Snapshot.Paths, err = buildPatterns(policy.Spec.PathPatterns)
	if err != nil {
		return nil, err
	}
	hooks := policy.Spec.Hooks
	entries := []*v1alpha1.HookConfig{hooks.LSMBprmCheckSecurity, hooks.LSMFileOpen,
		hooks.LSMFilePostOpen, hooks.LSMMmapFile, hooks.LSMSocketConnect,
		hooks.LSMContainerEvents, hooks.KprobeFileOpen, hooks.LSMInodeSetattr}
	for i, config := range entries {
		// Omitted hooks use root defaults; never retain values from a previous policy.
		request.Snapshot.Hooks[i].Flags = HookFlagEnabled | HookFlagTrackContainers | HookFlagMeasureHash
		if i == 6 {
			request.Snapshot.Hooks[i].Flags = 0
		}
		if config == nil {
			continue
		}
		if config.FilterOverride != 0 || config.ActionOverride != 0 {
			return nil, fmt.Errorf("hook overrides are unsupported")
		}
		var flags uint32
		if config.Enabled {
			flags |= HookFlagEnabled
		}
		if config.TrackContainers {
			flags |= HookFlagTrackContainers
		}
		if config.MeasureHash {
			flags |= HookFlagMeasureHash
		}
		request.Snapshot.Hooks[i].Flags = flags
	}
	return request, nil
}

func WritePolicyRequest(writer io.Writer, request *PolicyRequest) error {
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, request); err != nil {
		return err
	}
	count, err := writer.Write(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("policy transaction: %w", err)
	}
	if count != buffer.Len() {
		return io.ErrShortWrite
	}
	return nil
}

// ApplyPolicy activates a complete policy only after the kernel's synchronous TPM commit.
func ApplyPolicy(policy *v1alpha1.Policy, path string) error {
	request, err := BuildPolicyRequest(policy, "", 0)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open policy transaction: %w", err)
	}
	defer file.Close()
	return WritePolicyRequest(file, request)
}
