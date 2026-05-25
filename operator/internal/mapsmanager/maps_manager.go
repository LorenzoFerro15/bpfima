package mapsmanager

import (
	"fmt"
	"path/filepath"

	"github.com/LorenzoFerro15/bpfima/api/v1alpha1"
	"github.com/cilium/ebpf"
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
	Enabled      uint8
	_            [3]byte // padding
	FilterFlags  uint32
	ActionFlags  uint32
	MinFileSize  uint32
	MaxPathDepth uint32
	LogLevel     uint32
	Reserved     [2]uint32
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

// Open the maps given the directory
func OpenMaps(baseDir string, names []string) (map[string]*ebpf.Map, error) {
	result := make(map[string]*ebpf.Map, len(names))

	for _, name := range names {
		fullPath := filepath.Join(baseDir, name)
		m, err := ebpf.LoadPinnedMap(fullPath, nil)
		if err != nil {
			for _, opened := range result {
				opened.Close()
			}
			return nil, err
		}
		result[name] = m
	}

	return result, nil
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

// UpdatePolicy updates the BPF policy map with the given configuration
func UpdatePolicy(policyMap *ebpf.Map, policy v1alpha1.PolicyConfig, filters v1alpha1.FilterConfig, actions v1alpha1.ActionConfig) error {
	if policyMap == nil {
		return fmt.Errorf("Policy map is nil")
	}

	key := uint32(0) // Global policy key

	value := BpfimaPolicyConfig{
		Enabled:      boolToUint8(policy.Enabled),
		FilterFlags:  computeFilterFlags(filters),
		ActionFlags:  computeActionFlags(actions),
		MinFileSize:  uint32(policy.MinFileSize),
		MaxPathDepth: uint32(policy.MaxPathDepth),
		LogLevel:     uint32(policy.LogLevel),
	}

	return policyMap.Put(key, value)
}

// UpdatePatterns updates the BPF cgroup/path patterns map
func UpdatePatterns(patternsMap *ebpf.Map, patterns []v1alpha1.PatternEntry) error {
	if patternsMap == nil {
		return fmt.Errorf("Cgroup/path map is nil")
	}

	// Get the max number of entries storable in the map
	info, err := patternsMap.Info()
	if err != nil {
		return fmt.Errorf("Failed to get cgroup/path map info: %w", err)
	}

	maxEntries := int(info.MaxEntries)
	i := 0

	// Write current enabled patterns only
	for _, patternEntry := range patterns {
		if patternEntry.Pattern == "" || !patternEntry.Enabled {
			continue
		}

		// This should never occur due to CR validation, just safe-check
		if i >= maxEntries {
			return fmt.Errorf("Too many enabled patterns: %d (max %d)", i+1, maxEntries)
		}

		entry := BPFPatternEntry{
			Enabled:   1,
			MatchType: uint8(patternEntry.MatchType),
		}

		// Copy pattern into byte array (truncate if too long)
		patternLen := min(len(patternEntry.Pattern), MaxPatternLen-1)
		copy(entry.Pattern[:], patternEntry.Pattern[:patternLen])

		key := uint32(i)
		if err := patternsMap.Put(key, entry); err != nil {
			return fmt.Errorf("Failed to update cgroup/path pattern %d: %w", i, err)
		}
		i++
	}

	// Clean older entries
	zero := BPFPatternEntry{}
	for ; i < maxEntries; i++ {
		key := uint32(i)
		if err := patternsMap.Put(key, zero); err != nil {
			return fmt.Errorf("Failed to clear cgroup/path pattern %d: %w", i, err)
		}
	}

	return nil
}

// UpdateHookConfig updates the BPF hooks map
func UpdateHookConfig(hooksMap *ebpf.Map, hooks v1alpha1.HookConfigs) error {
	if hooksMap == nil {
		return fmt.Errorf("Hooks map is nil")
	}

	type hookEntry struct {
		index uint32
		cfg   *v1alpha1.HookConfig
	}

	entries := []hookEntry{
		{index: 0, cfg: hooks.LSMBprmCheckSecurity},
		{index: 1, cfg: hooks.LSMFileOpen},
		{index: 2, cfg: hooks.LSMFilePostOpen},
		{index: 3, cfg: hooks.LSMMmapFile},
		{index: 4, cfg: hooks.LSMSocketConnect},
		{index: 5, cfg: hooks.LSMContainerEvents},
		{index: 6, cfg: hooks.KprobeFileOpen},
	}

	for _, entry := range entries {
		if entry.cfg == nil {
			continue
		}

		// Compute the flags
		var flags uint32
		if entry.cfg.Enabled {
			flags |= HookFlagEnabled
		}
		if entry.cfg.TrackContainers {
			flags |= HookFlagTrackContainers
		}
		if entry.cfg.MeasureHash {
			flags |= HookFlagMeasureHash
		}

		bpfHook := BPFHookConfig{
			Flags:          flags,
			FilterOverride: uint32(entry.cfg.FilterOverride),
			ActionOverride: uint32(entry.cfg.ActionOverride),
		}

		if err := hooksMap.Put(entry.index, bpfHook); err != nil {
			return fmt.Errorf("Failed to update hook %d: %w", entry.index, err)
		}
	}

	return nil
}
