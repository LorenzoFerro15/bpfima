package policyselector

import (
	"cmp"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	bpfimav1alpha1 "github.com/LorenzoFerro15/bpfima/api/v1alpha1"
)

// Default Policy
var defaultPolicy = bpfimav1alpha1.Policy{
	ObjectMeta: metav1.ObjectMeta{Name: "bpfima-default"},
	Spec: bpfimav1alpha1.PolicySpec{
		Policy: bpfimav1alpha1.PolicyConfig{
			Enabled:      true,
			LogLevel:     2,
			MinFileSize:  0,
			MaxPathDepth: 32,
		},
		Filters: bpfimav1alpha1.FilterConfig{},
		Actions: bpfimav1alpha1.ActionConfig{
			ExtendTPM:       true,
			LogSecurityFS:   true,
			LogKernel:       true,
			AlertSuspicious: false,
			Block:           false,
			TrackContainer:  true,
			BuildDeps:       true,
		},
		CgroupPatterns: []bpfimav1alpha1.PatternEntry{
			{Pattern: "/", Enabled: true, MatchType: 0},
			{Pattern: "init.scope", Enabled: true, MatchType: 0},
		},
		PathPatterns: []bpfimav1alpha1.PatternEntry{
			{Pattern: "/proc/", Enabled: true, MatchType: 1},
			{Pattern: "/sys/", Enabled: true, MatchType: 1},
		},
		Hooks: bpfimav1alpha1.HookConfigs{
			LSMBprmCheckSecurity: &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
			LSMFileOpen:          &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
			LSMFilePostOpen:      &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
			LSMMmapFile:          &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
			LSMSocketConnect:     &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
			LSMContainerEvents:   &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
			KprobeFileOpen:       &bpfimav1alpha1.HookConfig{Enabled: true, TrackContainers: true, MeasureHash: true},
		},
	},
}

func IdentifyCorrectPolicy(policies []bpfimav1alpha1.Policy, nodeLabel map[string]string) (*bpfimav1alpha1.Policy, error) {
	var genericPolicy *bpfimav1alpha1.Policy
	var specificPolicy *bpfimav1alpha1.Policy

	// Loop over all policies
	for i := range policies {
		policy := &policies[i]

		// If the policy doesn't have a selector, consider it a fall-back candidate
		// Select the policy with the latest creation timestamp
		// If the timestamps coincide, go in alphabetic order
		if policy.Spec.Selector == nil {
			if genericPolicy == nil || policy.CreationTimestamp.After(genericPolicy.CreationTimestamp.Time) ||
				(policy.CreationTimestamp.Equal(&genericPolicy.CreationTimestamp) && policy.Name < genericPolicy.Name) {
				genericPolicy = policy
			}
			continue
		}

		// If the policy has a selector, check if it matches the node label
		selector, err := metav1.LabelSelectorAsSelector(policy.Spec.Selector)
		if err != nil {
			return nil, fmt.Errorf("failed to convert LabelSelector for policy %s: %w", policy.Name, err)
		}

		if selector.Matches(labels.Set(nodeLabel)) {
			if specificPolicy == nil || policy.CreationTimestamp.After(specificPolicy.CreationTimestamp.Time) ||
				(policy.CreationTimestamp.Equal(&specificPolicy.CreationTimestamp) && policy.Name < specificPolicy.Name) {
				specificPolicy = policy
			}
			continue
		}
	}

	// Policy choice: specificPolicy -> genericPolicy -> defaultPolicy
	return cmp.Or(specificPolicy, genericPolicy, &defaultPolicy), nil
}
