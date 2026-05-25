/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// PolicySpec defines the desired state of Policy
type PolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Policy configuration
	//
	// +kubebuilder:validation:Required
	Policy PolicyConfig `json:"policy"`

	// Filter flags - Control what to skip/filter out
	//
	// +kubebuilder:validation:Required
	Filters FilterConfig `json:"filters"`

	// Action flags - What to do when an event is captured
	//
	// +kubebuilder:validation:Required
	Actions ActionConfig `json:"actions"`

	// Cgroup ignore patterns
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	CgroupPatterns []PatternEntry `json:"cgroup_patterns,omitempty"`

	// Path ignore patterns
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	PathPatterns []PatternEntry `json:"path_patterns,omitempty"`

	// Hook-specific configuration
	//
	// +kubebuilder:validation:Optional
	Hooks HookConfigs `json:"hooks,omitempty"`
}

// PolicyConfig defines the main policy settings
type PolicyConfig struct {
	// Enabled controls whether BPF IMA is active
	//
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// LogLevel sets the logging verbosity (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3
	LogLevel int32 `json:"log_level"`

	// MinFileSize minimum file size to track
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Optional
	MinFileSize int64 `json:"min_file_size,omitempty"`

	// MaxPathDepth maximum depth of file paths to track
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Optional
	MaxPathDepth int32 `json:"max_path_depth,omitempty"`
}

// FilterConfig defines what items to filter out
type FilterConfig struct {
	// SystemCgroups filter system cgroups (/, init.scope)
	//
	// +kubebuilder:validation:Required
	SystemCgroups bool `json:"system_cgroups"`

	// ProcSys filter /proc, /sys paths
	//
	// +kubebuilder:validation:Required
	ProcSys bool `json:"proc_sys"`

	// Dev filter /dev paths
	//
	// +kubebuilder:validation:Required
	Dev bool `json:"dev"`

	// ReadonlyFiles filter readonly file opens
	//
	// +kubebuilder:validation:Required
	ReadonlyFiles bool `json:"readonly_files"`

	// SmallFiles filter files below min_file_size
	//
	// +kubebuilder:validation:Required
	SmallFiles bool `json:"small_files"`

	// NonExecutable filter non-executable files
	//
	// +kubebuilder:validation:Required
	NonExecutable bool `json:"non_executable"`

	// Libraries filter .so libraries
	//
	// +kubebuilder:validation:Required
	Libraries bool `json:"libraries"`

	// TmpFiles filter /tmp files
	//
	// +kubebuilder:validation:Required
	TmpFiles bool `json:"tmp_files"`
}

// ActionConfig defines what actions to take on events
type ActionConfig struct {
	// ExtendTPM extend measurement to TPM PCR
	//
	// +kubebuilder:validation:Required
	ExtendTPM bool `json:"extend_tpm"`

	// LogSecurityFS log to /sys/kernel/security/bpfima/
	//
	// +kubebuilder:validation:Required
	LogSecurityFS bool `json:"log_securityfs"`

	// LogKernel log to kernel log (dmesg)
	//
	// +kubebuilder:validation:Required
	LogKernel bool `json:"log_kernel"`

	// AlertSuspicious alert on suspicious activity
	//
	// +kubebuilder:validation:Required
	AlertSuspicious bool `json:"alert_suspicious"`

	// Block block the operation
	//
	// +kubebuilder:validation:Required
	Block bool `json:"block"`

	// TrackContainer track per-container measurements
	//
	// +kubebuilder:validation:Required
	TrackContainer bool `json:"track_container"`

	// BuildDeps build dependency chain
	//
	// +kubebuilder:validation:Required
	BuildDeps bool `json:"build_deps"`
}

// PatternEntry defines a single pattern for filtering
type PatternEntry struct {
	// Pattern the pattern string to match
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Pattern string `json:"pattern"`

	// Enabled whether this pattern is active
	//
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// MatchType 0=exact, 1=prefix
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1
	// +kubebuilder:validation:Required
	MatchType int32 `json:"match_type"`
}

// HookConfigs defines per-hook configuration
type HookConfigs struct {
	// LSMBprmCheckSecurity configuration
	//
	// +kubebuilder:validation:Optional
	LSMBprmCheckSecurity *HookConfig `json:"lsm_bprm_check_security,omitempty"`

	// LSMFileOpen configuration
	//
	// +kubebuilder:validation:Optional
	LSMFileOpen *HookConfig `json:"lsm_file_open,omitempty"`

	// LSMFilePostOpen configuration
	//
	// +kubebuilder:validation:Optional
	LSMFilePostOpen *HookConfig `json:"lsm_file_post_open,omitempty"`

	// LSMMmapFile configuration
	//
	// +kubebuilder:validation:Optional
	LSMMmapFile *HookConfig `json:"lsm_mmap_file,omitempty"`

	// LSMSocketConnect configuration
	//
	// +kubebuilder:validation:Optional
	LSMSocketConnect *HookConfig `json:"lsm_socket_connect,omitempty"`

	// LSMContainerEvents configuration
	//
	// +kubebuilder:validation:Optional
	LSMContainerEvents *HookConfig `json:"lsm_container_events,omitempty"`

	// KprobeFileOpen configuration
	//
	// +kubebuilder:validation:Optional
	KprobeFileOpen *HookConfig `json:"kprobe_file_open,omitempty"`
}

// HookConfig defines the configuration for a single hook
type HookConfig struct {
	// Enabled whether this hook is active
	//
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// TrackContainers whether to track container context
	//
	// +kubebuilder:validation:Required
	TrackContainers bool `json:"track_containers"`

	// MeasureHash whether to measure file hashes
	//
	// +kubebuilder:validation:Required
	MeasureHash bool `json:"measure_hash"`

	// FilterOverride override global filter flags
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Required
	FilterOverride int32 `json:"filter_override"`

	// ActionOverride override global action flags
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Required
	ActionOverride int32 `json:"action_override"`
}

// PolicyStatus defines the observed state of Policy.
type PolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the Policy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Policy is the Schema for the policies API
type Policy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Policy
	// +required
	Spec PolicySpec `json:"spec"`

	// status defines the observed state of Policy
	// +optional
	Status PolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PolicyList contains a list of Policy
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
}
