package securityfs

import "path/filepath"

const (
	// BaseDir is the base directory for BPFIMA security filesystem.
	BaseDir = "/sys/kernel/security/bpfima"
	// LeafListPath is the path to the history of inputs extended into the root.
	LeafListPath = BaseDir + "/merkle_root_history"
	// GlobalMeasurementListPath is the host/default namespace measurement list.
	GlobalMeasurementListPath = ContainerMeasurementDir + "/default/measurements"
	// StatusPath is the path to the status file.
	StatusPath = BaseDir + "/status"
	// ContainerListPath is the directory to enumerate for tracked namespaces.
	// Deprecated: use ContainerMeasurementDir; there is no container-list file.
	ContainerListPath = ContainerMeasurementDir
	// ContainerMeasurementDir is the path to the directory containing container-specific measurements.
	ContainerMeasurementDir = BaseDir + "/namespaces"
)

// ContainerMeasurementListPath returns the path to the measurement list for a specific container.
func ContainerMeasurementListPath(containerID string) string {
	return filepath.Join(ContainerMeasurementDir, containerID, "measurements")
}
