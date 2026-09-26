package securityfs

import "path/filepath"

const (
	// BaseDir is the base directory for BPFIMA security filesystem.
	BaseDir = "/sys/kernel/security/bpfima"
	// LeafListPath is the path to the list of Merkle tree leaves (the kernel "merkle_root" history).
	LeafListPath = BaseDir + "/merkle_root"
	// GlobalMeasurementListPath is the path to the global measurement list.
	GlobalMeasurementListPath = BaseDir + "/measurement_list"
	// StatusPath is the path to the status file.
	StatusPath = BaseDir + "/status"
	// ContainerListPath is the path to the list of tracked containers file.
	ContainerListPath = BaseDir + "/container_list"
	// ContainerMeasurementDir is the path to the directory containing container-specific measurements.
	ContainerMeasurementDir = BaseDir + "/containers"
)

// ContainerMeasurementListPath returns the path to the measurement list for a specific container.
func ContainerMeasurementListPath(containerID string) string {
	return filepath.Join(ContainerMeasurementDir, containerID, "measurements")
}
