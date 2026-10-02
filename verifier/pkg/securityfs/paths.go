package securityfs

import "path/filepath"

const (
	// BaseDir is the base directory for BPFIMA security filesystem.
	BaseDir = "/sys/kernel/security/bpfima"
	// LeafListPath is the path to the list of Merkle tree leaves (the kernel "merkle_root_history").
	LeafListPath = BaseDir + "/merkle_root_history"
	// GlobalMeasurementListPath is the path to the global measurement list.
	GlobalMeasurementListPath = BaseDir + "/measurement_list"
	// StatusPath is the path to the status file.
	StatusPath = BaseDir + "/status"
	// ContainerListPath is the path to the list of tracked containers file.
	ContainerListPath = BaseDir + "/container_list"
	// ContainerMeasurementDir is the path to the directory containing a directory of measurements
	// per namespace, named after the cgroup of the namespace (e.g. a container).
	ContainerMeasurementDir = BaseDir + "/namespaces"
)

// ContainerMeasurementListPath returns the path to the measurement list of the namespace with the
// given ID, i.e. the name of its cgroup as recorded by the kernel module.
func ContainerMeasurementListPath(containerID string) string {
	return filepath.Join(ContainerMeasurementDir, containerID, "measurements")
}
