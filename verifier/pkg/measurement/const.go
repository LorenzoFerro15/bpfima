package measurement

const (
	// DefaultBaseDir is the base directory for BPFIMA security filesystem.
	DefaultBaseDir = "/sys/kernel/security/bpfima"
	// DefaultRootListPath is the path to the Merkle root list.
	DefaultRootListPath = DefaultBaseDir + "/merkle_root"
	// DefaultGlobalMeasurementListPath is the path to the global measurement list.
	DefaultGlobalMeasurementListPath = DefaultBaseDir + "/measurement_list"
	// DefaultStatusPath is the path to the status file.
	DefaultStatusPath = DefaultBaseDir + "/status"
	// DefaultContainerListPath is the path to the list of tracked containers file.
	DefaultContainerListPath = DefaultBaseDir + "/container_list"
	// DefaultContainerMeasurementDir is the path to the directory containing container-specific measurements.
	DefaultContainerMeasurementDir = DefaultBaseDir + "/containers"
)
