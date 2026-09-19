package measurement

// ContainerMeasurementListPath returns the path to the measurement list for a specific container.
func ContainerMeasurementListPath(containerID string) string {
	return DefaultContainerMeasurementDir + "/" + containerID + "/measurements"
}
