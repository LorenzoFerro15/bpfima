package securityfs

import "testing"

func TestCurrentModulePaths(t *testing.T) {
	if LeafListPath != "/sys/kernel/security/bpfima/merkle_root_history" ||
		GlobalMeasurementListPath != "/sys/kernel/security/bpfima/namespaces/default/measurements" ||
		ContainerMeasurementListPath("example") != "/sys/kernel/security/bpfima/namespaces/example/measurements" {
		t.Fatal("verifier paths do not match current module endpoints")
	}
}
