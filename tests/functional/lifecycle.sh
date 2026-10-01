#!/bin/bash

set -e

# VERIFY THE BPFIMA POD LIFECYCLE: INSTALLATION, RESTART AND UNINSTALLATION

# Helper Functions
test_result() {
    if [ $? -eq 0 ]; then
        echo "  [PASS] $1"
    else
        echo "  [FAIL] $1"
        exit 1
    fi
}

verify_ebpf_state() {
    echo ""
    echo "Verifying kernel module is loaded..."
    lsmod | grep -q bpfima
    test_result "bpfima kernel module loaded"

    echo ""
    echo "Verifying eBPF programs and maps are pinned..."
    if [ -d /sys/fs/bpf/bpfima ]; then
        PROGS=$(ls -1 /sys/fs/bpf/bpfima | wc -l)
        echo "  Found $PROGS pinned eBPF programs/maps in /sys/fs/bpf/bpfima:"
        ls -1 /sys/fs/bpf/bpfima | sed 's/^/   - /'
        test_result "BPF programs pinned successfully"
    else
        echo "  [FAIL] /sys/fs/bpf/bpfima directory not found"
        exit 1
    fi

    MAPS_FOUND=$(find /sys/fs/bpf -name "*bpfima*" | wc -l)
    if [ "$MAPS_FOUND" -gt 0 ]; then
        echo "  Found $MAPS_FOUND pinned maps/programs:"
        find /sys/fs/bpf -name "*bpfima*" -exec echo "     - {}" \;
        test_result "BPF maps pinned successfully"
    else
        echo "  [FAIL] BPF maps not found"
        exit 1
    fi

    TIMING_STATS=$(find /sys/fs/bpf -name "bpf_timing_stats_*" | wc -l)
    if [ "$TIMING_STATS" -gt 0 ]; then
        test_result "Timing statistics maps pinned"
    else
        echo "  [FAIL] Timing statistics maps not found"
        exit 1
    fi
}

# 1. Installation & Initialization
echo "Installing BPFIMA via Helm..."
helm install bpfima oci://registry-1.docker.io/iochia02/bpfima --version 0.1.0
test_result "Helm install successful"

echo ""
echo "Waiting for daemonset rollout..."
kubectl rollout status daemonset/bpfima --timeout=5m
test_result "DaemonSet rollout complete"

echo ""
echo "Verifying K8s resources are present..."
kubectl get daemonset bpfima > /dev/null
test_result "DaemonSet exists"

kubectl get crd policies.bpfima.polito.it > /dev/null
test_result "CRD exists"

kubectl get ServiceAccount bpfima > /dev/null
test_result "ServiceAccount exists"

kubectl get ClusterRole bpfima > /dev/null
test_result "ClusterRole exists"

kubectl get ClusterRoleBinding bpfima > /dev/null
test_result "ClusterRoleBinding exists"


# 2. Verify Initial State
verify_ebpf_state

echo ""
echo "Verifying securityfs interface..."
ls /sys/kernel/security/bpfima/ > /dev/null 2>&1
test_result "SecurityFS bpfima interface mounted"

# 3. Simulate Pod Restart (NodeSelector Eviction)
echo ""
echo "Remove Pod to simulate restart..."
# Use kubectl patch instead of sed on the local template so K8s actively evicts the pod
kubectl patch daemonset bpfima -p '{"spec": {"template": {"spec": {"nodeSelector": {"simulate-eviction": "true"}}}}}'
echo "Waiting for old pods to terminate..."
sleep 5
kubectl wait --for=delete pod -l app=bpfima --timeout=60s || true
test_result "Pod Removed"

echo ""
echo "Verifying state persists while Pod is down..."
verify_ebpf_state

# 4. Recreate Pod
echo ""
echo "Recreating pod..."
kubectl patch daemonset bpfima --type json -p='[{"op": "remove", "path": "/spec/template/spec/nodeSelector/simulate-eviction"}]'
kubectl rollout status daemonset/bpfima --timeout=5m
test_result "Pod successfully recreated and rolled out"

# 5. Uninstall & Cleanup Verification
echo ""
echo "Uninstalling BPFIMA..."
helm uninstall bpfima
test_result "Helm uninstall successful"

sleep 10

echo ""
echo "Verifying kernel module is unloaded..."
if ! lsmod | grep -q bpfima; then
    test_result "bpfima kernel module unloaded"
else
    echo "  [FAIL] Module unload failed or is stuck"
    exit 1
fi

echo ""
echo "Verifying eBPF programs and maps are unpinned..."
if [ ! -d /sys/fs/bpf/bpfima ]; then
    test_result "All eBPF programs unpinned (/sys/fs/bpf/bpfima removed)"
else
    echo "  [FAIL] /sys/fs/bpf/bpfima still exists"
    exit 1
fi

MAP_COUNT=$(find /sys/fs/bpf -name "*bpfima*" 2>/dev/null | wc -l)
if [ "$MAP_COUNT" -eq 0 ]; then
    test_result "All BPF maps unpinned successfully"
else
    echo "  [FAIL] Found $MAP_COUNT lingering BPF maps"
    exit 1
fi

TIMING_MAPS=$(find /sys/fs/bpf -name "bpf_timing_stats_*" 2>/dev/null | wc -l)
if [ "$TIMING_MAPS" -eq 0 ]; then
    test_result "Timing statistics maps unpinned"
else
    echo "  [FAIL] Found lingering timing maps"
    exit 1
fi

echo ""
echo "Verifying securityfs interface is unmounted..."
if [ ! -d /sys/kernel/security/bpfima/ ]; then
    test_result "/sys/kernel/security/bpfima/ unmounted"
else
    echo "  [FAIL] /sys/kernel/security/bpfima/ still exists"
    exit 1
fi
echo "All tests performed"
exit 0