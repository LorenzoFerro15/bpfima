#!/bin/bash

set -e

# VERIFY THAT WHEN A CONTAINER IS CREATED, THE CORRESPONDING FOLDER IN THE SECURITYFS
# IS CREATED AND MEASUREMENTS RECORDED

# Configuration
POD_NAME="bpfima-test-pod"
IMAGE="alpine:latest"
SEC_FS_BASE="/sys/kernel/security/bpfima/namespaces"

# Ensure KUBECONFIG is set if running via sudo on k3s
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}

# ==========================================
# Helpers
# ==========================================
test_result() {
    if [ $? -eq 0 ]; then
        echo "  [PASS] $1"
    else
        echo "  [FAIL] $1"
        exit 1
    fi
}

cleanup() {
    echo ""
    echo "Cleaning up resources..."
    kubectl delete pod "$POD_NAME" --ignore-not-found=true --wait=false > /dev/null 2>&1
}
trap cleanup EXIT

# ==========================================
# Test Sequence
# ==========================================

echo "1. Creating Test Container"
kubectl run "$POD_NAME" --image="$IMAGE" --restart=Never -- sleep 3600 > /dev/null
echo "Waiting for $POD_NAME to become Ready..."
kubectl wait --for=condition=Ready pod/"$POD_NAME" --timeout=60s > /dev/null
test_result "Container created and running"


echo ""
echo "2. Retrieving Container ID"
# Extract the full container ID from Kubernetes (format: containerd://<hash>)
RAW_CONTAINER_ID=$(kubectl get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].containerID}')

if [ -z "$RAW_CONTAINER_ID" ]; then
    echo "  [FAIL] Could not retrieve container ID from Kubernetes"
    exit 1
fi

# Strip the "containerd://" prefix to get the pure hash
CONTAINER_HASH_LONG=${RAW_CONTAINER_ID#*://}
CONTAINER_HASH=${CONTAINER_HASH_LONG:0:48}

# Construct the expected folder name
EXPECTED_FOLDER="cri-containerd-${CONTAINER_HASH}"
TARGET_DIR="${SEC_FS_BASE}/${EXPECTED_FOLDER}"

echo "  Raw Kubernetes ID: $RAW_CONTAINER_ID"
echo "  Container Hash:    $CONTAINER_HASH"
echo "  Expected Folder:   $EXPECTED_FOLDER"

echo ""
echo "3. Verifying SecurityFS Folder"
if [ -d "$TARGET_DIR" ]; then
    echo "  Found namespace directory: $TARGET_DIR"

    if [ -f "${TARGET_DIR}/measurements" ]; then
        test_result "Measurements file exists in namespace folder"
    else
        echo "  [FAIL] Measurements file missing in $TARGET_DIR"
        exit 1
    fi
else
    echo "  [FAIL] Folder $TARGET_DIR does not exist"
    exit 1
fi


echo ""
echo "4. Executing Commands inside Container"
echo "  Triggering file open events..."
kubectl exec "$POD_NAME" -- sh -c '
    echo "test_data" > /tmp/bpfima_trigger_test.txt
    cat /tmp/bpfima_trigger_test.txt > /dev/null
'
test_result "In-container commands executed successfully"

echo ""
echo "5. Validating Event Capture"
MEASUREMENT_FILE="${TARGET_DIR}/measurements"

# Check if the execution caused an update in the securityfs measurement file
if [ ! -f "$MEASUREMENT_FILE" ]; then
    echo "  [FAIL] Measurements file is missing: $MEASUREMENT_FILE"
    exit 1
fi

echo "  Checking for expected '/bin/cat' execution event..."

# We look specifically for the cat command that was executed via kubectl exec
if grep -q "/bin/cat" "$MEASUREMENT_FILE"; then
    echo "  Event found! Matching entry:"
    grep "/bin/cat" "$MEASUREMENT_FILE" | sed 's/^/    /'
    test_result "BPFIMA successfully captured the specific container event"
else
    echo "  [FAIL] Expected event (/bin/cat) not found in measurements."
    echo "  Current measurements file contents:"
    cat "$MEASUREMENT_FILE" | sed 's/^/    /'
    exit 1
fi

echo ""
echo "6. Validating Continuous Monitoring"
echo "  Executing a secondary command (wget) to verify live capture..."

# wget will trigger a new execve and attempt a socket connection
kubectl exec "$POD_NAME" -- sh -c 'wget -q -T 1 http://127.0.0.1:8080 2> /dev/null || true'

sleep 1

echo "  Checking for expected '/usr/bin/wget' execution event..."
if grep -q "wget" "$MEASUREMENT_FILE"; then
    echo "  Event found! Matching entry:"
    grep "wget" "$MEASUREMENT_FILE" | sed 's/^/    /'
    test_result "Continuous monitoring verified successfully"
else
    echo "  [FAIL] Secondary event (wget) not found in measurements."
    echo "  Current measurements file contents:"
    cat "$MEASUREMENT_FILE" | sed 's/^/    /'
    exit 1
fi

echo "  Checking for expected '127.0.0.1:8080' connection attempt..."
if grep -qE "socket_connect.*127\.0\.0\.1:8080" "$MEASUREMENT_FILE"; then
    echo "  Event found! Matching entry:"
    grep -E "socket_connect.*127\.0\.0\.1:8080" "$MEASUREMENT_FILE" | sed 's/^/    /'
    test_result "Network socket monitoring verified successfully"
else
    echo "  [FAIL] Secondary event (socket_connect) not found in measurements."
    echo "  Current measurements file contents:"
    cat "$MEASUREMENT_FILE" | sed 's/^/    /'
    exit 1
fi

echo ""
echo "Container tracking and event capture verified successfully!"
exit 0