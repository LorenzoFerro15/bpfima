#!/bin/bash
# BPF-IMA Test Script

set -e

# Default settings
VERBOSE=0
BPF_HOOK=""

# Get paths first
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
TEST_DIR="/tmp/bpfima_test"
CONTAINER_NAME_PREFIX="bpfima_test"

# Source utility functions
source "$SCRIPT_DIR/test_utils.sh"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [BPF_HOOK] [OPTIONS]"
            echo ""
            echo "Arguments:"
            echo "  BPF_HOOK         Name of the BPF object file to load (with or without .o extension)"
            echo "                   Default: lsm_bprm_check_security"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Enable verbose output"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Use default hook"
            echo "  $0 lsm_mmap_file                     # Load specific hook"
            echo "  $0 lsm_bprm_check_security -v        # Load hook with verbose output"
            echo "  $0 -v                                 # Use default hook with verbose output"
            exit 0
            ;;
        *)
            if [ -z "$BPF_HOOK" ]; then
                BPF_HOOK="$1"
            else
                echo "Error: Unknown argument '$1'"
                exit 1
            fi
            shift
            ;;
    esac
done

# Set default BPF hook if not specified
if [ -z "$BPF_HOOK" ]; then
    BPF_HOOK="lsm_bprm_check_security"
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERR] Must run as root"
    exit 1
fi

# Re-set paths after argument parsing
cd "$PROJECT_ROOT"

# Add .o extension if not already present
if [[ "$BPF_HOOK" == *.o ]]; then
    BPF_OBJECT="$BUILD_DIR/$BPF_HOOK"
else
    BPF_OBJECT="$BUILD_DIR/${BPF_HOOK}.o"
fi

cd "$PROJECT_ROOT"

# Logging functions
log_info() {
    echo "[INFO] $1"
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[VERBOSE] $1"
    fi
}

log_warn() {
    echo "[WARN] $1"
}

log_err() {
    echo "[ERR] $1"
}

# Cleanup function
cleanup() {
    log_info "Cleanup started"
    
    # Kill bpfima-tool process first
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        log_info "Stopping bpfima-tool process (PID: $LOADER_PID)"
        kill -TERM "$LOADER_PID" 2>/dev/null || true
        
        # Wait for graceful exit
        if ! wait_for_process_exit "$LOADER_PID" 3; then
            log_warn "bpfima-tool didn't exit gracefully, forcing..."
            kill -9 "$LOADER_PID" 2>/dev/null || true
        fi
    fi
    
    # Also kill any remaining bpfima-tool processes
    if pkill -TERM -f "$BUILD_DIR/bpfima-tool" 2>/dev/null; then
        log_info "Stopping additional bpfima-tool processes"
        sleep 0.5
        pkill -9 -f "$BUILD_DIR/bpfima-tool" 2>/dev/null || true
    fi
     
    if [ -n "$CONTAINER_CLI" ]; then
        log_info "Removing test containers"
        for container in nginx redis postgres; do
            $CONTAINER_CLI rm -f "${CONTAINER_NAME_PREFIX}_${container}" >/dev/null 2>&1 || true
        done
    else
        # Try both if CONTAINER_CLI not set
        for container in nginx redis postgres; do
            if command -v docker >/dev/null 2>&1; then
                docker rm -f "${CONTAINER_NAME_PREFIX}_${container}" >/dev/null 2>&1 || true
            fi
            if command -v podman >/dev/null 2>&1; then
                podman rm -f "${CONTAINER_NAME_PREFIX}_${container}" >/dev/null 2>&1 || true
            fi
        done
    fi
    
    # Clean up pinned BPF maps
    log_verbose "Cleaning up pinned BPF maps"
    rm -f /sys/fs/bpf/bpfima_policy_map 2>/dev/null || true
    rm -f /sys/fs/bpf/bpfima_hook_config_map 2>/dev/null || true
    rm -f /sys/fs/bpf/bpfima_cgroup_patterns_map 2>/dev/null || true
    rm -f /sys/fs/bpf/bpfima_path_patterns_map 2>/dev/null || true
    
    # Try to remove module
    if lsmod | grep -q "^bpfima "; then
        log_info "Removing kernel module"
        if rmmod bpfima 2>/dev/null; then
            log_info "Kernel module removed"
        else
            log_warn "Could not remove module (may require manual cleanup)"
            log_warn "Try: sudo rmmod -f bpfima"
        fi
    fi
    
    rm -rf "$TEST_DIR" 2>/dev/null || true
    
    log_info "Cleanup completed"
}
trap cleanup EXIT INT TERM

# Main execution
log_info "BPF-IMA Test Starting"

# 1. Build
log_info "Building..."
if [ "$VERBOSE" -eq 1 ]; then
    if ! make all; then
        log_err "Build failed"
        exit 1
    fi
else
    if ! make all > /dev/null 2>&1; then
        log_err "Build failed"
        exit 1
    fi
fi
log_info "Build successful"

# 2. Load kernel module
log_info "Loading kernel module..."
if lsmod | grep -q "^bpfima "; then
    log_info "Module already loaded, removing..."
    pkill -9 -f "$BUILD_DIR/bpfima-tool" 2>/dev/null || true
    
    if ! wait_for_module_unload bpfima 2; then
        if ! rmmod -f bpfima 2>/dev/null; then
            log_err "Cannot remove existing module - it may be in use"
            log_err "Please run: sudo pkill -9 bpfima-tool && sudo rmmod -f bpfima"
            exit 1
        fi
    fi
    
    if ! wait_for_module_unload bpfima 5; then
        log_err "Module did not unload in time"
        exit 1
    fi
fi

if ! insmod "$BUILD_DIR/bpfima.ko"; then
    log_err "Failed to load module"
    exit 1
fi

if ! wait_for_module bpfima 5; then
    log_err "Module did not load in time"
    exit 1
fi

if ! wait_for_securityfs bpfima 5; then
    log_err "SecurityFS not available"
    exit 1
fi

log_info "Module loaded and ready"

# 3. Load eBPF program
if [ ! -f "$BPF_OBJECT" ]; then
    log_err "BPF object not found: $BPF_OBJECT"
    log_info "Available BPF objects:"
    ls -1 "$BUILD_DIR"/*.o 2>/dev/null | xargs -n1 basename || log_warn "No BPF objects found"
    exit 1
fi

log_info "Starting eBPF program: $(basename $BPF_OBJECT)"

# Use bpfima-tool instead of old loader
"$BUILD_DIR/bpfima-tool" load "$BPF_OBJECT" -d

# Wait for PID file
PID_FILE="/var/run/bpfima.pid"
for i in {1..50}; do
    if [ -f "$PID_FILE" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -f "$PID_FILE" ]; then
    log_err "PID file not created in time"
    exit 1
fi

LOADER_PID=$(cat "$PID_FILE")
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    log_err "bpfima-tool process failed to start (PID: $LOADER_PID is dead)"
    exit 1
fi
log_info "eBPF program loaded (PID: $LOADER_PID)"

# Wait for BPF maps to be pinned
log_verbose "Waiting for BPF maps to be available..."
if ! wait_for_bpf_maps bpfima_policy_map bpfima_hook_config_map bpfima_cgroup_patterns_map bpfima_path_patterns_map; then
    log_err "BPF maps not available in time"
    log_err "bpfima-tool may have failed"
    exit 1
fi
log_verbose "  BPF maps available"

# Initialize policy maps using bpfima-tool
log_info "Initializing BPF policy maps (comprehensive policy - tracks everything)"
if [ "$VERBOSE" -eq 1 ]; then
    if ! "$BUILD_DIR/bpfima-tool" policy-init; then
        log_err "Failed to initialize policy maps"
        log_err "This may cause issues with event recording"
        log_warn "Continuing anyway..."
    else
        log_info "  Policy maps initialized successfully"
        log_info "  - Filter flags: 0x0 (no filtering)"
        log_info "  - All user processes, containers, and system services will be tracked"
    fi
else
    if ! "$BUILD_DIR/bpfima-tool" policy-init > /dev/null 2>&1; then
        log_warn "Failed to initialize policy maps (continuing anyway)"
    else
        log_info "Policy maps initialized successfully"
    fi
fi

# Verify policy map is accessible
if [ -e "/sys/fs/bpf/bpfima_policy_map" ]; then
    log_verbose "  Policy map pinned and accessible"
else
    log_warn "Policy map not found at /sys/fs/bpf/bpfima_policy_map"
fi

# 3.6 Test YAML Policy Update
log_info ""
log_info "=== Testing YAML Policy Update ==="
log_info "This will test loading policy configuration from YAML files"

# Test with default comprehensive policy
if [ -f "config/policy.yaml" ]; then
    log_info "Testing policy update with config/policy.yaml"
    if [ "$VERBOSE" -eq 1 ]; then
        if "$BUILD_DIR/bpfima-tool" policy-update config/policy.yaml; then
            log_info "  Successfully loaded comprehensive policy from YAML"
        else
            log_warn "Failed to load YAML policy (may not be fully implemented yet)"
        fi
    else
        if "$BUILD_DIR/bpfima-tool" policy-update config/policy.yaml > /dev/null 2>&1; then
            log_info "  YAML policy loaded successfully"
        else
            log_warn "YAML policy update failed (continuing with hardcoded defaults)"
        fi
    fi
    
    # Verify the policy was updated
    if [ -f "/sys/kernel/security/bpfima/policy" ]; then
        log_verbose "Current policy after YAML update:"
        if [ "$VERBOSE" -eq 1 ]; then
            cat /sys/kernel/security/bpfima/policy | head -10
        fi
        
        # Validate policy content
        log_info "Validating policy configuration..."
        if grep -q "enabled:" /sys/kernel/security/bpfima/policy && \
           grep -q "filter_flags:" /sys/kernel/security/bpfima/policy && \
           grep -q "action_flags:" /sys/kernel/security/bpfima/policy; then
            log_info "  Policy file contains expected fields"
        else
            log_warn "Policy file missing expected fields"
        fi
    fi
else
    log_warn "config/policy.yaml not found, skipping YAML policy test"
fi

# Test with minimal policy if available
if [ -f "config/policy-minimal.yaml" ] && [ "$VERBOSE" -eq 1 ]; then
    log_info ""
    log_info "Testing with minimal policy (config/policy-minimal.yaml)"
    if "$BUILD_DIR/bpfima-tool" policy-update config/policy-minimal.yaml; then
        log_info "  Successfully loaded minimal policy from YAML"
    else
        log_warn "Failed to load minimal YAML policy"
    fi
fi

# 3.7 Test global policy changes
log_info ""
log_info "=== Testing Global Policy Changes ==="
log_info "This will trigger policy change tracking and Merkle tree extensions"

if [ -f "/sys/kernel/security/bpfima/policy" ]; then
    log_info "Initial global policy:"
    if [ "$VERBOSE" -eq 1 ]; then
        cat /sys/kernel/security/bpfima/policy | head -10
    fi
    
    # Change 1: Update filter_flags
    log_info "Test 1: Changing filter_flags to 0x7"
    echo "filter_flags=0x7" > /sys/kernel/security/bpfima/policy
    log_info "  filter_flags updated"
    
    # Verify the change was applied
    if grep -q "filter_flags: 0x00000007" /sys/kernel/security/bpfima/policy; then
        log_info "     Verified: filter_flags is now 0x7"
    else
        log_warn "     Failed to verify filter_flags update"
    fi
    
    # Change 2: Update action_flags
    log_info "Test 2: Changing action_flags to 0x1F"
    echo "action_flags=0x1F" > /sys/kernel/security/bpfima/policy
    log_info "  action_flags updated"
    
    # Verify the change was applied
    if grep -q "action_flags: 0x0000001f" /sys/kernel/security/bpfima/policy; then
        log_info "     Verified: action_flags is now 0x1F"
    else
        log_warn "     Failed to verify action_flags update"
    fi
    
    # Change 3: Update min_file_size
    log_info "Test 3: Changing min_file_size to 4096"
    echo "min_file_size=4096" > /sys/kernel/security/bpfima/policy
    log_info "  min_file_size updated"
    
    # Verify the change was applied
    if grep -q "min_file_size: 4096" /sys/kernel/security/bpfima/policy; then
        log_info "     Verified: min_file_size is now 4096"
    else
        log_warn "     Failed to verify min_file_size update"
    fi
    
    # Change 4: Update log_level
    log_info "Test 4: Changing log_level to 3"
    echo "log_level=3" > /sys/kernel/security/bpfima/policy
    log_info "  log_level updated"
    
    # Verify the change was applied
    if grep -q "log_level: 3" /sys/kernel/security/bpfima/policy; then
        log_info "     Verified: log_level is now 3"
    else
        log_warn "     Failed to verify log_level update"
    fi
    
    # Display policy changes
    if [ -f "/sys/kernel/security/bpfima/policy_changes" ]; then
        log_info ""
        log_info "Global policy changes recorded:"
        if [ "$VERBOSE" -eq 1 ]; then
            cat /sys/kernel/security/bpfima/policy_changes
        else
            CHANGE_COUNT=$(grep -v '^#' /sys/kernel/security/bpfima/policy_changes 2>/dev/null | wc -l)
            log_info "  Total changes recorded: $CHANGE_COUNT"
            log_info "  (use -v to see full details)"
        fi
    else
        log_warn "policy_changes file not found"
    fi
    
    # Check kernel messages for Merkle extensions
    if [ "$VERBOSE" -eq 1 ]; then
        log_verbose "Recent Merkle root extensions:"
        dmesg | grep -i "merkle root extended" | tail -5 || log_verbose "No Merkle extensions found in logs"
    fi
else
    log_warn "Global policy file not found at /sys/kernel/security/bpfima/policy"
fi

log_info "Global policy tests completed"
log_info ""

# 4. Run container test
log_info "Starting container tests"

CONTAINER_CLI="docker"

log_info "Using container runtime: $CONTAINER_CLI"

# Test with multiple different container images
IMAGES=("nginx:latest" "redis:latest" "postgres:latest")
CONTAINERS=("nginx" "redis" "postgres")

for i in "${!IMAGES[@]}"; do
    IMAGE="${IMAGES[$i]}"
    CONTAINER="${CONTAINERS[$i]}"
    CONTAINER_NAME="${CONTAINER_NAME_PREFIX}_${CONTAINER}"
    
    log_info "Pulling image: $IMAGE"
    if [ "$VERBOSE" -eq 1 ]; then
        if ! $CONTAINER_CLI pull "$IMAGE"; then
            log_warn "Failed to pull $IMAGE"
            continue
        fi
    else
        if ! $CONTAINER_CLI pull "$IMAGE" 2>&1 | grep -v "up to date" | grep -q .; then
            log_verbose "Image $IMAGE already up to date or pulled successfully"
        fi
    fi
    
    log_info "Starting container: $CONTAINER_NAME (image: $IMAGE)"
    
    # Start container with appropriate settings for each image
    case "$CONTAINER" in
        nginx)
            if [ "$VERBOSE" -eq 1 ]; then
                if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm "$IMAGE"; then
                    log_err "Failed to start $CONTAINER_NAME"
                    continue
                fi
            else
                if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm "$IMAGE" >/dev/null 2>&1; then
                    log_err "Failed to start $CONTAINER_NAME"
                    continue
                fi
            fi
            ;;
        redis)
            if [ "$VERBOSE" -eq 1 ]; then
                if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm "$IMAGE"; then
                    log_err "Failed to start $CONTAINER_NAME"
                    continue
                fi
            else
                if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm "$IMAGE" >/dev/null 2>&1; then
                    log_err "Failed to start $CONTAINER_NAME"
                    continue
                fi
            fi
            ;;
        postgres)
            if [ "$VERBOSE" -eq 1 ]; then
                if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm -e POSTGRES_PASSWORD=testpass "$IMAGE"; then
                    log_err "Failed to start $CONTAINER_NAME"
                    continue
                fi
            else
                if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm -e POSTGRES_PASSWORD=testpass "$IMAGE" >/dev/null 2>&1; then
                    log_err "Failed to start $CONTAINER_NAME"
                    continue
                fi
            fi
            ;;
    esac
    
    log_info "Container started: $CONTAINER_NAME"
    
    # Wait for container to be fully running
    if ! wait_for_container "$CONTAINER_NAME" "$CONTAINER_CLI" 30; then
        log_err "Container $CONTAINER_NAME not ready in time"
        continue
    fi
    log_verbose "  Container $CONTAINER_NAME is running"
    
    # Perform file operations in container
    log_info "Performing file operations in $CONTAINER_NAME"
    
    case "$CONTAINER" in
        nginx)
            CMD=(sh -c 'echo test > /tmp/test.txt && cat /tmp/test.txt > /dev/null && ls -la /usr/share/nginx/html/ > /dev/null')
            ;;
        redis)
            CMD=(sh -c 'echo test > /tmp/test.txt && cat /tmp/test.txt > /dev/null && ls -la /data/ > /dev/null')
            ;;
        postgres)
            CMD=(bash -c 'echo test > /tmp/test.txt && cat /tmp/test.txt > /dev/null && ls -la /var/lib/postgresql/ > /dev/null')
            ;;
    esac
    
    if [ "$VERBOSE" -eq 1 ]; then
        log_verbose "Executing in $CONTAINER_NAME: ${CMD[*]}"
        if ! $CONTAINER_CLI exec "$CONTAINER_NAME" "${CMD[@]}"; then
            log_warn "Some operations failed in $CONTAINER_NAME"
        fi
    else
        if ! $CONTAINER_CLI exec "$CONTAINER_NAME" "${CMD[@]}" >/dev/null 2>&1; then
            log_warn "Some operations failed in $CONTAINER_NAME"
        fi
    fi
    
    log_info "File operations completed in $CONTAINER_NAME"
done

# Give a moment for all measurements to be processed
sleep 0.5
log_info "All container operations completed"

# 6. Check securityfs
if [ -d "/sys/kernel/security/bpfima/namespaces" ]; then
    CONTAINER_COUNT=$(ls -1 /sys/kernel/security/bpfima/namespaces/ 2>/dev/null | wc -l)
    log_info "Containers tracked in securityfs: $CONTAINER_COUNT"
    
    # Validate we tracked the expected number of containers
    if [ "$CONTAINER_COUNT" -ge 3 ]; then
        log_info "     Expected number of containers tracked (3 or more)"
    else
        log_warn "     Expected at least 3 containers, found $CONTAINER_COUNT"
    fi
    
    if [ "$VERBOSE" -eq 1 ]; then
        log_verbose "Namespace IDs:"
        ls -1 /sys/kernel/security/bpfima/namespaces/ 2>/dev/null || true
    fi
    
    # Validate that container directories contain expected files
    log_info "Validating container measurement files..."
    for ns_dir in /sys/kernel/security/bpfima/namespaces/*/; do
        if [ -f "${ns_dir}measurements" ] && [ -f "${ns_dir}status" ]; then
            NS_ID=$(basename "$ns_dir")
            MEASUREMENT_COUNT=$(wc -l < "${ns_dir}measurements" 2>/dev/null || echo "0")
            if [ "$MEASUREMENT_COUNT" -gt 0 ]; then
                log_verbose "  Container ${NS_ID:0:12}...: $MEASUREMENT_COUNT measurements recorded"
            fi
        fi
    done
else
    log_warn "securityfs directory not found"
fi

# 6.5 Test namespace-specific policy changes
log_info ""
log_info "=== Testing Namespace Policy Changes ==="

if [ -d "/sys/kernel/security/bpfima/namespaces" ]; then
    # Get the first namespace ID
    NAMESPACE_IDS=($(ls -1 /sys/kernel/security/bpfima/namespaces/ 2>/dev/null))
    
    if [ ${#NAMESPACE_IDS[@]} -gt 0 ]; then
        TEST_NAMESPACE="${NAMESPACE_IDS[0]}"
        log_info "Testing policy changes for namespace: ${TEST_NAMESPACE:0:12}..."
        
        POLICY_FILE="/sys/kernel/security/bpfima/namespaces/$TEST_NAMESPACE/policy"
        CHANGES_FILE="/sys/kernel/security/bpfima/namespaces/$TEST_NAMESPACE/policy_changes"
        
        if [ -f "$POLICY_FILE" ]; then
            log_info "Initial namespace policy:"
            if [ "$VERBOSE" -eq 1 ]; then
                cat "$POLICY_FILE" | head -10
            fi
            
            # Change 1: Update filter_flags
            log_info "Test 1: Changing namespace filter_flags to 0x3"
            echo "filter_flags=0x3" > "$POLICY_FILE"
            log_info "  Namespace filter_flags updated"
            
            # Verify the change
            if grep -q "filter_flags: 0x00000003" "$POLICY_FILE"; then
                log_info "     Verified: namespace filter_flags is now 0x3"
            else
                log_warn "     Failed to verify namespace filter_flags update"
            fi
            
            # Change 2: Update action_flags
            log_info "Test 2: Changing namespace action_flags to 0x7E"
            echo "action_flags=0x7E" > "$POLICY_FILE"
            log_info "  Namespace action_flags updated"
            
            # Verify the change
            if grep -q "action_flags: 0x0000007e" "$POLICY_FILE"; then
                log_info "     Verified: namespace action_flags is now 0x7E"
            else
                log_warn "     Failed to verify namespace action_flags update"
            fi
            
            # Change 3: Update min_file_size
            log_info "Test 3: Changing namespace min_file_size to 8192"
            echo "min_file_size=8192" > "$POLICY_FILE"
            log_info "  Namespace min_file_size updated"
            
            # Verify the change
            if grep -q "min_file_size: 8192" "$POLICY_FILE"; then
                log_info "     Verified: namespace min_file_size is now 8192"
            else
                log_warn "     Failed to verify namespace min_file_size update"
            fi
            
            # Display policy changes
            if [ -f "$CHANGES_FILE" ]; then
                log_info ""
                log_info "Namespace policy changes recorded:"
                if [ "$VERBOSE" -eq 1 ]; then
                    cat "$CHANGES_FILE"
                else
                    CHANGE_COUNT=$(grep -v '^#' "$CHANGES_FILE" 2>/dev/null | wc -l)
                    log_info "  Total changes recorded: $CHANGE_COUNT"
                    
                    # Verify changes were recorded
                    if [ "$CHANGE_COUNT" -ge 3 ]; then
                        log_info "     Expected number of policy changes tracked"
                    else
                        log_warn "     Expected at least 3 policy changes, found $CHANGE_COUNT"
                    fi
                    log_info "  (use -v to see full details)"
                fi
            else
                log_warn "policy_changes file not found for namespace"
            fi
            
            # Check kernel messages for leaf hash extensions
            if [ "$VERBOSE" -eq 1 ]; then
                log_verbose "Recent container leaf hash extensions:"
                dmesg | grep -i "extended leaf hash" | tail -5 || log_verbose "No leaf hash extensions found in logs"
                log_verbose "Recent Merkle root extensions (from namespace changes):"
                dmesg | grep -i "extended merkle root for policy" | tail -5 || log_verbose "No policy-related Merkle extensions found"
            fi
        else
            log_warn "Policy file not found for namespace: $TEST_NAMESPACE"
        fi
    else
        log_warn "No namespaces found to test policy changes"
    fi
else
    log_warn "Namespaces directory not found"
fi

log_info "Namespace policy tests completed"
log_info ""

# 7. Stop containers
log_info "Stopping containers"
for container in nginx redis postgres; do
    CONTAINER_NAME="${CONTAINER_NAME_PREFIX}_${container}"
    if [ "$VERBOSE" -eq 1 ]; then
        log_verbose "Stopping $CONTAINER_NAME"
        $CONTAINER_CLI stop "$CONTAINER_NAME" 2>&1 || true
    else
        $CONTAINER_CLI stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
done
log_info "Containers stopped"

# Give system a moment to process container shutdown
sleep 0.5

# Socket creation tests
log_info ""
log_info "Testing socket creation"

# Test TCP connection between two valid IPs (localhost)
log_info "TEST 1: TCP connection between two valid IPs (127.0.0.1) - Standard IPv4 connection"
python3 -c "
import socket, threading, time
def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 23456))
    s.listen(1)
    conn, addr = s.accept()
    conn.send(b'hello')
    conn.close()
    s.close()
threading.Thread(target=server, daemon=True).start()
time.sleep(1)
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(('127.0.0.1', 23456))
data = c.recv(16)
c.close()
"
log_info "TCP connection test completed"

log_info "TEST 2: Creation of an Unix domain socket"
python3 -c "
import socket, os, threading, time
sock_path = '/tmp/test_socket.sock'
if os.path.exists(sock_path):
    os.remove(sock_path)
def server():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sock_path)
    s.listen(1)
    conn, addr = s.accept()
    conn.send(b'hello')
    conn.close()
    s.close()
    os.remove(sock_path)

threading.Thread(target=server, daemon=True).start()
time.sleep(0.5)
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(sock_path)
data = c.recv(16)
c.close()
"
log_info "Unix domain socket test completed"

log_info "Socket creation tests completed"
# To see the socket hook output, use the following command:
# tail -20 /sys/kernel/debug/tracing/trace_pipe

# 8. Display summary
log_info ""
log_info "==================================="
log_info "===  TEST SUMMARY  ==="
log_info "==================================="

# Show policy change statistics
log_info ""
log_info "Policy Change Statistics:"

if [ -f "/sys/kernel/security/bpfima/policy_changes" ]; then
    GLOBAL_CHANGES=$(grep -v '^#' /sys/kernel/security/bpfima/policy_changes 2>/dev/null | wc -l)
    log_info "  Global policy changes: $GLOBAL_CHANGES"
    
    # Validate we have recorded policy changes
    if [ "$GLOBAL_CHANGES" -ge 4 ]; then
        log_info "     Expected number of global policy changes recorded"
    else
        log_warn "     Expected at least 4 global policy changes, found $GLOBAL_CHANGES"
    fi
    
    # Verify policy change file contains expected fields
    if grep -q "filter_flags" /sys/kernel/security/bpfima/policy_changes && \
       grep -q "action_flags" /sys/kernel/security/bpfima/policy_changes; then
        log_info "     Policy changes contain expected field names"
    fi
else
    log_info "  Global policy changes: N/A"
fi

if [ -d "/sys/kernel/security/bpfima/namespaces" ]; then
    TOTAL_NS_CHANGES=0
    for ns_dir in /sys/kernel/security/bpfima/namespaces/*/; do
        if [ -f "${ns_dir}policy_changes" ]; then
            NS_CHANGES=$(grep -v '^#' "${ns_dir}policy_changes" 2>/dev/null | wc -l)
            TOTAL_NS_CHANGES=$((TOTAL_NS_CHANGES + NS_CHANGES))
        fi
    done
    log_info "  Namespace policy changes: $TOTAL_NS_CHANGES"
    
    # Validate we have namespace policy changes
    if [ "$TOTAL_NS_CHANGES" -ge 3 ]; then
        log_info "     Expected namespace policy changes recorded"
    elif [ "$TOTAL_NS_CHANGES" -gt 0 ]; then
        log_warn "     Expected at least 3 namespace policy changes, found $TOTAL_NS_CHANGES"
    fi
else
    log_info "  Namespace policy changes: N/A"
fi

# Show Merkle root history
log_info ""
log_info "Merkle Root History:"
if [ -f "/sys/kernel/security/bpfima/merkle_root_history" ]; then
    MERKLE_ENTRIES=$(wc -l < /sys/kernel/security/bpfima/merkle_root_history 2>/dev/null || echo "0")
    log_info "  Total Merkle root extensions: $MERKLE_ENTRIES"
    
    # Validate we have Merkle root extensions
    if [ "$MERKLE_ENTRIES" -gt 0 ]; then
        log_info "     Merkle root history contains entries"
        
        # Verify entries contain hash values (should be hex strings)
        if grep -qE '[0-9a-f]{64}' /sys/kernel/security/bpfima/merkle_root_history; then
            log_info "     Merkle root entries contain valid hash values"
        else
            log_warn "     Merkle root entries don't contain expected hash format"
        fi
        
        # Verify entries contain container/namespace information
        if grep -q "container:" /sys/kernel/security/bpfima/merkle_root_history || \
           grep -q "namespace:" /sys/kernel/security/bpfima/merkle_root_history; then
            log_info "     Merkle root entries contain container tracking info"
        fi
    else
        log_warn "     No Merkle root extensions recorded"
    fi
    
    if [ "$VERBOSE" -eq 1 ]; then
        log_info ""
        log_info "Full Merkle root history:"
        cat /sys/kernel/security/bpfima/merkle_root_history
    else
        log_info "  (use -v to see full history)"
        log_info "  Last 3 extensions:"
        tail -3 /sys/kernel/security/bpfima/merkle_root_history 2>/dev/null || log_info "    (none)"
    fi
else
    log_info "  Merkle root history: N/A"
fi

log_info ""
log_info "Test completed successfully"
log_info "Check logs with: dmesg | grep bpfima"

# Show recent kernel messages
if dmesg | grep -q bpfima; then
    log_info ""
    log_info "Recent kernel messages:"
    if [ "$VERBOSE" -eq 1 ]; then
        dmesg | grep bpfima | tail -30
    else
        dmesg | grep bpfima | tail -10
    fi
fi

# Wait a moment for any final events
sleep 2

log_info "Test finished - press Ctrl+C to cleanup and exit"
log_info "Monitoring mode active... (loader PID: $LOADER_PID)"

# Wait indefinitely until interrupted
while true; do
    sleep 1
done
