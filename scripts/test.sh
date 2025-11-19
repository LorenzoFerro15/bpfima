#!/bin/bash
# BPF-IMA Test Script

set -e

# Default settings
VERBOSE=0
BPF_HOOK=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS] [BPF_HOOK]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Enable verbose output"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Arguments:"
            echo "  BPF_HOOK         Name of the BPF object file to load (with or without .o extension)"
            echo "                   Default: lsm_container_events"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Use default hook"
            echo "  $0 -v                                 # Use default hook with verbose output"
            echo "  $0 lsm_mmap_file                     # Load specific hook"
            echo "  $0 -v lsm_bprm_check_security        # Load hook with verbose output"
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
    BPF_HOOK="lsm_container_events"
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERR] Must run as root"
    exit 1
fi

# Get paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
TEST_DIR="/tmp/bpfima_test"
CONTAINER_NAME_PREFIX="bpfima_test"

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
    
    # Kill loader process first
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        log_info "Stopping loader process (PID: $LOADER_PID)"
        kill -9 "$LOADER_PID" 2>/dev/null || true
        sleep 1
    fi
    
    # Also kill any remaining loader processes
    if pkill -9 -f "$BUILD_DIR/loader" 2>/dev/null; then
        log_info "Stopped additional loader processes"
        sleep 1
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
    
    # Wait a bit for BPF programs to detach
    sleep 1
    
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
    pkill -9 -f "$BUILD_DIR/loader" 2>/dev/null || true
    sleep 1
    if ! rmmod -f bpfima 2>/dev/null; then
        log_err "Cannot remove existing module - it may be in use"
        log_err "Please run: sudo pkill -9 loader && sudo rmmod -f bpfima"
        exit 1
    fi
    sleep 1
fi

if ! insmod "$BUILD_DIR/bpfima.ko"; then
    log_err "Failed to load module"
    exit 1
fi
log_info "Module loaded"

# 3. Load eBPF program
if [ ! -f "$BPF_OBJECT" ]; then
    log_err "BPF object not found: $BPF_OBJECT"
    log_info "Available BPF objects:"
    ls -1 "$BUILD_DIR"/*.o 2>/dev/null | xargs -n1 basename || log_warn "No BPF objects found"
    exit 1
fi

log_info "Starting eBPF program: $(basename $BPF_OBJECT)"
"$BUILD_DIR/loader" "$BPF_OBJECT" &
LOADER_PID=$!
sleep 2

if ! kill -0 $LOADER_PID 2>/dev/null; then
    log_err "Loader process died"
    exit 1
fi
log_info "eBPF program loaded (PID: $LOADER_PID)"

# 3.5 Wait for BPF maps to be pinned
log_verbose "Waiting for BPF maps to be available..."
sleep 1

# 3.6 Initialize policy maps with less strict defaults
log_info "Initializing BPF policy maps (less strict policy - tracks everything)"
if [ -f "$BUILD_DIR/policy_init" ]; then
    if [ "$VERBOSE" -eq 1 ]; then
        if ! "$BUILD_DIR/policy_init"; then
            log_err "Failed to initialize policy maps"
            log_err "This may cause issues with event recording"
            log_warn "Continuing anyway..."
        else
            log_info "✓ Policy maps initialized successfully"
            log_info "  - Filter flags: 0x0 (no filtering)"
            log_info "  - All user processes, containers, and system services will be tracked"
        fi
    else
        if ! "$BUILD_DIR/policy_init" > /dev/null 2>&1; then
            log_warn "Failed to initialize policy maps (continuing anyway)"
        else
            log_info "Policy maps initialized successfully"
        fi
    fi
else
    log_err "policy_init tool not found at $BUILD_DIR/policy_init"
    log_err "Policy maps will be empty - events may not be recorded!"
    log_warn "Run 'make' to build policy_init"
fi

# Verify policy map is accessible
if [ -e "/sys/fs/bpf/bpfima_policy_map" ]; then
    log_verbose "✓ Policy map pinned and accessible"
else
    log_warn "Policy map not found at /sys/fs/bpf/bpfima_policy_map"
fi

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
    sleep 2
    
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
    sleep 1
done

sleep 2
log_info "All container operations completed"

# 6. Check securityfs
if [ -d "/sys/kernel/security/bpfima/namespaces" ]; then
    CONTAINER_COUNT=$(ls -1 /sys/kernel/security/bpfima/namespaces/ 2>/dev/null | wc -l)
    log_info "Containers tracked in securityfs: $CONTAINER_COUNT"
    if [ "$VERBOSE" -eq 1 ]; then
        log_verbose "Namespace IDs:"
        ls -1 /sys/kernel/security/bpfima/namespaces/ 2>/dev/null || true
    fi
else
    log_warn "securityfs directory not found"
fi

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

sleep 2

# Socket creation tests
log_info ""
log_info "Testing socket creation"

# Test TCP connection between two valid IPs (localhost)
log_info "Testing TCP connection between two valid IPs (127.0.0.1)"
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
print('TCP connection test: received', data)
"
log_info "TCP connection test completed"

log_info "Socket creation tests completed"
# To see the socket hook output, use the following command:
# tail -20 /sys/kernel/debug/tracing/trace_pipe

# 8. Display summary
log_info "Test completed successfully"
log_info "Check logs with: dmesg | grep bpfima"

# Show recent kernel messages
if dmesg | grep -q bpfima; then
    log_info "Recent kernel messages:"
    if [ "$VERBOSE" -eq 1 ]; then
        dmesg | grep bpfima | tail -20
    else
        dmesg | grep bpfima | tail -10
    fi
fi

# Wait a moment for any final events
sleep 2

log_info "Test finished - press Ctrl+C to cleanup and exit"
log_info "Monitoring mode active... (loader PID: $LOADER_PID)"

# Wait indefinitely until interrupted
if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
    wait "$LOADER_PID" 2>/dev/null || true
else
    log_warn "Loader process not running"
    sleep infinity
fi
