#!/bin/bash
# BPF-IMA Test Script

set -e

# Parse command line arguments
if [ "$#" -eq 1 ]; then
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        log_info "Usage: $0 [BPF_HOOK]"
        log_info "  BPF_HOOK: Name of the BPF object file to load (with or without .o extension)"
        log_info "  Default: lsm_container_events"
        log_info "  Examples:"
        log_info "    $0                                    # Use default hook"
        log_info "    $0 lsm_mmap_file                     # Load specific hook"
        log_info "    $0 lsm_bprm_check_security.o         # Load another hook (with .o)"
        exit 0
    else
        # Add .o extension if not already present
        if [[ "$1" == *.o ]]; then
            BPF_OBJECT="$BUILD_DIR/$1"
        else
            BPF_OBJECT="$BUILD_DIR/$1.o"
        fi
    fi
else
    BPF_OBJECT="$BUILD_DIR/lsm_container_events.o"
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
CONTAINER_NAME="bpfima_test_container"

# Get BPF hook name from argument or use default
BPF_HOOK="${1:-lsm_container_events}"
BPF_OBJECT="$BUILD_DIR/${BPF_HOOK}.o"

cd "$PROJECT_ROOT"

# Logging functions
log_info() {
    echo "[INFO] $1"
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
    
    # Remove containers
    if [ -n "$CONTAINER_CLI" ]; then
        log_info "Removing test container"
        $CONTAINER_CLI rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    else
        # Try both if CONTAINER_CLI not set
        if command -v docker >/dev/null 2>&1; then
            docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        fi
        if command -v podman >/dev/null 2>&1; then
            podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        fi
    fi
    
    # Wait a bit for BPF programs to detach
    sleep 1
    
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
if ! make all > /dev/null 2>&1; then
    log_err "Build failed"
    exit 1
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

# 4. Run container test
log_info "Starting container test"

CONTAINER_CLI=""
if command -v docker >/dev/null 2>&1; then
    CONTAINER_CLI=docker
elif command -v podman >/dev/null 2>&1; then
    CONTAINER_CLI=podman
else
    log_warn "No container runtime found (docker/podman)"
    wait $LOADER_PID
    exit 0
fi

log_info "Using container runtime: $CONTAINER_CLI"

$CONTAINER_CLI pull alpine:latest >/dev/null 2>&1 || log_warn "Failed to pull alpine image"

log_info "Starting container: $CONTAINER_NAME"
if ! $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm alpine:latest sleep 300 >/dev/null 2>&1; then
    log_err "Failed to start container"
    exit 1
fi
log_info "Container started"

# 5. Perform file operations in container
log_info "Performing file operations in container"
$CONTAINER_CLI exec "$CONTAINER_NAME" sh -c "
    echo 'test content' > /tmp/test1.txt &&
    echo 'more data' > /tmp/test2.txt &&
    ls -la /tmp &&
    cat /tmp/test1.txt > /dev/null &&
    cat /tmp/test2.txt > /dev/null
" >/dev/null 2>&1 || log_warn "Some container operations failed"

sleep 2
log_info "File operations completed"

# 6. Check securityfs
if [ -d "/sys/kernel/security/bpfima/containers" ]; then
    CONTAINER_COUNT=$(ls -1 /sys/kernel/security/bpfima/containers/ 2>/dev/null | wc -l)
    log_info "Containers tracked in securityfs: $CONTAINER_COUNT"
else
    log_warn "securityfs directory not found"
fi

# 7. Stop container
log_info "Stopping container"
$CONTAINER_CLI stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
log_info "Container stopped"

# 8. Display summary
log_info "Test completed successfully"
log_info "Check logs with: dmesg | grep bpfima"

# Show recent kernel messages
if dmesg | grep -q bpfima; then
    log_info "Recent kernel messages:"
    dmesg | grep bpfima | tail -10
fi

# Wait a moment for any final events
sleep 2

log_info "Test finished - press Ctrl+C to cleanup and exit"
log_info "Monitoring mode active... (loader PID: $LOADER_PID)"

# Wait indefinitely until interrupted
wait
