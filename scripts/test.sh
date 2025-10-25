#!/bin/bash
# Minimal eBPF test script

set -e

# Default values
BPF_CONTAINER=false
VERBOSE=false
BPF_OBJECT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --container|--with-container)
            BPF_CONTAINER=true
            shift
            ;;
        *.o)
            BPF_OBJECT="$1"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [BPF_OBJECT]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v     Enable verbose output with detailed insights"
            echo "  --help, -h        Show this help message"
            echo ""
            echo "Arguments:"
            echo "  BPF_OBJECT        Path to .o file (default: build/lsm_mmap_file.o)"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 --verbose"
            echo "  $0 build/kprobe_file_open.o"
            echo "  $0 --verbose build/lsm_file_open.o"
            echo "  $0 --container    Run a lightweight container and execute commands inside it"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Must run as root"
    exit 1
fi

# Get paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

cd "$PROJECT_ROOT"

# Set default BPF object if not specified
if [ -z "$BPF_OBJECT" ]; then
    BPF_OBJECT="$BUILD_DIR/lsm_mmap_file.o"
fi

# Validate BPF object path
if [[ ! "$BPF_OBJECT" = /* ]]; then
    # Relative path, prepend PROJECT_ROOT
    BPF_OBJECT="$PROJECT_ROOT/$BPF_OBJECT"
fi

# Cleanup function
cleanup() {
    if $VERBOSE; then
        echo ""
        echo "=== Cleanup ==="
    fi
    echo "Cleaning up..."
    pkill -f "$BUILD_DIR/loader" 2>/dev/null || true
    if $VERBOSE; then
        echo "  Stopped loader process"
    fi
    if lsmod | grep -q "^bpfima "; then
        rmmod bpfima 2>/dev/null || true
        if $VERBOSE; then
            echo "  Removed kernel module"
        fi
    fi
    # Ensure test container is removed if it exists
    CONTAINER_NAME="bpfima_test_container"
    if command -v docker >/dev/null 2>&1; then
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    if command -v podman >/dev/null 2>&1; then
        podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    echo "Done"
}
trap cleanup EXIT INT TERM

# Build
echo "Building..."
if $VERBOSE; then
    echo "=== Build output ==="
    make all
    echo ""
else
    make all > /dev/null 2>&1 || { echo "Build failed"; exit 1; }
fi

if $VERBOSE; then
    echo "✓ Build successful"
    echo ""
fi

# Load kernel module
echo "Loading kernel module..."
lsmod | grep -q "^bpfima " && rmmod bpfima 2>/dev/null
insmod "$BUILD_DIR/bpfima.ko" || { echo "Failed to load module"; exit 1; }

if $VERBOSE; then
    echo "✓ Module loaded"
    lsmod | grep bpfima
    echo ""
    echo "=== Module info ==="
    modinfo "$BUILD_DIR/bpfima.ko" | head -5
    echo ""
fi

# Validate BPF object exists
if [ ! -f "$BPF_OBJECT" ]; then
    echo "Error: BPF object not found: $BPF_OBJECT"
    echo "Available objects in build/:"
    ls -1 "$BUILD_DIR"/*.o 2>/dev/null || echo "  (none found)"
    exit 1
fi

# Start eBPF program
echo "Starting eBPF monitor..."
if $VERBOSE; then
    echo "Target: $BPF_OBJECT"
    echo "=== Loader output ==="
fi
"$BUILD_DIR/loader" "$BPF_OBJECT" &
LOADER_PID=$!
sleep 2

# Check if still running
if ! kill -0 $LOADER_PID 2>/dev/null; then
    echo "Error: Loader died"
    exit 1
fi

echo "✓ Running (PID: $LOADER_PID)"
echo "Loaded: $(basename "$BPF_OBJECT")"

if $VERBOSE; then
    echo ""
    echo "=== System info ==="
    echo "BPF object: $BPF_OBJECT"
    echo "Trace output: /sys/kernel/debug/tracing/trace_pipe"
    echo "Kernel messages: dmesg | grep bpfima"
    echo "Loaded programs: bpftool prog list"
    echo ""
    echo "=== Recent trace (last 5 lines) ==="
    tail -5 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "  (no trace data yet)"
    echo ""
fi

echo "Press Ctrl-C to stop"
echo ""

# Test actions for lsm_file_post_open if the loaded object is lsm_file_post_open.o
if [[ "$(basename "$BPF_OBJECT")" == "lsm_file_post_open.o" ]]; then
    echo "=== Running test actions for lsm_file_post_open ==="
    
    # Create a test directory and files
    TEST_DIR="/home/lo/bpfima_test"
    mkdir -p "$TEST_DIR"
    
    echo "Creating test files to trigger file_post_open hash measurements..."
    
    # Create a test executable file (5KB - within the size range)
    TEST_EXEC="$TEST_DIR/test_exec.sh"
    echo "#!/bin/bash" > "$TEST_EXEC"
    echo "echo 'This is a test executable'" >> "$TEST_EXEC"
    # Pad the file to make it larger than 4KB
    head -c 5000 /dev/zero | tr '\0' 'A' >> "$TEST_EXEC"
    chmod +x "$TEST_EXEC"
    
    # Create another test file (8KB)
    TEST_FILE="$TEST_DIR/test_binary"
    dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=8 2>/dev/null
    chmod +x "$TEST_FILE"
    
    echo "  Created test files in $TEST_DIR"
    sleep 1
    
    echo ""
    echo "Triggering hash measurements by executing test files..."
    
    # Execute the test script (this should trigger lsm_file_post_open with MAY_EXEC)
    echo "  1. Executing $TEST_EXEC"
    "$TEST_EXEC" 2>/dev/null || true
    sleep 1
    
    # Try to execute the binary (will fail but should trigger the hook)
    echo "  2. Executing $TEST_FILE"
    "$TEST_FILE" 2>/dev/null || true
    sleep 1
    
    # Open files in read mode with exec permissions
    echo "  3. Opening files with various methods"
    # Use cat to open and read the files
    cat "$TEST_EXEC" > /dev/null 2>&1 || true
    sleep 0.5
    cat "$TEST_FILE" > /dev/null 2>&1 || true
    sleep 0.5
    
    # Try opening with exec command
    echo "  4. Using exec to open files"
    bash -c "exec 3< '$TEST_EXEC'; exec 3<&-" 2>/dev/null || true
    sleep 0.5
    
    echo ""
    echo "Test actions completed. Check trace output:"
    echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
    echo "  or: sudo dmesg | grep -i 'bpf\|ima\|hash'"
    echo ""
    
    # Show recent trace output if verbose
    if $VERBOSE; then
        echo "=== Recent trace output (last 30 lines) ==="
        tail -30 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "  (no trace data available)"
        echo ""
    fi
    
    echo "Cleaning up test files..."
    rm -rf "$TEST_DIR"
    echo "  Removed $TEST_DIR"
    echo ""
fi

echo "Press Ctrl-C to stop monitoring"

# If requested, run a lightweight container, exec commands inside it, then stop/remove it
run_container() {
    CONTAINER_NAME="bpfima_test_container"

    # pick docker or podman
    if command -v docker >/dev/null 2>&1; then
        CONTAINER_CLI=docker
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_CLI=podman
    else
        echo "No container runtime found (docker or podman). Skipping container test."
        return 0
    fi

    echo "[container] Using runtime: $CONTAINER_CLI"

    # Pull a small image
    echo "[container] Pulling alpine image..."
    $CONTAINER_CLI pull alpine:latest >/dev/null 2>&1 || true

    # Run container in background
    echo "[container] Starting container: $CONTAINER_NAME"
    $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm alpine:latest sleep 300 >/dev/null
    if [ $? -ne 0 ]; then
        echo "[container] Failed to start container"
        return 1
    fi

    # Exec some lightweight commands
    echo "[container] Executing commands inside container"
    $CONTAINER_CLI exec "$CONTAINER_NAME" sh -c "echo 'hello from container' > /tmp/hello && ls -la /tmp && cat /etc/os-release" || true

    # Wait a moment then stop the container
    sleep 1
    echo "[container] Stopping container"
    $CONTAINER_CLI stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    echo "[container] Done"
}

if $BPF_CONTAINER; then
    run_container || echo "Container test failed"
fi

# Wait
wait $LOADER_PID
