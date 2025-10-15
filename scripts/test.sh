#!/bin/bash
# Minimal eBPF test script

set -e

# Default values
VERBOSE=false
BPF_OBJECT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
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

# Wait
wait $LOADER_PID
