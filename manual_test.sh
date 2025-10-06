#!/bin/bash

# Modified test script that keeps eBPF running for manual testing

echo "=== eBPF LSM Manual Test Script ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    
    # Kill the specific loader process if we have its PID
    if [ ! -z "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        echo "   Stopping loader_tpm (PID: $LOADER_PID)..."
        kill -TERM "$LOADER_PID" 2>/dev/null
        wait "$LOADER_PID" 2>/dev/null
        echo "   ✓ Loader stopped"
    fi
    
    # Kill any remaining loader processes as fallback
    pkill -f "loader_tpm" 2>/dev/null || true
    
    # Remove kernel module if loaded
    if lsmod | grep -q "^bpfima "; then
        echo "   Removing kernel module..."
        rmmod bpfima 2>/dev/null && echo "   ✓ Module removed" || echo "   Failed to remove module"
    fi
    
    echo "Cleanup completed."
}

# Initialize LOADER_PID to empty
LOADER_PID=""

echo "1. Building all components..."
if make all; then
    echo "   ✓ Build successful"
else
    echo "   ✗ Build failed"
    exit 1
fi

echo ""
echo "2. Loading kernel module..."
# Remove module if already loaded
rmmod bpfima 2>/dev/null || true
if insmod bpfima.ko; then
    echo "   ✓ Kernel module loaded"
else
    echo "   ✗ Failed to load kernel module"
    exit 1
fi

echo " === LOADED SECURITYFS ==="
cat /sys/kernel/security/bpfima/status 2>/dev/null || echo "Status file not available"
cat /sys/kernel/security/bpfima/measurement 2>/dev/null || echo "Measurement file not available"

echo ""
echo "3. Clearing trace buffer..."
echo > /sys/kernel/debug/tracing/trace

echo ""
echo "4. Starting eBPF TPM loader..."
./loader_tpm &
LOADER_PID=$!

# Wait for the loader to fully initialize and attach programs
echo "   Waiting for eBPF programs to load and attach..."
sleep 3

# Check if loader is still running
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "   ✗ Loader process died after startup"
    exit 1
fi

echo "   ✓ Loader initialized (PID: $LOADER_PID)"

echo ""
echo "=== eBPF LSM Hook is now ACTIVE ==="
echo ""
echo "Triggering some file operations to test the hook..."

# Create some test files and operations that should trigger mmap
echo "Creating test file..."
echo "test content for mmap" > /tmp/test_mmap.txt

echo "Running executable (should trigger mmap of binary)..."
/bin/cat /tmp/test_mmap.txt > /dev/null

echo "Reading with head (smaller binary)..."  
/usr/bin/head -1 /tmp/test_mmap.txt > /dev/null

echo "Running bash script (should mmap libraries and executables)..."
/bin/bash -c 'echo "hello from bash"; cat /tmp/test_mmap.txt' > /dev/null

echo "Loading a library-heavy program..."
/usr/bin/python3 -c 'print("hello")' > /dev/null 2>&1 || echo "Python not available"

echo ""
echo "Checking trace output for LSM hook activity..."
echo "=== Recent trace output ==="
tail -10 /sys/kernel/debug/tracing/trace | grep "MMAP\|File\|inode" || echo "No LSM activity found in recent trace"
echo "==========================="

echo ""
echo "You can now:"
echo "  1. Monitor trace output in real-time (in another terminal):"
echo "     sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
echo "  2. Check recent trace entries:"
echo "     sudo tail -20 /sys/kernel/debug/tracing/trace"
echo ""
echo "  3. Trigger more operations (in another terminal):"
echo "     - /bin/bash -c 'echo hello'"
echo "     - cat /bin/bash > /dev/null"
echo "     - ls -la /usr/bin/ls"
echo ""
echo "Press Ctrl+C to stop and cleanup..."

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Keep running until interrupted
while true; do
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        echo "   ✗ Loader process died unexpectedly"
        break
    fi
    sleep 5
done