#!/bin/bash

# Comprehensive eBPF TPM test script
# This script builds, loads, tests, and monitors the eBPF TPM functionality

echo "=== eBPF TPM Test Script ==="
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
    # Kill any running loader processes
    pkill -f "loader" 2>/dev/null
    # Remove kernel module if loaded
    rmmod hello 2>/dev/null
    echo "Cleanup completed."
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM EXIT

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
rmmod hello 2>/dev/null || true
if insmod hello.ko; then
    echo "   ✓ Kernel module loaded"
else
    echo "   ✗ Failed to load kernel module"
    exit 1
fi

echo ""
echo "3. Clearing trace buffer..."
echo > /sys/kernel/debug/tracing/trace

echo ""
echo "4. Starting eBPF loader with kfunc_tpm.o..."
if ./loader kfunc_tpm.o &
then
    LOADER_PID=$!
    echo "   ✓ Loader started (PID: $LOADER_PID)"
    # Give loader time to attach
    sleep 2
else
    echo "   ✗ Failed to start loader"
    exit 1
fi

echo ""
echo "5. Testing file operations..."
echo "   Creating test file..."
echo "Test data for eBPF monitoring" > /tmp/ebpf_test_file.txt
ls -la /tmp/ebpf_test_file.txt

echo "   Removing test file..."
rm -f /tmp/ebpf_test_file.txt

echo "   Waiting for eBPF events to be processed..."
sleep 2

echo ""
echo "6. Stopping loader..."
kill $LOADER_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null

echo ""
echo "7. Displaying trace output (last 30 lines)..."
echo "==================== TRACE OUTPUT ===================="
tail -30 /sys/kernel/debug/tracing/trace
echo "====================== END TRACE ======================"

echo ""
echo "8. Displaying kernel messages (dmesg)..."
echo "==================== DMESG OUTPUT ===================="
dmesg | tail -30
echo "====================== END DMESG ======================"

echo ""
echo "=== Test completed successfully ==="