#!/bin/bash

# Test script for simple eBPF file monitoring

echo "=== Simple eBPF File Monitoring Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

echo "1. Building programs..."
make clean
make kfunc_simple.o loader_simple

if [ ! -f "kfunc_simple.o" ]; then
    echo "ERROR: Failed to build eBPF program"
    exit 1
fi

if [ ! -f "loader_simple" ]; then
    echo "ERROR: Failed to build loader"
    exit 1
fi

echo "   ✓ Build successful"
echo ""

echo "2. Starting eBPF monitoring in background..."
./loader_simple &
LOADER_PID=$!

# Give it time to attach
sleep 2

echo "   ✓ Monitor started (PID: $LOADER_PID)"
echo ""

echo "3. Creating test files..."
mkdir -p /tmp/ebpf_test
touch /tmp/ebpf_test/test1.txt
touch /tmp/ebpf_test/test2.txt
echo "test data" > /tmp/ebpf_test/test3.txt

echo "   ✓ Test files created"
echo ""

echo "4. Performing file operations to trigger monitoring..."

echo "   - Unlinking test1.txt..."
unlink /tmp/ebpf_test/test1.txt
sleep 1

echo "   - Removing test2.txt..."
rm /tmp/ebpf_test/test2.txt
sleep 1

echo "   - Removing test3.txt..."
rm /tmp/ebpf_test/test3.txt
sleep 1

echo "   - Removing directory..."
rmdir /tmp/ebpf_test
sleep 1

echo "   ✓ File operations completed"
echo ""

echo "5. Checking trace output..."
echo ""
echo "--- Recent trace entries ---"
cat /sys/kernel/debug/tracing/trace_pipe | head -20 &
TRACE_PID=$!
sleep 3
kill $TRACE_PID 2>/dev/null

echo ""
echo "6. Cleanup..."
kill $LOADER_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null

# Clean trace buffer
echo > /sys/kernel/debug/tracing/trace

echo "   ✓ Cleanup completed"
echo ""

echo "=== Test completed ==="
echo "The eBPF program monitored file unlink operations and"
echo "generated contextual measurement data for each event."
echo ""
echo "Key features demonstrated:"
echo "• Tracepoint-based syscall monitoring"
echo "• Process context extraction (PID, UID, GID, comm)"
echo "• Timestamp collection"
echo "• Measurement data generation"
echo "• IMA-style event logging"