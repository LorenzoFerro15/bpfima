#!/bin/bash

# Live monitoring script for eBPF file operations

echo "=== Live eBPF File Monitoring ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

# Check if programs are built
if [ ! -f "kfunc_simple.o" ] || [ ! -f "loader_simple" ]; then
    echo "Building programs..."
    make kfunc_simple.o loader_simple
fi

echo "Starting live file monitoring..."
echo "This will show file unlink operations in real-time."
echo "Open another terminal and try: rm /tmp/test.txt"
echo "Press Ctrl+C to stop monitoring"
echo ""

# Clear trace buffer
echo > /sys/kernel/debug/tracing/trace

# Start loader in background
./loader_simple &
LOADER_PID=$!

# Give it time to attach
sleep 2

echo "=== Monitoring started - watching for file operations ==="
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping monitoring..."
    kill $LOADER_PID 2>/dev/null
    wait $LOADER_PID 2>/dev/null
    echo "Cleanup completed."
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Monitor trace output in real-time
cat /sys/kernel/debug/tracing/trace_pipe