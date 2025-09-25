#!/bin/bash

echo "=== Testing eBPF with IMA Support ==="
echo "1. Loading eBPF program in background..."
sudo ./loader &
LOADER_PID=$!

echo "2. Waiting for program to attach..."
sleep 2

echo "3. Checking trace output (first 10 lines)..."
echo "Triggering file deletion to test kfuncs..."

touch /tmp/test1 /tmp/test2 /tmp/test3
rm /tmp/test1 /tmp/test2 /tmp/test3 

echo "4. Checking trace output:"
sudo timeout 5s cat /sys/kernel/debug/tracing/trace_pipe | grep -E "(IMA|bpf_strstr|Hello)" | head -5

echo "5. Stopping loader..."
sudo kill $LOADER_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null

echo "=== Test Complete ==="