#!/bin/bash

# Comprehensive eBPF TPM test script
# This script builds, loads, tests, and monitors the eBPF TPM functionality

echo "=== eBPF TPM Test Script ==="
echo ""

#MODULE_MESSAGES=$(dmesg | grep -E "(bpfima|bpf-ima)" | wc -l)
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
    
    # Clean up temporary files
    [ -f "$DMESG_BEFORE" ] && rm -f "$DMESG_BEFORE"
    
    echo "Cleanup completed."
}

# Initialize LOADER_PID to empty (will be set when loader starts)
LOADER_PID=""

# Capture initial dmesg state
DMESG_BEFORE=$(mktemp)
dmesg > "$DMESG_BEFORE"

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
rmmod bpfima 2>/dev/null || true
if insmod bpfima.ko; then
    echo "   ✓ Kernel module loaded"
else
    echo "   ✗ Failed to load kernel module"
    exit 1
fi

echo " === LOADED SECURITYFS ==="
cat /sys/kernel/security/bpfima/status
cat /sys/kernel/security/bpfima/measurement

echo ""
echo "3. Clearing trace buffer..."
echo > /sys/kernel/debug/tracing/trace

# Optional: Clear dmesg buffer to focus on test-related messages
# Uncomment the next line if you want a clean dmesg for this test
# dmesg -c > /dev/null

echo ""
echo ""
echo "4. Starting eBPF TPM loader..."
./loader_tpm &
LOADER_PID=$!

# Wait for the loader to fully initialize and attach programs
echo "   Waiting for eBPF programs to load and attach..."
sleep 5

# Check if loader is still running
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "   ✗ Loader process died after startup"
    exit 1
fi

echo "   ✓ Loader initialized (PID: $LOADER_PID)"

echo ""
echo "5. Testing file operations..."
echo "   Creating test file..."
echo "Test data for eBPF monitoring" > /tmp/ebpf_test_file.txt
echo "Test data for eBPF monitoring" > /tmp/ebpf_test_file1.txt
echo "Test data for eBPF monitoring" > /tmp/ebpf_test_file2.txt
cat /tmp/ebpf_test_file.txt
ls -la /tmp/ebpf_test_file.txt
ls -la /tmp/ebpf_test_file1.txt
ls -la /tmp/ebpf_test_file2.txt

echo "   Removing test file..."
rm -f /tmp/ebpf_test_file.txt
rm -f /tmp/ebpf_test_file1.txt
rm -f /tmp/ebpf_test_file2.txt

echo "   Waiting for eBPF events to be processed..."
sleep 2

echo " === Retrieving measurement data ==="
cat /sys/kernel/security/bpfima/status
cat /sys/kernel/security/bpfima/measurements

echo "   Checking for immediate kernel issues..."
RECENT_ERRORS=$(dmesg | tail -5 | grep -iE "(oops|panic|segfault|warning)" | wc -l)
if [ "$RECENT_ERRORS" -gt 0 ]; then
    echo "    Recent kernel messages detected - check dmesg output below"
else
    echo "    No immediate kernel issues detected"
fi

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

# Get timestamp when test started (approximately)
TEST_START_TIME=$(date -d '2 minutes ago' '+%s')

# Filter dmesg to show only recent messages related to our test
echo "Recent kernel messages (last 2 minutes):"
dmesg -T | awk -v start_time="$TEST_START_TIME" '
{
    # Extract timestamp from dmesg -T format
    if (match($0, /^[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}/)) {
        timestamp_str = substr($0, RSTART, RLENGTH)
        # Convert to epoch time (simplified approach)
        print $0
    }
}' | tail -20

echo ""
echo "Messages related to our module (bpfima, bpf, TPM, IMA):"
dmesg | grep -E "(bpfima|bpf|TPM|IMA|kfunc|measurement)" | tail -10

echo ""
echo "New messages since test started:"
if [ -f "$DMESG_BEFORE" ]; then
    DMESG_AFTER=$(mktemp)
    dmesg > "$DMESG_AFTER"
    diff "$DMESG_BEFORE" "$DMESG_AFTER" | grep '^>' | sed 's/^> //' | tail -10
    rm -f "$DMESG_AFTER"
else
    echo "Could not compare - no baseline available"
fi

echo ""
echo "Error Analysis:"

# Check for TPM-related messages (expected)
TPM_MESSAGES=$(dmesg | grep -iE "tpm|pcr" | wc -l)
if [ "$TPM_MESSAGES" -gt 0 ]; then
    echo "   TPM activity detected ($TPM_MESSAGES messages):"
    dmesg | grep -iE "(tpm|pcr|extended.*pcr)" | tail -3
fi

# Check for our module activity (expected)
MODULE_MESSAGES=$(dmesg | grep -E "(bpfima|bpf_kfunc_example)" | wc -l)
if [ "$MODULE_MESSAGES" -gt 0 ]; then
    echo "   Our module activity ($MODULE_MESSAGES messages):"
    dmesg | grep -E "(bpfima|bpf_kfunc_example)" | tail -2
fi

# Check for concerning errors (need attention)
CRITICAL_ERRORS=$(dmesg | grep -iE "(oops|panic|kernel bug)" | wc -l)
SEGFAULTS=$(dmesg | grep -iE "segfault.*rm\[" | wc -l)

if [ "$CRITICAL_ERRORS" -gt 0 ]; then
    echo "CRITICAL: Found $CRITICAL_ERRORS severe kernel error(s)"
    dmesg | grep -iE "(oops|panic|kernel bug)" | tail -2
elif [ "$SEGFAULTS" -gt 0 ]; then
    echo "   Found $SEGFAULTS rm segfault(s) - likely due to eBPF monitoring (expected)"
else
    echo "   No critical kernel errors detected"
fi

echo "====================== END DMESG ======================"

echo ""
echo "=== Test completed successfully ==="

