

echo "eBPF kprobe demo - Testing kfunc.o with do_unlinkat"
echo "=================================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)"
   exit 1
fi

echo "1. Loading eBPF program..."
./loader &
LOADER_PID=$!

# Wait a moment for the program to load
sleep 2

echo "2. Triggering some unlink operations to test the kprobe..."
# Create and delete some test files to trigger do_unlinkat
mkdir -p /tmp/bpf_test
touch /tmp/bpf_test/test1.txt
touch /tmp/bpf_test/test2.txt
rm /tmp/bpf_test/test1.txt
rm /tmp/bpf_test/test2.txt
rmdir /tmp/bpf_test

echo "3. Check the trace output in another terminal with:"
echo "   sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
echo "4. The loader is running in background (PID: $LOADER_PID)"
echo "   Press Ctrl+C to stop it when you're done testing."

# Wait for loader or Ctrl+C
wait $LOADER_PID
echo "Loader stopped."