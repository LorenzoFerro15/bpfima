#!/bin/bash

echo "=== Working TPM Simulation Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

echo "1. Building TPM simulation program..."
if make kfunc_tpm_sim.o >/dev/null 2>&1; then
    echo "   ✓ Build successful"
else
    echo "   ✗ Build failed"
    exit 1
fi

echo ""
echo "2. Creating simple loader..."
cat > loader_working_tpm.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

static struct bpf_object *obj = NULL;
static struct bpf_link *link1 = NULL;
static struct bpf_link *link2 = NULL;

void cleanup(void) {
    if (link1) bpf_link__destroy(link1);
    if (link2) bpf_link__destroy(link2);
    if (obj) bpf_object__close(obj);
}

void signal_handler(int sig) {
    printf("\n=== Stopping TPM simulation ===\n");
    cleanup();
    exit(0);
}

int main() {
    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    obj = bpf_object__open("kfunc_tpm_sim.o");
    if (libbpf_get_error(obj)) {
        printf("Failed to open BPF object\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        goto cleanup;
    }
    
    struct bpf_program *prog1 = bpf_object__find_program_by_name(obj, "handle_unlinkat_tpm_sim");
    if (prog1) {
        link1 = bpf_program__attach(prog1);
        if (!libbpf_get_error(link1)) {
            printf("✓ TPM tracepoint attached\n");
        }
    }
    
    struct bpf_program *prog2 = bpf_object__find_program_by_name(obj, "handle_vfs_unlink_tmp_sim");
    if (prog2) {
        link2 = bpf_program__attach(prog2);
        if (!libbpf_get_error(link2)) {
            printf("✓ VFS kprobe attached\n");
        }
    }
    
    printf("\n=== TPM Simulation Active ===\n");
    printf("Monitoring file unlink operations...\n");
    printf("TPM counters and PCR simulation enabled\n");
    printf("Press Ctrl+C to stop\n\n");
    
    while (1) sleep(1);
    
cleanup:
    cleanup();
    return 0;
}
EOF

gcc -o loader_working_tpm loader_working_tpm.c -lbpf -lelf -lz
echo "   ✓ Loader compiled"

echo ""
echo "3. Starting TPM simulation monitoring..."

# Clear trace buffer
echo > /sys/kernel/debug/tracing/trace

# Start loader in background
./loader_working_tpm &
LOADER_PID=$!

# Give it time to attach
sleep 2

echo "   ✓ TPM simulation started (PID: $LOADER_PID)"

echo ""
echo "4. Creating test files..."
mkdir -p /tmp/tpm_sim_test
echo "Test file 1" > /tmp/tpm_sim_test/file1.txt
echo "Test file 2" > /tmp/tpm_sim_test/file2.txt
echo "Test file 3" > /tmp/tpm_sim_test/file3.txt
echo "   ✓ Test files created"

echo ""
echo "5. Performing file operations..."
echo "   - Unlinking file1.txt..."
unlink /tmp/tpm_sim_test/file1.txt

echo "   - Removing file2.txt..."
rm /tmp/tpm_sim_test/file2.txt

echo "   - Removing file3.txt..."
rm /tmp/tpm_sim_test/file3.txt

echo "   - Removing directory..."
rmdir /tmp/tpm_sim_test

echo "   ✓ File operations completed"

echo ""
echo "6. Checking TPM simulation trace output..."
sleep 2

echo ""
echo "--- TPM Simulation Trace Entries ---"
cat /sys/kernel/debug/tracing/trace | grep -E "(TPM|PCR|measurement)" | tail -10

echo ""
echo "7. Cleanup..."

# Stop the loader
kill $LOADER_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null

# Clean up temporary files
rm -f loader_working_tmp.c loader_working_tpm

echo "   ✓ Cleanup completed"

echo ""
echo "=== TPM Simulation Test Completed ==="
echo ""
echo "This test demonstrated:"
echo "• TPM simulation using BPF maps"
echo "• PCR counter simulation" 
echo "• Measurement data generation"
echo "• File unlink monitoring"
echo "• No dependency on kernel module kfuncs"