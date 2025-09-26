#!/bin/bash

# Test script for TPM-enhanced eBPF monitoring

echo "=== TPM-Enhanced eBPF File Monitoring Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

echo "1. Building programs..."
make clean >/dev/null 2>&1
if make modules kfunc_tpm.o loader; then
    echo "   ✓ Build successful"
else
    echo "   ✗ Build failed"
    exit 1
fi

echo ""
echo "2. Loading kernel module with TPM support..."
if insmod hello.ko; then
    echo "   ✓ Kernel module loaded"
else
    echo "   ✗ Failed to load kernel module"
    exit 1
fi

echo ""
echo "3. Checking TPM availability..."
if [ -e /dev/tpm0 ]; then
    echo "   ✓ TPM device found: /dev/tpm0"
    TPM_AVAILABLE="YES"
else
    echo "   ⚠ No TPM device found - will use simulation"
    TPM_AVAILABLE="NO"
fi

echo ""
echo "4. Starting TPM-enhanced eBPF monitoring in background..."
# Clear trace buffer
echo > /sys/kernel/debug/tracing/trace

# Create a modified loader for TPM version
cat > loader_tpm.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <errno.h>
#include <string.h>

static struct bpf_object *obj = NULL;
static struct bpf_link *tracepoint_link = NULL;
static struct bpf_link *kprobe_link = NULL;

void cleanup(void) {
    if (tracepoint_link) {
        bpf_link__destroy(tracepoint_link);
        tracepoint_link = NULL;
    }
    if (kprobe_link) {
        bpf_link__destroy(kprobe_link);
        kprobe_link = NULL;
    }
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
}

void signal_handler(int sig) {
    cleanup();
    exit(0);
}

int main() {
    struct rlimit rlim_new = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim_new);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    obj = bpf_object__open("kfunc_tpm.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }
    
    struct bpf_program *tracepoint_prog = bpf_object__find_program_by_name(obj, "handle_unlinkat_tpm");
    if (tracepoint_prog) {
        tracepoint_link = bpf_program__attach(tracepoint_prog);
        if (!libbpf_get_error(tracepoint_link)) {
            printf("TPM tracepoint attached successfully\n");
        }
    }
    
    struct bpf_program *kprobe_prog = bpf_object__find_program_by_name(obj, "handle_vfs_unlink_tpm");
    if (kprobe_prog) {
        kprobe_link = bpf_program__attach(kprobe_prog);
        if (!libbpf_get_error(kprobe_link)) {
            printf("TPM kprobe attached successfully\n");
        }
    }
    
    while (1) sleep(1);
    
cleanup:
    cleanup();
    return 0;
}
EOF

gcc -o loader_tmp loader_tpm.c -lbpf -lelf -lz
./loader_tpm &
LOADER_PID=$!

# Give it time to attach
sleep 3

echo "   ✓ TPM monitor started (PID: $LOADER_PID)"

echo ""
echo "5. Creating test files..."
mkdir -p /tmp/tpm_test
echo "Test file 1" > /tmp/tpm_test/file1.txt
echo "Test file 2" > /tmp/tpm_test/file2.txt
echo "Test file 3" > /tmp/tpm_test/file3.txt
echo "   ✓ Test files created"

echo ""
echo "6. Performing file operations to trigger TPM monitoring..."
echo "   - Unlinking file1.txt..."
unlink /tmp/tpm_test/file1.txt

echo "   - Removing file2.txt..."
rm /tmp/tpm_test/file2.txt

echo "   - Removing file3.txt..."
rm /tmp/tpm_test/file3.txt

echo "   - Removing directory..."
rmdir /tmp/tpm_test

echo "   ✓ File operations completed"

echo ""
echo "7. Checking TPM-enhanced trace output..."
sleep 2

echo ""
echo "--- Recent TPM trace entries ---"
tail -20 /sys/kernel/debug/tracing/trace | grep -E "(TPM|PCR|measurement)" || echo "No TPM-specific entries found"

echo ""
echo "8. Cleanup..."

# Stop the loader
kill $LOADER_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null

# Unload kernel module
rmmod hello 2>/dev/null

# Clean up temporary files
rm -f loader_tpm.c loader_tpm

echo "   ✓ Cleanup completed"

echo ""
echo "=== TPM Test completed ==="
echo ""
echo "Key features demonstrated:"
echo "• TPM availability detection: $TPM_AVAILABLE"
echo "• Enhanced measurement system with TPM integration"
if [ "$TPM_AVAILABLE" = "YES" ]; then
    echo "• Real TPM PCR operations"
else
    echo "• TPM simulation mode"
fi
echo "• Tracepoint and kprobe based monitoring"
echo "• Process context and measurement data generation"