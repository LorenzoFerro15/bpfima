#!/bin/bash

echo "=== Quick TPM eBPF Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

echo "✓ TPM devices found:"
ls -la /dev/tpm*

echo ""
echo "✓ Kernel module already loaded:"
lsmod | grep hello

echo ""
echo "Building TPM loader..."
cat > loader_tpm_quick.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

static struct bpf_object *obj = NULL;
static struct bpf_link *link = NULL;

void cleanup(void) {
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
}

void signal_handler(int sig) {
    printf("\nStopping TPM monitoring...\n");
    cleanup();
    exit(0);
}

int main() {
    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    signal(SIGINT, signal_handler);
    
    obj = bpf_object__open("kfunc_tpm.o");
    if (libbpf_get_error(obj)) {
        printf("Failed to open BPF object\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        goto cleanup;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_unlinkat_tpm");
    if (!prog) {
        printf("Failed to find program\n");
        goto cleanup;
    }
    
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        printf("Failed to attach program\n");
        goto cleanup;
    }
    
    printf("TPM-enhanced eBPF monitoring active!\n");
    printf("Try: rm /tmp/test_file.txt (in another terminal)\n");
    printf("Press Ctrl+C to stop\n\n");
    
    while (1) sleep(1);
    
cleanup:
    cleanup();
    return 0;
}
EOF

gcc -o loader_tpm_quick loader_tpm_quick.c -lbpf -lelf -lz

echo "✓ TPM loader compiled"

echo ""
echo "Starting TPM monitoring (Press Ctrl+C to stop)..."
echo "Open another terminal and run: sudo rm /tmp/test_file.txt"
echo "Then check: sudo cat /sys/kernel/debug/tracing/trace_pipe | grep TPM"
echo ""

# Clear trace buffer
echo > /sys/kernel/debug/tracing/trace

# Create a test file
echo "Test content" > /tmp/test_file.txt

echo "Created test file: /tmp/test_file.txt"
echo "Remove it to see TPM monitoring in action!"
echo ""

./loader_tpm_quick