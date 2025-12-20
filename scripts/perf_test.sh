#!/bin/bash

# scripts/perf_test.sh

source ./scripts/test_utils.sh > /dev/null 2>&1

BUILD_DIR=$(pwd)/build

# --- Compilation ---
# Compile Exec test binary
cat <<EOF > /tmp/test_binary.c
#include <stdio.h>
int main() { return 0; }
EOF
gcc /tmp/test_binary.c -o /tmp/test_binary > /dev/null 2>&1

# Compile Socket test binary
cat <<EOF > /tmp/socket_test_binary.c
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    
    // We don't care if it succeeds or fails, just that it triggers the hook
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        return 1;
    }
    
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    close(sock);
    return 0;
}
EOF
gcc /tmp/socket_test_binary.c -o /tmp/socket_test_binary > /dev/null 2>&1


# --- Helpers ---
cleanup_bpf() {
    sudo "$BUILD_DIR/bpfima-tool" unload lsm_bprm_check_security > /dev/null 2>&1
    sudo "$BUILD_DIR/bpfima-tool" unload lsm_socket_connect > /dev/null 2>&1
    
    # Force kill any lingering bpfima-tool processes
    sudo pkill -f "bpfima-tool" > /dev/null 2>&1 || true
    
    if lsmod | grep -q "^bpfima "; then
        sudo rmmod bpfima > /dev/null 2>&1
    fi
    
    sudo rm -f /sys/fs/bpf/bpfima_policy_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/bpfima_cgroup_patterns_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/bpfima_path_patterns_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/bpfima_hook_config_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/scratch_buf_map 2>/dev/null || true
}

load_bpf_hook() {
    local hook_obj=$1
    
    # Ensure module loaded
    if ! lsmod | grep -q "^bpfima "; then
        sudo insmod $BUILD_DIR/bpfima.ko > /dev/null 2>&1
        if ! wait_for_module bpfima 5 > /dev/null 2>&1; then echo "Module load failed"; exit 1; fi
        if ! wait_for_securityfs bpfima 5 > /dev/null 2>&1; then echo "SecurityFS failed"; exit 1; fi
    fi
    
    # Load hook
    if ! sudo "$BUILD_DIR/bpfima-tool" load "$hook_obj" -d > /dev/null 2>&1; then
        echo "Tool load failed for $hook_obj"
        exit 1
    fi
    sudo "$BUILD_DIR/bpfima-tool" policy-init > /dev/null 2>&1
}

measure_cmd() {
    local cmd=$1
    local type=$2
    local phase=$3
    
    start_time=$(date +%s%N)
    $cmd > /dev/null 2>&1
    end_time=$(date +%s%N)
    total_time=$(($end_time - $start_time))
    
    echo "Type: $type | Phase: $phase | Time: $total_time ns"
}

# --- PROCESS EXECUTION TEST ---
cleanup_bpf
# 1. Warmup (3 runs)
for i in {1..3}; do sudo /tmp/test_binary > /dev/null 2>&1; done
# 2. Baseline Measure
measure_cmd "sudo /tmp/test_binary" "Exec" "Baseline"

# 3. Load BPF (Cold)
load_bpf_hook "$BUILD_DIR/lsm_bprm_check_security.o"
measure_cmd "sudo /tmp/test_binary" "Exec" "BPF_First"

# 4. Run Again (Warm)
# 4. Run Again (Warm)
# Intermediate warmup to ensure stability
for i in {1..3}; do sudo /tmp/test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/test_binary" "Exec" "BPF_Second"


# --- SOCKET CONNECT TEST ---
cleanup_bpf
# 1. Warmup (3 runs)
for i in {1..3}; do sudo /tmp/socket_test_binary > /dev/null 2>&1; done
# 2. Baseline Measure
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "Baseline"

# 3. Load BPF (Cold)
load_bpf_hook "$BUILD_DIR/lsm_socket_connect.o"
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "BPF_First"

# 4. Run Again (Warm)
# Intermediate warmup to ensure stability
for i in {1..3}; do sudo /tmp/socket_test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "BPF_Second"

# final cleanup
cleanup_bpf
rm -f /tmp/test_binary /tmp/test_binary.c /tmp/socket_test_binary /tmp/socket_test_binary.c