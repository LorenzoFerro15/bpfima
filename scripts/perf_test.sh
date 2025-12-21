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
    sudo rm -f /sys/fs/bpf/bpf_timing_stats 2>/dev/null || true
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

collect_bpf_stats() {
    local type=$1
    local phase=$2
    local map_id=$3 # 0 for BPRM, 1 for SOCKET

    echo "Collecting stats for $type $phase (Index $map_id)..." >&2

    # Dump map elements. We use -j for JSON output
    # The map key is u32, value is struct hook_timing (6 u64s = 48 bytes)
    # However, bpftool map dump output looks like:
    # [{ "key": 0, "value": { "total_time": 123, ... } }, ...]
    # We filter by key using jq or just grep/awk if jq isn't available. 
    # Let's assume jq is not available and do rough parsing or use bpftool's ability to lookup by key if supported cleanly.
    # Actually, dumping the whole map and parsing is easier.
    
    # We need to map struct fields to offsets or use JSON if available.
    # Let's try JSON with a python one-liner, assuming python3 is available since we have a python script.
    
    sudo bpftool map dump pinned /sys/fs/bpf/bpf_timing_stats -j > /tmp/map_dump.json 2>&1
    if [ -s /tmp/map_dump.json ]; then
        cat /tmp/map_dump.json | python3 scripts/parse_map.py "$type" "$phase" "$map_id"
    else
        echo "# Failed to dump map or map empty"
    fi
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
collect_bpf_stats "Exec" "BPF_First" 0

# 4. Run Again (Warm)
# Intermediate warmup to ensure stability
for i in {1..3}; do sudo /tmp/test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/test_binary" "Exec" "BPF_Second"
collect_bpf_stats "Exec" "BPF_Second" 0


# --- SOCKET CONNECT TEST ---
cleanup_bpf
# 1. Warmup (3 runs)
for i in {1..3}; do sudo /tmp/socket_test_binary > /dev/null 2>&1; done
# 2. Baseline Measure
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "Baseline"

# 3. Load BPF (Cold)
load_bpf_hook "$BUILD_DIR/lsm_socket_connect.o"
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "BPF_First"
collect_bpf_stats "Socket" "BPF_First" 1

# 4. Run Again (Warm)
# Intermediate warmup to ensure stability
for i in {1..3}; do sudo /tmp/socket_test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "BPF_Second"
collect_bpf_stats "Socket" "BPF_Second" 1

# final cleanup
cleanup_bpf
rm -f /tmp/test_binary /tmp/test_binary.c /tmp/socket_test_binary /tmp/socket_test_binary.c