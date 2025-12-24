#!/bin/bash

source ./scripts/test_utils.sh > /dev/null 2>&1

BUILD_DIR=$(pwd)/build

cat <<EOF > /tmp/test_binary.c
#include <stdio.h>
int main() { return 0; }
EOF
gcc /tmp/test_binary.c -o /tmp/test_binary > /dev/null 2>&1

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
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        return 1;
    }
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    close(sock);
    return 0;
}
EOF
gcc /tmp/socket_test_binary.c -o /tmp/socket_test_binary > /dev/null 2>&1

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
    local map_id=$3
    sudo bpftool map dump pinned /sys/fs/bpf/bpf_timing_stats -j > /tmp/map_dump.json 2>&1
    if [ -s /tmp/map_dump.json ]; then
        cat /tmp/map_dump.json | python3 scripts/parse_map.py "$type" "$phase" "$map_id"
    else
        echo "# Failed to dump map or map empty"
    fi
}

cleanup_bpf "$BUILD_DIR"

for i in {1..3}; do sudo /tmp/test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/test_binary" "Exec" "Baseline"

load_bpf_hook "$BUILD_DIR/lsm_bprm_check_security.o" "$BUILD_DIR"
measure_cmd "sudo /tmp/test_binary" "Exec" "BPF_First"
collect_bpf_stats "Exec" "BPF_First" 0

for i in {1..3}; do sudo /tmp/test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/test_binary" "Exec" "BPF_Second"
collect_bpf_stats "Exec" "BPF_Second" 0

cleanup_bpf "$BUILD_DIR"

for i in {1..3}; do sudo /tmp/socket_test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "Baseline"

load_bpf_hook "$BUILD_DIR/lsm_socket_connect.o" "$BUILD_DIR"
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "BPF_First"
collect_bpf_stats "Socket" "BPF_First" 1

for i in {1..3}; do sudo /tmp/socket_test_binary > /dev/null 2>&1; done
measure_cmd "sudo /tmp/socket_test_binary" "Socket" "BPF_Second"
collect_bpf_stats "Socket" "BPF_Second" 1

cleanup_bpf "$BUILD_DIR"
rm -f /tmp/test_binary /tmp/test_binary.c /tmp/socket_test_binary /tmp/socket_test_binary.c