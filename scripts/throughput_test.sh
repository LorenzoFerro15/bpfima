#!/bin/bash

source ./scripts/test_utils.sh > /dev/null 2>&1

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <exec|socket> <count>"
    exit 1
fi

MODE=$1
COUNT=$2

BUILD_DIR=$(pwd)/build
mkdir -p /tmp/bpf_throughput

compile_exec_binaries() {
    for i in {1..10}; do
        cat <<EOF > /tmp/bpf_throughput/exec_test_$i.c
#include <stdio.h>
int main() { return 0; }
EOF
        gcc /tmp/bpf_throughput/exec_test_$i.c -o /tmp/bpf_throughput/exec_test_$i > /dev/null 2>&1
    done
}

compile_socket_binary() {
    cat <<EOF > /tmp/bpf_throughput/socket_test.c
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
    gcc /tmp/bpf_throughput/socket_test.c -o /tmp/bpf_throughput/socket_test > /dev/null 2>&1
}

run_exec_workload() {
    for i in {1..10}; do
        for ((j=1; j<=COUNT; j++)); do
            /tmp/bpf_throughput/exec_test_$i > /dev/null 2>&1 &
        done
    done
    wait
}

run_socket_workload() {
    for i in {1..10}; do
        for ((j=1; j<=COUNT; j++)); do
           /tmp/bpf_throughput/socket_test > /dev/null 2>&1 &
        done
    done
    wait
}

measure_and_report() {
    local type=$1
    local phase=$2
    local workload_func=$3
    
    start_time=$(date +%s%N)
    $workload_func
    end_time=$(date +%s%N)
    
    total_time=$((end_time - start_time))
    total_calls=$((10 * COUNT)) # Both workloads do 10 * COUNT calls
    
    echo "Type: $type | Phase: $phase | Count: $total_calls | Time: $total_time ns"
}

run_full_exec_test() {
    compile_exec_binaries
    
    # Load BPF immediately
    cleanup_bpf "$BUILD_DIR"
    load_bpf_hook "$BUILD_DIR/lsm_bprm_check_security.o" "$BUILD_DIR"
    
    # Warmup (Silent)
    run_exec_workload > /dev/null 2>&1
    
    # Measure Stable
    measure_and_report "Exec" "Stable" run_exec_workload
    
    cleanup_bpf "$BUILD_DIR"
}

run_full_socket_test() {
    compile_socket_binary
    
    # Load BPF immediately
    cleanup_bpf "$BUILD_DIR"
    load_bpf_hook "$BUILD_DIR/lsm_socket_connect.o" "$BUILD_DIR"
    
    # Warmup (Silent)
    run_socket_workload > /dev/null 2>&1
    
    # Measure Stable
    measure_and_report "Socket" "Stable" run_socket_workload
    
    cleanup_bpf "$BUILD_DIR"
}

if [ "$MODE" == "exec" ]; then
    run_full_exec_test
elif [ "$MODE" == "socket" ]; then
    run_full_socket_test
else
    echo "Unknown mode: $MODE"
    exit 1
fi
