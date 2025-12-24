#!/bin/bash

# scripts/throughput_test.sh
# Usage: ./throughput_test.sh <exec|socket> <count_per_binary>

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <exec|socket> <count>"
    exit 1
fi

MODE=$1
COUNT=$2

# Create build dir for temporary binaries if not exists
mkdir -p /tmp/bpf_throughput

# --- Compilation ---

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
    
    // Just trigger the hook, don't care about connection success
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

# --- Execution ---

run_exec_test() {
    compile_exec_binaries
    
    start_time=$(date +%s%N)
    
    # Launch 10 different binaries, COUNT times each, ALL in background
    for i in {1..10}; do
        for ((j=1; j<=COUNT; j++)); do
            /tmp/bpf_throughput/exec_test_$i > /dev/null 2>&1 &
        done
    done
    
    # Wait for all background jobs to finish
    wait
    
    end_time=$(date +%s%N)
    total_time=$((end_time - start_time))
    
    # Clean output for parser
    # Format: Type: <Type> | Count: <TotalCalls> | Time: <ns>
    # Total calls for exec = 10 * COUNT
    total_calls=$((10 * COUNT))
    echo "Type: Exec | Count: $total_calls | Time: $total_time ns"
}

run_socket_test() {
    compile_socket_binary
    
    start_time=$(date +%s%N)
    
    # Launch socket test COUNT times in background
    # Note: user asked for "lots of sockets opened", treating COUNT as total socket ops for now
    # Or "10 executables different called 100 times each" -> 1000 ops.
    # For socket to be comparable, let's just do COUNT * 10 to match the scale or just COUNT?
    # User said: "evaluates the times taken when a lot of different sockets are opened"
    # To keep it consistent with the "exec" scale (where we do 10 * N), let's do 10 * N valid socket ops here too? 
    # Or just N * 10 to keep the input semantics identical "count per unit".
    # Let's do 10 parallel loops of COUNT to simulate "10 different sources" roughly, or just simple flat loop.
    # Given requirements: "make the executables call asyncronous".
    # I'll spawn COUNT * 10 processes to be perfectly symmetric with exec test.
    
    for i in {1..10}; do
        for ((j=1; j<=COUNT; j++)); do
           /tmp/bpf_throughput/socket_test > /dev/null 2>&1 &
        done
    done
    
    wait
    
    end_time=$(date +%s%N)
    total_time=$((end_time - start_time))
    
    total_calls=$((10 * COUNT))
    echo "Type: Socket | Count: $total_calls | Time: $total_time ns"
}

# --- Main ---

if [ "$MODE" == "exec" ]; then
    run_exec_test
elif [ "$MODE" == "socket" ]; then
    run_socket_test
else
    echo "Unknown mode: $MODE"
    exit 1
fi
