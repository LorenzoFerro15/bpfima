#!/bin/bash

source ./scripts/test_utils.sh > /dev/null 2>&1

BUILD_DIR=$(pwd)/build
OUTPUT_FILE="size_exec_latency.log"
SIZES=("4K" "64K" "1M" "10M" "50M" "100M")
ITERATIONS=50

echo "Compiling base binary..."
cat <<EOF > /tmp/base_binary.c
#include <stdio.h>
int main() { return 0; }
EOF
gcc /tmp/base_binary.c -o /tmp/base_binary

measure_avg_latency() {
    local cmd=$1
    local total_ns=0
    
    for i in {1..5}; do $cmd > /dev/null 2>&1; done

    for i in $(seq 1 $ITERATIONS); do
        start_time=$(date +%s%N)
        $cmd > /dev/null 2>&1
        end_time=$(date +%s%N)
        duration=$((end_time - start_time))
        total_ns=$((total_ns + duration))
    done
    
    echo $((total_ns / ITERATIONS))
}

for size in "${SIZES[@]}"; do
    echo "Preparing test for size: $size"
    
    cp /tmp/base_binary /tmp/test_bin_$size
    
    current_size=$(stat -c%s /tmp/test_bin_$size)
    target_bytes=$(numfmt --from=iec $size)
    pad_bytes=$((target_bytes - current_size))
    
    if [ $pad_bytes -gt 0 ]; then
        dd if=/dev/zero bs=1024 count=$((pad_bytes / 1024)) >> /tmp/test_bin_$size 2>/dev/null
        remaining=$((pad_bytes % 1024))
        if [ $remaining -gt 0 ]; then
             dd if=/dev/zero bs=1 count=$remaining >> /tmp/test_bin_$size 2>/dev/null
        fi
    fi
    chmod +x /tmp/test_bin_$size

    cleanup_bpf "$BUILD_DIR"
    echo "  Measuring Baseline..."
    baseline_avg=$(measure_avg_latency "/tmp/test_bin_$size")
    echo "  Baseline: $baseline_avg ns"

    echo "  Loading BPF..."
    load_bpf_hook "$BUILD_DIR/lsm_bprm_check_security.o" "$BUILD_DIR"
    echo "  Measuring BPF..."
    bpf_avg=$(measure_avg_latency "/tmp/test_bin_$size")
    echo "  BPF: $bpf_avg ns"
    
    overhead_ns=$((bpf_avg - baseline_avg))
    
    echo "$size,$baseline_avg,$bpf_avg,$overhead_ns" >> $OUTPUT_FILE
    echo "  Overhead: ${overhead_ns} ns"
done

cleanup_bpf "$BUILD_DIR"
rm -f /tmp/base_binary /tmp/base_binary.c /tmp/test_bin_*

echo "Done. Results saved to $OUTPUT_FILE"
