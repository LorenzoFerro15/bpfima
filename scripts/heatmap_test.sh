#!/bin/bash
# scripts/heatmap_test.sh

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

cleanup_bpf() {
    sudo "$BUILD_DIR/bpfima-tool" unload lsm_bprm_check_security > /dev/null 2>&1
    sudo pkill -f "bpfima-tool" > /dev/null 2>&1 || true
    if lsmod | grep -q "^bpfima "; then
        sudo rmmod bpfima > /dev/null 2>&1
    fi
    sudo rm -f /sys/fs/bpf/bpfima_* 2>/dev/null || true
}

load_bpf_hook() {
    local hook_obj=$1
    if ! lsmod | grep -q "^bpfima "; then
        sudo insmod $BUILD_DIR/bpfima.ko > /dev/null 2>&1
        sleep 1
    fi
    sudo "$BUILD_DIR/bpfima-tool" load "$hook_obj" -d > /dev/null 2>&1
    sudo "$BUILD_DIR/bpfima-tool" policy-init > /dev/null 2>&1
    sleep 2 # Let it settle
}

measure_avg_latency() {
    local cmd=$1
    local total_ns=0
    
    # Warmup
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

# No header, just append data
# Format: Size,Baseline_Avg,BPF_Avg,Overhead_NS

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

    cleanup_bpf
    echo "  Measuring Baseline..."
    baseline_avg=$(measure_avg_latency "/tmp/test_bin_$size")
    echo "  Baseline: $baseline_avg ns"

    echo "  Loading BPF..."
    load_bpf_hook "$BUILD_DIR/lsm_bprm_check_security.o"
    echo "  Measuring BPF..."
    bpf_avg=$(measure_avg_latency "/tmp/test_bin_$size")
    echo "  BPF: $bpf_avg ns"
    
    # Calculate Overhead (Difference)
    overhead_ns=$((bpf_avg - baseline_avg))
    
    echo "$size,$baseline_avg,$bpf_avg,$overhead_ns" >> $OUTPUT_FILE
    echo "  Overhead: ${overhead_ns} ns"
done

cleanup_bpf
rm -f /tmp/base_binary /tmp/base_binary.c /tmp/test_bin_*

echo "Done. Results saved to $OUTPUT_FILE"
