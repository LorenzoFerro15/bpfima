#!/bin/bash

# scripts/test_utils.sh

DEFAULT_TIMEOUT=300
POLL_INTERVAL=2

wait_for_process() {
    local pid=$1
    local timeout=${2:-5}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

wait_for_process_exit() {
    local pid=$1
    local timeout=${2:-5}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

wait_for_file() {
    local file=$1
    local timeout=${2:-30}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if [ -e "$file" ]; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

wait_for_module() {
    local module=$1
    local timeout=${2:-10}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if lsmod | grep -q "^${module} "; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

wait_for_module_unload() {
    local module=$1
    local timeout=${2:-10}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if ! lsmod | grep -q "^${module} "; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

wait_for_bpf_map() {
    local map_name=$1
    local timeout=${2:-10}
    wait_for_file "/sys/fs/bpf/${map_name}" "$timeout"
}

wait_for_bpf_maps() {
    local maps=("$@")
    local timeout=30
    local elapsed=0
    
    # Last argument might be timeout if it's numeric, but for now assuming default or fixed
    
    while [ $elapsed -lt $((timeout * 10)) ]; do
        local all_found=1
        for map in "${maps[@]}"; do
            if [ ! -e "/sys/fs/bpf/$map" ]; then
                all_found=0
                break
            fi
        done
        
        if [ $all_found -eq 1 ]; then
            return 0
        fi
        
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

wait_for_securityfs() {
    local path="/sys/kernel/security/$1"
    local timeout=${2:-10}
    wait_for_file "$path" "$timeout"
}

wait_for_container() {
    local container_name=$1
    local container_cli=${2:-docker}
    local timeout=${3:-30}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if $container_cli inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null | grep -q "true"; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    return 1
}

cleanup_bpf() {
    local build_dir=${1:-$(pwd)/build}
    
    sudo "$build_dir/bpfima-tool" unload lsm_bprm_check_security > /dev/null 2>&1
    sudo "$build_dir/bpfima-tool" unload lsm_socket_connect > /dev/null 2>&1
    
    sudo pkill -f "bpfima-tool" > /dev/null 2>&1 || true
    
    if lsmod | grep -q "^bpfima "; then
        sudo rmmod bpfima > /dev/null 2>&1
    fi
    
    sudo rm -f /sys/fs/bpf/bpfima_* 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/scratch_buf_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/bpf_timing_stats 2>/dev/null || true
}

load_bpf_hook() {
    local hook_obj=$1
    local build_dir=${2:-$(pwd)/build}
    
    if ! lsmod | grep -q "^bpfima "; then
        sudo insmod "$build_dir/bpfima.ko" > /dev/null 2>&1
        wait_for_module bpfima 5
        wait_for_securityfs bpfima 5
    fi
    
    sudo "$build_dir/bpfima-tool" load "$hook_obj" -d > /dev/null 2>&1
    sudo "$build_dir/bpfima-tool" policy-init > /dev/null 2>&1
}

if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    export -f wait_for_process
    export -f wait_for_file
    export -f wait_for_module
    export -f wait_for_bpf_map
    export -f wait_for_securityfs
    export -f wait_for_process_exit
    export -f wait_for_bpf_maps
    export -f wait_for_module_unload
    export -f wait_for_container
    export -f cleanup_bpf
    export -f load_bpf_hook
fi
