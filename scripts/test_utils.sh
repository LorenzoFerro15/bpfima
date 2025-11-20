#!/bin/bash
# BPF IMA Test Utilities
# Provides polling and synchronization functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Polling timeout in deciseconds (0.1s units)
DEFAULT_TIMEOUT=300  # 30 seconds
POLL_INTERVAL=2      # 0.2 seconds (2 deciseconds)

##
# @brief Wait for a process to be running
# @param $1 PID to wait for
# @param $2 Timeout in seconds (default: 5)
# @return 0 if process is running, 1 on timeout
##
wait_for_process() {
    local pid=$1
    local timeout=${2:-5}
    local timeout_ds=$((timeout * 10))  # Convert to deciseconds
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

##
# @brief Wait for a file to exist
# @param $1 File path to wait for
# @param $2 Timeout in seconds (default: 30)
# @return 0 if file exists, 1 on timeout
##
wait_for_file() {
    local file=$1
    local timeout=${2:-30}
    local timeout_ds=$((timeout * 10))  # Convert to deciseconds
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

##
# @brief Wait for a kernel module to be loaded
# @param $1 Module name
# @param $2 Timeout in seconds (default: 10)
# @return 0 if module is loaded, 1 on timeout
##
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

##
# @brief Wait for a BPF map to be pinned
# @param $1 Map name (without path)
# @param $2 Timeout in seconds (default: 10)
# @return 0 if map exists, 1 on timeout
##
wait_for_bpf_map() {
    local map_name=$1
    local timeout=${2:-10}
    local map_path="/sys/fs/bpf/${map_name}"
    
    wait_for_file "$map_path" "$timeout"
}

##
# @brief Wait for multiple BPF maps to be pinned
# @param $@ List of map names
# @return 0 if all maps exist, 1 on timeout
##
wait_for_bpf_maps() {
    local timeout=10
    local maps=("$@")
    
    for map in "${maps[@]}"; do
        if ! wait_for_bpf_map "$map" "$timeout"; then
            echo "Timeout waiting for BPF map: $map" >&2
            return 1
        fi
    done
    
    return 0
}

##
# @brief Wait for securityfs directory to be available
# @param $1 Path under /sys/kernel/security/
# @param $2 Timeout in seconds (default: 10)
# @return 0 if path exists, 1 on timeout
##
wait_for_securityfs() {
    local path="/sys/kernel/security/$1"
    local timeout=${2:-10}
    
    wait_for_file "$path" "$timeout"
}

##
# @brief Wait for a container to be running
# @param $1 Container name
# @param $2 Container CLI (docker/podman)
# @param $3 Timeout in seconds (default: 30)
# @return 0 if container is running, 1 on timeout
##
wait_for_container() {
    local container=$1
    local cli=$2
    local timeout=${3:-30}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if $cli ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
            # Check if it's actually running
            local state=$($cli inspect --format '{{.State.Status}}' "$container" 2>/dev/null)
            if [ "$state" = "running" ]; then
                return 0
            fi
        fi
        sleep 0.2
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    
    return 1
}

##
# @brief Wait for a process to exit
# @param $1 PID to wait for
# @param $2 Timeout in seconds (default: 10)
# @return 0 if process exited, 1 on timeout
##
wait_for_process_exit() {
    local pid=$1
    local timeout=${2:-10}
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

##
# @brief Wait for kernel module to be unloaded
# @param $1 Module name
# @param $2 Timeout in seconds (default: 10)
# @return 0 if module is unloaded, 1 on timeout
##
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

##
# @brief Poll a file for expected content
# @param $1 File path
# @param $2 Expected pattern (grep regex)
# @param $3 Timeout in seconds (default: 10)
# @return 0 if pattern found, 1 on timeout
##
wait_for_file_content() {
    local file=$1
    local pattern=$2
    local timeout=${3:-10}
    local timeout_ds=$((timeout * 10))
    local elapsed=0
    
    while [ $elapsed -lt $timeout_ds ]; do
        if [ -e "$file" ] && grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        sleep $POLL_INTERVAL
        elapsed=$(echo "$elapsed + $POLL_INTERVAL" | bc)
    done
    
    return 1
}

##
# @brief Verify BPF IMA is ready (module + maps + securityfs)
# @return 0 if ready, 1 if not ready
##
verify_bpfima_ready() {
    local errors=0
    
    # Check module
    if ! lsmod | grep -q "^bpfima "; then
        echo -e "${RED}  ${NC} Kernel module not loaded" >&2
        errors=$((errors + 1))
    else
        echo -e "${GREEN} ${NC} Kernel module loaded"
    fi
    
    # Check securityfs
    if [ ! -d "/sys/kernel/security/bpfima" ]; then
        echo -e "${RED}  ${NC} SecurityFS not available" >&2
        errors=$((errors + 1))
    else
        echo -e "${GREEN} ${NC} SecurityFS available"
    fi
    
    # Check essential BPF maps
    local maps=("bpfima_policy_map" "bpfima_hook_config_map")
    for map in "${maps[@]}"; do
        if [ ! -e "/sys/fs/bpf/$map" ]; then
            echo -e "${YELLOW}⚠${NC} BPF map not found: $map" >&2
        else
            echo -e "${GREEN} ${NC} BPF map: $map"
        fi
    done
    
    return $errors
}

# Export functions if sourced
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    export -f wait_for_process
    export -f wait_for_file
    export -f wait_for_module
    export -f wait_for_bpf_map
    export -f wait_for_bpf_maps
    export -f wait_for_securityfs
    export -f wait_for_container
    export -f wait_for_process_exit
    export -f wait_for_module_unload
    export -f wait_for_file_content
    export -f verify_bpfima_ready
fi
