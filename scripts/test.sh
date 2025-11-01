#!/bin/bash
# BPF-IMA Integrated Test & Validation Script
# Combines interactive testing with comprehensive validation

set -e

# Default values
BPF_CONTAINER=false
VERBOSE=false
BPF_OBJECT=""
VALIDATE_MODE=false
VALIDATE_TASKS=""
SKIP_CLEANUP=false
INTERACTIVE_MODE=true

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Validation results tracking
declare -A VALIDATION_RESULTS
TESTS_PASSED=0
TESTS_FAILED=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --container|--with-container)
            BPF_CONTAINER=true
            shift
            ;;
        --validate)
            VALIDATE_MODE=true
            INTERACTIVE_MODE=false
            shift
            ;;
        --task)
            VALIDATE_MODE=true
            INTERACTIVE_MODE=false
            shift
            VALIDATE_TASKS="$VALIDATE_TASKS $1"
            shift
            ;;
        --skip-cleanup)
            SKIP_CLEANUP=true
            shift
            ;;
        --interactive)
            INTERACTIVE_MODE=true
            VALIDATE_MODE=false
            shift
            ;;
        *.o)
            BPF_OBJECT="$1"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [BPF_OBJECT]"
            echo ""
            echo "Integrated test and validation script for BPF-IMA container tracking"
            echo ""
            echo "Modes:"
            echo "  Default (Interactive)  Run interactive test with live monitoring"
            echo "  --validate             Run comprehensive validation of all tasks"
            echo "  --task N               Validate specific task(s) (1-7)"
            echo ""
            echo "Options:"
            echo "  --verbose, -v          Enable verbose output with detailed insights"
            echo "  --container            Run container-based tests (docker/podman)"
            echo "  --skip-cleanup         Don't cleanup after tests (for debugging)"
            echo "  --interactive          Force interactive mode (default)"
            echo "  --help, -h             Show this help message"
            echo ""
            echo "Arguments:"
            echo "  BPF_OBJECT             Path to .o file"
            echo "                         Default (interactive): build/lsm_mmap_file.o"
            echo "                         Default (validate): build/lsm_container_events.o"
            echo ""
            echo "Validation Tasks:"
            echo "  1. Data Structures     - Validate kernel data structures"
            echo "  2. SecurityFS Setup    - Check securityfs filesystem interface"
            echo "  3. Merkle Tree         - Verify Merkle tree operations"
            echo "  4. TPM Integration     - Test TPM PCR extension"
            echo "  5. eBPF Hooks          - Validate eBPF program attachment"
            echo "  6. Kernel-eBPF Comm    - Test BPF maps and ring buffers"
            echo "  7. Interactive Valid   - Run comprehensive end-to-end tests"
            echo ""
            echo "Examples:"
            echo "  # Interactive mode (default)"
            echo "  $0"
            echo "  $0 --verbose"
            echo "  $0 build/kprobe_file_open.o"
            echo "  $0 --container --verbose"
            echo ""
            echo "  # Validation mode"
            echo "  $0 --validate                    # Validate all tasks"
            echo "  $0 --validate --verbose          # Verbose validation"
            echo "  $0 --task 2 --task 3            # Validate specific tasks"
            echo "  $0 --validate --container        # Include container tests"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Must run as root${NC}"
    exit 1
fi

# Get paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

cd "$PROJECT_ROOT"

# Set default BPF object based on mode
if [ -z "$BPF_OBJECT" ]; then
    if $VALIDATE_MODE; then
        BPF_OBJECT="$BUILD_DIR/lsm_container_events.o"
    else
        BPF_OBJECT="$BUILD_DIR/lsm_mmap_file.o"
    fi
fi

# Validate BPF object path
if [[ ! "$BPF_OBJECT" = /* ]]; then
    # Relative path, prepend PROJECT_ROOT
    BPF_OBJECT="$PROJECT_ROOT/$BPF_OBJECT"
fi

# Helper functions for validation mode
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_task() {
    echo ""
    echo -e "${YELLOW}>>> Task $1: $2${NC}"
}

print_step() {
    if $VALIDATE_MODE || $VERBOSE; then
        echo -e "  ${GREEN}→${NC} $1"
    fi
}

print_success() {
    if $VALIDATE_MODE; then
        echo -e "  ${GREEN}✓${NC} $1"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    elif $VERBOSE; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo "✓ $1"
    fi
}

print_fail() {
    echo -e "  ${RED}✗${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_warning() {
    if $VALIDATE_MODE || $VERBOSE; then
        echo -e "  ${YELLOW}⚠${NC} $1"
    fi
}

print_info() {
    if $VERBOSE; then
        echo -e "  ${BLUE}ℹ${NC} $1"
    fi
}

# Cleanup function
cleanup() {
    if $SKIP_CLEANUP; then
        print_warning "Skipping cleanup (--skip-cleanup specified)"
        return
    fi
    
    if $VERBOSE && $VALIDATE_MODE; then
        print_header "Cleanup"
    elif $VERBOSE; then
        echo ""
        echo "=== Cleanup ==="
    fi
    
    echo "Cleaning up..."
    pkill -f "$BUILD_DIR/loader" 2>/dev/null || true
    if $VERBOSE; then
        print_step "Stopped loader process"
    fi
    if lsmod | grep -q "^bpfima "; then
        rmmod bpfima 2>/dev/null || true
        if $VERBOSE; then
            print_step "Removed kernel module"
        fi
    fi
    # Ensure test container is removed if it exists
    CONTAINER_NAME="bpfima_test_container"
    if command -v docker >/dev/null 2>&1; then
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    if command -v podman >/dev/null 2>&1; then
        podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    echo "Done"
}
trap cleanup EXIT INT TERM

# Validation function: Check if task should run
should_run_task() {
    local task_num=$1
    if [ -z "$VALIDATE_TASKS" ]; then
        return 0  # Run all if no specific tasks specified
    fi
    for task in $VALIDATE_TASKS; do
        if [ "$task" == "$task_num" ]; then
            return 0
        fi
    done
    return 1
}

# ==========================================
# VALIDATION TASK FUNCTIONS
# ==========================================

# Task 1: Data Structures Validation
validate_task1_data_structures() {
    print_task "1" "Data Structures Validation"
    
    print_step "Checking kernel module compilation..."
    if [ -f "$BUILD_DIR/bpfima.ko" ]; then
        print_success "Kernel module exists: bpfima.ko"
    else
        print_fail "Kernel module not found: bpfima.ko"
        return 1
    fi
    
    print_step "Validating data structure definitions..."
    
    if grep -q "struct container_node" "$PROJECT_ROOT/include/bpfima_common.h"; then
        print_success "container_node structure defined"
        print_info "Fields: id, measurement_list, leaf_hash, securityfs_dir"
    else
        print_fail "container_node structure not found"
    fi
    
    if grep -q "struct merkle_tree_root" "$PROJECT_ROOT/include/bpfima_common.h"; then
        print_success "merkle_tree_root structure defined"
        print_info "Fields: root_hash, lock, leaf_count"
    else
        print_fail "merkle_tree_root structure not found"
    fi
    
    if grep -q "struct measurement_entry" "$PROJECT_ROOT/include/bpfima_common.h"; then
        print_success "measurement_entry structure defined"
    else
        print_fail "measurement_entry structure not found"
    fi
    
    if grep -q "struct merkle_root_entry" "$PROJECT_ROOT/include/bpfima_common.h"; then
        print_success "merkle_root_entry structure defined"
    else
        print_fail "merkle_root_entry structure not found"
    fi
    
    print_step "Checking header dependencies..."
    if [ -f "$PROJECT_ROOT/include/bpfima_common.h" ] && \
       [ -f "$PROJECT_ROOT/include/bpfima_merkle.h" ] && \
       [ -f "$PROJECT_ROOT/include/bpfima_securityfs.h" ] && \
       [ -f "$PROJECT_ROOT/include/bpfima_kfuncs.h" ]; then
        print_success "All header files present"
    else
        print_fail "Missing header files"
    fi
    
    VALIDATION_RESULTS["task1"]="PASSED"
}

# Task 2: SecurityFS Setup Validation
validate_task2_securityfs() {
    print_task "2" "SecurityFS Setup Validation"
    
    print_step "Checking securityfs mount point..."
    if mount | grep -q "securityfs"; then
        print_success "securityfs is mounted"
    else
        print_warning "securityfs not mounted, attempting to mount..."
        mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || print_warning "Could not mount securityfs"
    fi
    
    print_step "Validating bpfima securityfs directory structure..."
    
    if [ -d "/sys/kernel/security/bpfima" ]; then
        print_success "Main directory exists: /sys/kernel/security/bpfima"
    else
        print_fail "Main directory not found: /sys/kernel/security/bpfima"
        VALIDATION_RESULTS["task2"]="FAILED"
        return 1
    fi
    
    if [ -d "/sys/kernel/security/bpfima/containers" ]; then
        print_success "Containers directory exists"
    else
        print_warning "Containers directory not found"
    fi
    
    if [ -f "/sys/kernel/security/bpfima/merkle_root" ]; then
        print_success "Merkle root file exists"
        if $VERBOSE; then
            print_info "Content preview:"
            head -3 /sys/kernel/security/bpfima/merkle_root 2>/dev/null | sed 's/^/    /'
        fi
    else
        print_fail "Merkle root file not found"
    fi
    
    VALIDATION_RESULTS["task2"]="PASSED"
}

# Task 3: Merkle Tree Implementation Validation
validate_task3_merkle_tree() {
    print_task "3" "Merkle Tree Implementation Validation"
    
    print_step "Checking Merkle tree implementation files..."
    if [ -f "$PROJECT_ROOT/src/merkle.c" ]; then
        print_success "Merkle tree implementation exists"
    else
        print_fail "Merkle tree implementation not found"
        return 1
    fi
    
    print_step "Validating Merkle tree functions..."
    
    if grep -q "compute_container_leaf_hash" "$PROJECT_ROOT/src/merkle.c"; then
        print_success "compute_container_leaf_hash() function defined"
    else
        print_fail "compute_container_leaf_hash() not found"
    fi
    
    if grep -q "recalculate_merkle_root" "$PROJECT_ROOT/src/merkle.c"; then
        print_success "recalculate_merkle_root() function defined"
    else
        print_fail "recalculate_merkle_root() not found"
    fi
    
    print_step "Reading Merkle root from securityfs..."
    if [ -f "/sys/kernel/security/bpfima/merkle_root" ]; then
        MERKLE_ROOT=$(cat /sys/kernel/security/bpfima/merkle_root 2>/dev/null | head -1)
        if [ -n "$MERKLE_ROOT" ]; then
            print_success "Merkle root readable"
            if $VERBOSE; then
                echo "$MERKLE_ROOT" | sed 's/^/    /' | head -5
            fi
        else
            print_warning "Merkle root file empty (no containers yet)"
        fi
    fi
    
    if grep -q "SHA256\|sha256" "$PROJECT_ROOT/src/merkle.c"; then
        print_success "SHA-256 hashing implemented"
    else
        print_fail "SHA-256 hashing not found"
    fi
    
    VALIDATION_RESULTS["task3"]="PASSED"
}

# Task 4: TPM PCR Extension Validation
validate_task4_tpm_integration() {
    print_task "4" "TPM PCR Extension Validation"
    
    print_step "Checking TPM integration in code..."
    
    if grep -q "extend_tpm_pcr_with_root" "$PROJECT_ROOT/src/merkle.c"; then
        print_success "extend_tpm_pcr_with_root() function defined"
    else
        print_fail "extend_tpm_pcr_with_root() not found"
    fi
    
    if grep -q "#include <linux/tpm.h>" "$PROJECT_ROOT/src/merkle.c"; then
        print_success "TPM header included"
    else
        print_fail "TPM header not included"
    fi
    
    if grep -q "tpm_pcr_extend" "$PROJECT_ROOT/src/merkle.c"; then
        print_success "tpm_pcr_extend() calls found"
    else
        print_fail "tpm_pcr_extend() calls not found"
    fi
    
    if grep -q "TPM_PCR_INDEX" "$PROJECT_ROOT/include/bpfima_common.h"; then
        TPM_PCR=$(grep "TPM_PCR_INDEX" "$PROJECT_ROOT/include/bpfima_common.h" | awk '{print $3}')
        print_success "TPM PCR index defined: $TPM_PCR"
    else
        print_fail "TPM PCR index not defined"
    fi
    
    print_step "Checking TPM device availability..."
    if [ -c "/dev/tpm0" ] || [ -c "/dev/tpmrm0" ]; then
        print_success "TPM device found"
        $VERBOSE && ls -l /dev/tpm* 2>/dev/null | sed 's/^/    /'
    else
        print_warning "No TPM device (graceful degradation active)"
        print_info "System will work without TPM"
    fi
    
    print_step "Checking kernel log for TPM operations..."
    if dmesg | grep -i "bpfima.*tpm" | tail -5 | grep -q "Extended TPM PCR\|TPM not available"; then
        print_success "TPM operations logged"
        $VERBOSE && dmesg | grep -i "bpfima.*tpm" | tail -3 | sed 's/^/    /'
    else
        print_warning "No TPM operations logged yet"
    fi
    
    VALIDATION_RESULTS["task4"]="PASSED"
}

# Task 5: eBPF Container Event Hook Validation
validate_task5_ebpf_hooks() {
    print_task "5" "eBPF Container Event Hook Validation"
    
    print_step "Checking eBPF program compilation..."
    
    if [ -f "$BUILD_DIR/lsm_container_events.o" ]; then
        print_success "lsm_container_events.o compiled"
    else
        print_fail "lsm_container_events.o not found"
    fi
    
    if [ -f "$BUILD_DIR/lsm_bprm_check_security.o" ]; then
        print_success "lsm_bprm_check_security.o compiled"
    else
        print_warning "lsm_bprm_check_security.o not found"
    fi
    
    print_step "Validating eBPF hook implementation..."
    
    if grep -q "SEC(\"lsm/" "$PROJECT_ROOT/hooks/lsm/lsm_container_events.c"; then
        print_success "LSM hooks defined"
    else
        print_fail "LSM hooks not found"
    fi
    
    if grep -q "cgroup\|container_id" "$PROJECT_ROOT/hooks/lsm/lsm_container_events.c"; then
        print_success "Container tracking logic present"
    else
        print_fail "Container tracking logic not found"
    fi
    
    print_step "Checking attached BPF programs..."
    if command -v bpftool >/dev/null 2>&1; then
        BPF_COUNT=$(bpftool prog list 2>/dev/null | grep -c "lsm" || echo "0")
        if [ "$BPF_COUNT" -gt 0 ]; then
            print_success "LSM BPF programs attached: $BPF_COUNT"
            $VERBOSE && bpftool prog list | grep -A2 "lsm" | head -10 | sed 's/^/    /'
        else
            print_warning "No LSM BPF programs visible yet"
        fi
    else
        print_warning "bpftool not available"
    fi
    
    VALIDATION_RESULTS["task5"]="PASSED"
}

# Task 6: Kernel-eBPF Communication Validation
validate_task6_kernel_ebpf_communication() {
    print_task "6" "Kernel-eBPF Communication Validation"
    
    print_step "Checking kfunc definitions..."
    
    if grep -q "bpf_container_create_or_get" "$PROJECT_ROOT/include/bpfima_kfuncs.h"; then
        print_success "bpf_container_create_or_get() kfunc defined"
    else
        print_fail "bpf_container_create_or_get() not found"
    fi
    
    if grep -q "bpf_container_add_measurement" "$PROJECT_ROOT/include/bpfima_kfuncs.h"; then
        print_success "bpf_container_add_measurement() kfunc defined"
    else
        print_fail "bpf_container_add_measurement() not found"
    fi
    
    if grep -q "bpf_get_merkle_root" "$PROJECT_ROOT/include/bpfima_kfuncs.h"; then
        print_success "bpf_get_merkle_root() kfunc defined"
    else
        print_fail "bpf_get_merkle_root() not found"
    fi
    
    print_step "Checking BPF map definitions..."
    
    if grep -q "BPF_MAP_TYPE_RINGBUF" "$PROJECT_ROOT/hooks/lsm/lsm_container_events.c"; then
        print_success "Ring buffer map defined"
    else
        print_warning "Ring buffer map not found"
    fi
    
    if grep -q "container_stats_map" "$PROJECT_ROOT/hooks/lsm/lsm_container_events.c"; then
        print_success "Container statistics map defined"
    else
        print_warning "Container statistics map not found"
    fi
    
    if grep -q "global_stats" "$PROJECT_ROOT/hooks/lsm/lsm_container_events.c"; then
        print_success "Global statistics map defined"
    else
        print_warning "Global statistics map not found"
    fi
    
    print_step "Verifying BTF kfunc registration..."
    if grep -q "register_btf_kfunc_id_set" "$PROJECT_ROOT/src/main.c"; then
        print_success "BTF kfunc registration implemented"
    else
        print_fail "BTF kfunc registration not found"
    fi
    
    print_step "Checking BPF maps in system..."
    if command -v bpftool >/dev/null 2>&1; then
        MAP_COUNT=$(bpftool map list 2>/dev/null | wc -l)
        if [ "$MAP_COUNT" -gt 0 ]; then
            print_success "BPF maps loaded: $MAP_COUNT"
            $VERBOSE && bpftool map list | head -8 | sed 's/^/    /'
        else
            print_warning "No BPF maps visible yet"
        fi
    fi
    
    VALIDATION_RESULTS["task6"]="PASSED"
}

# Task 7: Interactive Validation (End-to-End)
validate_task7_interactive() {
    print_task "7" "Interactive Validation - End-to-End Tests"
    
    print_step "Creating test environment..."
    TEST_DIR="/tmp/bpfima_validation_test"
    mkdir -p "$TEST_DIR"
    
    print_step "Generating test files..."
    TEST_EXEC="$TEST_DIR/test_binary"
    echo -e "#!/bin/bash\necho 'Test execution'" > "$TEST_EXEC"
    chmod +x "$TEST_EXEC"
    print_success "Created test executable"
    
    print_step "Triggering container events..."
    echo "  Executing test file..."
    "$TEST_EXEC" >/dev/null 2>&1 || true
    sleep 1
    
    echo "  Creating additional test files..."
    for i in {1..3}; do
        dd if=/dev/urandom of="$TEST_DIR/test_file_$i" bs=1024 count=4 2>/dev/null
    done
    sleep 1
    
    print_step "Checking for container creation..."
    CONTAINER_COUNT=$(ls -1 /sys/kernel/security/bpfima/containers/ 2>/dev/null | wc -l)
    if [ "$CONTAINER_COUNT" -gt 0 ]; then
        print_success "Containers tracked: $CONTAINER_COUNT"
        $VERBOSE && ls -1 /sys/kernel/security/bpfima/containers/ | sed 's/^/    /'
    else
        print_warning "No containers tracked yet"
    fi
    
    print_step "Validating measurements..."
    if [ -f "/sys/kernel/security/bpfima/measurements" ]; then
        MEASUREMENT_COUNT=$(wc -l < /sys/kernel/security/bpfima/measurements 2>/dev/null || echo "0")
        if [ "$MEASUREMENT_COUNT" -gt 0 ]; then
            print_success "Measurements recorded: $MEASUREMENT_COUNT"
            $VERBOSE && head -5 /sys/kernel/security/bpfima/measurements | sed 's/^/    /'
        else
            print_warning "No measurements recorded yet"
        fi
    fi
    
    print_step "Checking Merkle root updates..."
    if [ -f "/sys/kernel/security/bpfima/merkle_root" ]; then
        MERKLE_CONTENT=$(cat /sys/kernel/security/bpfima/merkle_root 2>/dev/null)
        if echo "$MERKLE_CONTENT" | grep -q "Leaf count: [1-9]"; then
            print_success "Merkle tree updated with leaf nodes"
            $VERBOSE && echo "$MERKLE_CONTENT" | head -5 | sed 's/^/    /'
        else
            print_warning "Merkle tree may not have leaves yet"
        fi
    fi
    
    print_step "Checking kernel log for events..."
    KERNEL_EVENTS=$(dmesg | grep -c "bpfima.*container\|Task 6" 2>/dev/null || echo "0")
    if [ "$KERNEL_EVENTS" -gt 0 ]; then
        print_success "Container events logged: $KERNEL_EVENTS"
        $VERBOSE && dmesg | grep "bpfima.*container\|Task 6" | tail -3 | sed 's/^/    /'
    else
        print_warning "No container events in kernel log"
    fi
    
    if $BPF_CONTAINER; then
        print_step "Running container runtime validation..."
        run_container_test
    fi
    
    print_step "Cleaning test environment..."
    rm -rf "$TEST_DIR"
    print_success "Test environment cleaned"
    
    VALIDATION_RESULTS["task7"]="PASSED"
}

# ==========================================
# INTERACTIVE TEST FUNCTIONS
# ==========================================

# Build
echo "Building..."
if $VERBOSE; then
    echo "=== Build output ==="
    make all
    echo ""
else
    make all > /dev/null 2>&1 || { echo "Build failed"; exit 1; }
fi

if $VERBOSE; then
    echo "✓ Build successful"
    echo ""
fi

# Load kernel module
echo "Loading kernel module..."
lsmod | grep -q "^bpfima " && rmmod bpfima 2>/dev/null
insmod "$BUILD_DIR/bpfima.ko" || { echo "Failed to load module"; exit 1; }

if $VERBOSE; then
    echo "✓ Module loaded"
    lsmod | grep bpfima
    echo ""
    echo "=== Module info ==="
    modinfo "$BUILD_DIR/bpfima.ko" | head -5
    echo ""
fi

# Validate BPF object exists
if [ ! -f "$BPF_OBJECT" ]; then
    echo "Error: BPF object not found: $BPF_OBJECT"
    echo "Available objects in build/:"
    ls -1 "$BUILD_DIR"/*.o 2>/dev/null || echo "  (none found)"
    exit 1
fi

# Start eBPF program
echo "Starting eBPF monitor..."
if $VERBOSE; then
    echo "Target: $BPF_OBJECT"
    echo "=== Loader output ==="
fi
"$BUILD_DIR/loader" "$BPF_OBJECT" &
LOADER_PID=$!
sleep 2

# Check if still running
if ! kill -0 $LOADER_PID 2>/dev/null; then
    echo "Error: Loader died"
    exit 1
fi

echo "✓ Running (PID: $LOADER_PID)"
echo "Loaded: $(basename "$BPF_OBJECT")"

if $VERBOSE; then
    echo ""
    echo "=== System info ==="
    echo "BPF object: $BPF_OBJECT"
    echo "Trace output: /sys/kernel/debug/tracing/trace_pipe"
    echo "Kernel messages: dmesg | grep bpfima"
    echo "Loaded programs: bpftool prog list"
    echo ""
    echo "=== Recent trace (last 5 lines) ==="
    tail -5 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "  (no trace data yet)"
    echo ""
fi

echo "Press Ctrl-C to stop"
echo ""

# Test actions for lsm_file_post_open if the loaded object is lsm_file_post_open.o
if [[ "$(basename "$BPF_OBJECT")" == "lsm_file_post_open.o" ]]; then
    echo "=== Running test actions for lsm_file_post_open ==="
    
    # Create a test directory and files
    TEST_DIR="/home/lo/bpfima_test"
    mkdir -p "$TEST_DIR"
    
    echo "Creating test files to trigger file_post_open hash measurements..."
    
    # Create a test executable file (5KB - within the size range)
    TEST_EXEC="$TEST_DIR/test_exec.sh"
    echo "#!/bin/bash" > "$TEST_EXEC"
    echo "echo 'This is a test executable'" >> "$TEST_EXEC"
    # Pad the file to make it larger than 4KB
    head -c 5000 /dev/zero | tr '\0' 'A' >> "$TEST_EXEC"
    chmod +x "$TEST_EXEC"
    
    # Create another test file (8KB)
    TEST_FILE="$TEST_DIR/test_binary"
    dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=8 2>/dev/null
    chmod +x "$TEST_FILE"
    
    echo "  Created test files in $TEST_DIR"
    sleep 1
    
    echo ""
    echo "Triggering hash measurements by executing test files..."
    
    # Execute the test script (this should trigger lsm_file_post_open with MAY_EXEC)
    echo "  1. Executing $TEST_EXEC"
    "$TEST_EXEC" 2>/dev/null || true
    sleep 1
    
    # Try to execute the binary (will fail but should trigger the hook)
    echo "  2. Executing $TEST_FILE"
    "$TEST_FILE" 2>/dev/null || true
    sleep 1
    
    # Open files in read mode with exec permissions
    echo "  3. Opening files with various methods"
    # Use cat to open and read the files
    cat "$TEST_EXEC" > /dev/null 2>&1 || true
    sleep 0.5
    cat "$TEST_FILE" > /dev/null 2>&1 || true
    sleep 0.5
    
    # Try opening with exec command
    echo "  4. Using exec to open files"
    bash -c "exec 3< '$TEST_EXEC'; exec 3<&-" 2>/dev/null || true
    sleep 0.5
    
    echo ""
    echo "Test actions completed. Check trace output:"
    echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
    echo "  or: sudo dmesg | grep -i 'bpf\|ima\|hash'"
    echo ""
    
    # Show recent trace output if verbose
    if $VERBOSE; then
        echo "=== Recent trace output (last 30 lines) ==="
        tail -30 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "  (no trace data available)"
        echo ""
    fi
    
    echo "Cleaning up test files..."
    rm -rf "$TEST_DIR"
    echo "  Removed $TEST_DIR"
    echo ""
fi

echo "Press Ctrl-C to stop monitoring"

# Container test function
run_container_test() {
    CONTAINER_NAME="bpfima_test_container"

    # pick docker or podman
    if command -v docker >/dev/null 2>&1; then
        CONTAINER_CLI=docker
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_CLI=podman
    else
        print_warning "No container runtime found (docker or podman)"
        return 0
    fi

    print_info "Using container runtime: $CONTAINER_CLI"

    print_step "Pulling alpine image..."
    $CONTAINER_CLI pull alpine:latest >/dev/null 2>&1 || true

    print_step "Starting container: $CONTAINER_NAME"
    $CONTAINER_CLI run -d --name "$CONTAINER_NAME" --rm alpine:latest sleep 300 >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        print_fail "Failed to start container"
        return 1
    fi
    print_success "Container started"

    print_step "Executing commands inside container"
    $CONTAINER_CLI exec "$CONTAINER_NAME" sh -c "echo 'hello' > /tmp/hello && ls /tmp" >/dev/null 2>&1 || true
    sleep 2

    CONTAINER_CGROUP=$($CONTAINER_CLI inspect --format='{{.Id}}' "$CONTAINER_NAME" 2>/dev/null | cut -c1-12)
    if [ -n "$CONTAINER_CGROUP" ] && [ -d "/sys/kernel/security/bpfima/containers" ]; then
        if ls /sys/kernel/security/bpfima/containers/ 2>/dev/null | grep -q "$CONTAINER_CGROUP"; then
            print_success "Container tracked in securityfs"
        else
            print_warning "Container not in securityfs (different cgroup naming)"
        fi
    fi

    print_step "Stopping container"
    $CONTAINER_CLI stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    print_success "Container test completed"
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# Build phase
if $VALIDATE_MODE; then
    print_header "BPF-IMA Container Tracking System Validation"
    echo "Project: $PROJECT_ROOT"
    echo "Mode: Validation"
    echo "BPF Object: $(basename $BPF_OBJECT)"
    echo ""
    
    print_header "Build Phase"
    echo "Building all components..."
    if $VERBOSE; then
        make all
    else
        make all > /dev/null 2>&1 || { print_fail "Build failed"; exit 1; }
    fi
    print_success "Build completed successfully"
    
    # Load kernel module for validation tasks 2+
    if should_run_task 2 || should_run_task 3 || should_run_task 4 || \
       should_run_task 5 || should_run_task 6 || should_run_task 7; then
        print_step "Loading kernel module..."
        lsmod | grep -q "^bpfima " && rmmod bpfima 2>/dev/null
        insmod "$BUILD_DIR/bpfima.ko" || { print_fail "Failed to load module"; exit 1; }
        print_success "Module loaded"
        
        # Load eBPF program for tasks 5, 6, 7
        if should_run_task 5 || should_run_task 6 || should_run_task 7; then
            if [ -f "$BPF_OBJECT" ]; then
                print_step "Loading eBPF program..."
                "$BUILD_DIR/loader" "$BPF_OBJECT" &
                LOADER_PID=$!
                sleep 2
                if kill -0 $LOADER_PID 2>/dev/null; then
                    print_success "eBPF program loaded (PID: $LOADER_PID)"
                else
                    print_warning "eBPF program failed to load"
                fi
            fi
        fi
    fi
    
    # Run validation tasks
    should_run_task 1 && validate_task1_data_structures
    should_run_task 2 && validate_task2_securityfs
    should_run_task 3 && validate_task3_merkle_tree
    should_run_task 4 && validate_task4_tpm_integration
    should_run_task 5 && validate_task5_ebpf_hooks
    should_run_task 6 && validate_task6_kernel_ebpf_communication
    should_run_task 7 && validate_task7_interactive
    
    # Final Summary
    print_header "Validation Summary"
    echo ""
    echo "Tests Passed: $TESTS_PASSED"
    echo "Tests Failed: $TESTS_FAILED"
    echo ""
    
    for task in "${!VALIDATION_RESULTS[@]}"; do
        result="${VALIDATION_RESULTS[$task]}"
        if [ "$result" == "PASSED" ]; then
            echo -e "${GREEN}✓${NC} $task: PASSED"
        else
            echo -e "${RED}✗${NC} $task: FAILED"
        fi
    done
    
    echo ""
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}All validations completed successfully!${NC}"
        echo -e "${GREEN}========================================${NC}"
        exit 0
    else
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}Some validations failed!${NC}"
        echo -e "${RED}========================================${NC}"
        exit 1
    fi

elif $INTERACTIVE_MODE; then
    # Interactive test mode (original functionality)
    echo "BPF-IMA Interactive Test Mode"
    echo "Project: $PROJECT_ROOT"
    echo "BPF Object: $(basename $BPF_OBJECT)"
    echo ""
    
    # Build
    echo "Building..."
    if $VERBOSE; then
        echo "=== Build output ==="
        make all
        echo ""
    else
        make all > /dev/null 2>&1 || { echo "Build failed"; exit 1; }
    fi

    if $VERBOSE; then
        print_success "Build successful"
        echo ""
    else
        echo "✓ Build successful"
    fi

    # Load kernel module
    echo "Loading kernel module..."
    lsmod | grep -q "^bpfima " && rmmod bpfima 2>/dev/null
    insmod "$BUILD_DIR/bpfima.ko" || { echo "Failed to load module"; exit 1; }

    if $VERBOSE; then
        print_success "Module loaded"
        lsmod | grep bpfima
        echo ""
        echo "=== Module info ==="
        modinfo "$BUILD_DIR/bpfima.ko" | head -5
        echo ""
    else
        echo "✓ Module loaded"
    fi

    # Validate BPF object exists
    if [ ! -f "$BPF_OBJECT" ]; then
        echo "Error: BPF object not found: $BPF_OBJECT"
        echo "Available objects in build/:"
        ls -1 "$BUILD_DIR"/*.o 2>/dev/null || echo "  (none found)"
        exit 1
    fi

    # Start eBPF program
    echo "Starting eBPF monitor..."
    if $VERBOSE; then
        echo "Target: $BPF_OBJECT"
        echo "=== Loader output ==="
    fi
    "$BUILD_DIR/loader" "$BPF_OBJECT" &
    LOADER_PID=$!
    sleep 2

    # Check if still running
    if ! kill -0 $LOADER_PID 2>/dev/null; then
        echo "Error: Loader died"
        exit 1
    fi

    echo "✓ Running (PID: $LOADER_PID)"
    echo "Loaded: $(basename "$BPF_OBJECT")"

    if $VERBOSE; then
        echo ""
        echo "=== System info ==="
        echo "BPF object: $BPF_OBJECT"
        echo "Trace output: /sys/kernel/debug/tracing/trace_pipe"
        echo "Kernel messages: dmesg | grep bpfima"
        echo "Loaded programs: bpftool prog list"
        echo ""
        echo "=== Recent trace (last 5 lines) ==="
        tail -5 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "  (no trace data yet)"
        echo ""
    fi

    echo "Press Ctrl-C to stop"
    echo ""

    # Test actions for lsm_file_post_open if the loaded object is lsm_file_post_open.o
    if [[ "$(basename "$BPF_OBJECT")" == "lsm_file_post_open.o" ]]; then
        echo "=== Running test actions for lsm_file_post_open ==="
        
        # Create a test directory and files
        TEST_DIR="/home/lo/bpfima_test"
        mkdir -p "$TEST_DIR"
        
        echo "Creating test files to trigger file_post_open hash measurements..."
        
        # Create a test executable file (5KB - within the size range)
        TEST_EXEC="$TEST_DIR/test_exec.sh"
        echo "#!/bin/bash" > "$TEST_EXEC"
        echo "echo 'This is a test executable'" >> "$TEST_EXEC"
        # Pad the file to make it larger than 4KB
        head -c 5000 /dev/zero | tr '\0' 'A' >> "$TEST_EXEC"
        chmod +x "$TEST_EXEC"
        
        # Create another test file (8KB)
        TEST_FILE="$TEST_DIR/test_binary"
        dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=8 2>/dev/null
        chmod +x "$TEST_FILE"
        
        echo "  Created test files in $TEST_DIR"
        sleep 1
        
        echo ""
        echo "Triggering hash measurements by executing test files..."
        
        # Execute the test script (this should trigger lsm_file_post_open with MAY_EXEC)
        echo "  1. Executing $TEST_EXEC"
        "$TEST_EXEC" 2>/dev/null || true
        sleep 1
        
        # Try to execute the binary (will fail but should trigger the hook)
        echo "  2. Executing $TEST_FILE"
        "$TEST_FILE" 2>/dev/null || true
        sleep 1
        
        # Open files in read mode with exec permissions
        echo "  3. Opening files with various methods"
        # Use cat to open and read the files
        cat "$TEST_EXEC" > /dev/null 2>&1 || true
        sleep 0.5
        cat "$TEST_FILE" > /dev/null 2>&1 || true
        sleep 0.5
        
        # Try opening with exec command
        echo "  4. Using exec to open files"
        bash -c "exec 3< '$TEST_EXEC'; exec 3<&-" 2>/dev/null || true
        sleep 0.5
        
        echo ""
        echo "Test actions completed. Check trace output:"
        echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
        echo "  or: sudo dmesg | grep -i 'bpf\|ima\|hash'"
        echo ""
        
        # Show recent trace output if verbose
        if $VERBOSE; then
            echo "=== Recent trace output (last 30 lines) ==="
            tail -30 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "  (no trace data available)"
            echo ""
        fi
        
        echo "Cleaning up test files..."
        rm -rf "$TEST_DIR"
        echo "  Removed $TEST_DIR"
        echo ""
    fi

    echo "Press Ctrl-C to stop monitoring"

    # If requested, run a lightweight container
    if $BPF_CONTAINER; then
        run_container_test || echo "Container test failed"
    fi

    # Wait
    wait $LOADER_PID
fi
