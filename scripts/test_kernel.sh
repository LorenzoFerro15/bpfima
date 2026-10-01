#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
SECURITYFS_DIR="/sys/kernel/security/bpfima"
LOAD_MODULE=0
CHECK_ONLY=0
STRESS=0
TIMEOUT_SECONDS=300
OUTPUT_DIR=""
OWN_MODULE=0
TEMPORARY_DIR=""
CHILD_PID=""
STARTED_AT=""
RESULT=0

usage() {
    cat <<'EOF'
Usage: scripts/test_kernel.sh [options]

Build first: make modules kernel-tests
Run on an isolated BPF LSM host: sudo ./scripts/test_kernel.sh --load-module

  --check                 Check prerequisites without loading or running tests
  --load-module           Load build/bpfima.ko if absent; unload only that module
  --stress                Also test concurrent creation, recording, and deduplication
  --securityfs-dir PATH   Use an alternate bpfima SecurityFS directory
  --output-dir PATH       Directory for test output and kernel logs
  --timeout SECONDS       Per-executable timeout (default: 300)
  -h, --help              Show this help

Without --load-module, the updated module must already be loaded with BTF.
Positive tests create test namespaces and measurements and may extend TPM PCRs.
No Go tests or userspace-only sanitizer tests run through this entry point.
EOF
}

error() {
    echo "ERROR: $*" >&2
    exit 2
}

need_value() {
    [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || error "$1 requires a value"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        --load-module) LOAD_MODULE=1; shift ;;
        --stress) STRESS=1; shift ;;
        --securityfs-dir) need_value "$@"; SECURITYFS_DIR="$2"; shift 2 ;;
        --output-dir) need_value "$@"; OUTPUT_DIR="$2"; shift 2 ;;
        --timeout) need_value "$@"; TIMEOUT_SECONDS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown option: $1 (use --help)" ;;
    esac
done

[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]{0,5}$ ]] || error "--timeout must be a positive integer of at most six digits"
for command in timeout dmesg readelf mktemp; do
    command -v "$command" >/dev/null || error "Missing command: $command"
done
for artifact in security-regression security-regression.bpf.o module-interactions module-interactions.bpf.o \
                lsm_bprm_check_security.o lsm_file_post_open.o lsm_inode_setattr.o lsm_mmap_file.o lsm_socket_connect.o; do
    [[ -r "$BUILD_DIR/$artifact" ]] || error "Missing build/$artifact; run make modules kernel-tests"
done
[[ -x "$BUILD_DIR/security-regression" && -x "$BUILD_DIR/module-interactions" ]] || error "Test executables are not executable"
[[ -r /sys/kernel/btf/vmlinux ]] || error "Kernel BTF unavailable at /sys/kernel/btf/vmlinux"
[[ -r /sys/kernel/security/lsm ]] || error "SecurityFS unavailable; mount it with sudo mount -t securityfs securityfs /sys/kernel/security"
LSM_LIST="$(cat /sys/kernel/security/lsm)"
[[ ",$LSM_LIST," == *,bpf,* ]] || error "BPF LSM is disabled; include bpf in the kernel lsm= boot option and reboot"

if [[ -d /sys/module/bpfima ]]; then
    [[ -r /sys/kernel/btf/bpfima ]] || error "Loaded bpfima module has no BTF; rebuild it with matching kernel vmlinux and reload"
    [[ -r "$SECURITYFS_DIR/status" ]] || error "Missing $SECURITYFS_DIR/status; select its directory with --securityfs-dir"
    "$BUILD_DIR/module-interactions" --check-abi || error "Loaded module ABI is incompatible; reload the updated module"
elif [[ $LOAD_MODULE -eq 1 ]]; then
    command -v insmod >/dev/null || error "Missing command: insmod"
    command -v rmmod >/dev/null || error "Missing command: rmmod"
    [[ -r "$BUILD_DIR/bpfima.ko" ]] || error "Missing build/bpfima.ko; run make modules"
    MODULE_SECTIONS="$(readelf -SW "$BUILD_DIR/bpfima.ko")" || error "Cannot read build/bpfima.ko as an ELF module"
    [[ "$MODULE_SECTIONS" == *".BTF "* ]] || error "build/bpfima.ko has no BTF; provide matching kernel vmlinux, then run make modules"
else
    error "bpfima is not loaded; use --load-module or load the updated module first"
fi

echo "Kernel: $(uname -r)"
echo "LSMs: $LSM_LIST"
echo "PASS: kernel suite prerequisites"
if [[ $CHECK_ONLY -eq 1 ]]; then
    exit 0
fi
[[ $EUID -eq 0 ]] || error "Run this script with sudo"
dmesg >/dev/null || error "Cannot read kernel logs; run with permission to read dmesg"

if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$BUILD_DIR/kernel-test-results/$(date +%Y%m%d-%H%M%S)-$$"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
# util-linux dmesg expects local time without an ISO 8601 timezone suffix.
STARTED_AT="$(date '+%Y-%m-%d %H:%M:%S')"
dmesg --since "$STARTED_AT" >/dev/null || error "Cannot filter kernel logs by the run's start time"
dmesg >"$OUTPUT_DIR/dmesg-before.log"

cleanup() {
    local exit_code=$?
    local cleanup_failed=0
    local unloaded=0
    local log_status=0
    local diagnostic_pattern='BUG:|WARNING:|KASAN:|KCSAN:|UBSAN:|general protection fault|kernel BUG at|Unable to handle kernel|scheduling while atomic|possible circular locking|refcount_t:|rcu.*stall|INFO: task .* blocked'
    trap - EXIT INT TERM
    if [[ -n "$CHILD_PID" ]]; then
        kill -TERM "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
        CHILD_PID=""
    fi
    if [[ $OWN_MODULE -eq 1 ]]; then
        # Closing BPF FDs can release module references after an RCU grace period.
        for attempt in {1..10}; do
            if rmmod bpfima >>"$OUTPUT_DIR/unload.log" 2>&1; then
                unloaded=1
                break
            fi
            sleep 1
        done
        if [[ $unloaded -eq 1 ]]; then
            if [[ -d /sys/module/bpfima || -e "$SECURITYFS_DIR/status" || -e /sys/kernel/btf/bpfima ]]; then
                echo "FAIL: module unload left module/BTF/SecurityFS state" >&2
                cleanup_failed=1
            else
                echo "PASS: module unload removes module, BTF, and SecurityFS state"
            fi
        else
            echo "FAIL: module unload failed; see $OUTPUT_DIR/unload.log" >&2
            cleanup_failed=1
        fi
    fi
    # Include delayed RCU/cleanup diagnostics in the captured kernel log.
    sleep 1
    if ! dmesg --since "$STARTED_AT" >"$OUTPUT_DIR/dmesg-run.log"; then
        echo "FAIL: could not collect the run's kernel log" >&2
        cleanup_failed=1
    else
        grep -Ei "$diagnostic_pattern" \
            "$OUTPUT_DIR/dmesg-run.log" >"$OUTPUT_DIR/kernel-errors.log" || log_status=$?
        case "$log_status" in
            0)
                echo "FAIL: kernel warning/sanitizer report; see $OUTPUT_DIR/kernel-errors.log" >&2
                grep -Ein -B 5 -A 60 "$diagnostic_pattern" "$OUTPUT_DIR/dmesg-run.log" \
                    >"$OUTPUT_DIR/kernel-warning-context.log" || true
                cat "$OUTPUT_DIR/kernel-warning-context.log" >&2
                cleanup_failed=1
                ;;
            1) echo "PASS: no kernel warning or sanitizer report during the run" ;;
            *)
                echo "FAIL: could not scan the kernel log" >&2
                cleanup_failed=1
                ;;
        esac
    fi
    [[ -z "$TEMPORARY_DIR" ]] || rm -rf -- "$TEMPORARY_DIR"
    if [[ $exit_code -eq 0 && $cleanup_failed -ne 0 ]]; then
        exit_code=1
    fi
    printf 'exit_code=%d\nkernel=%s\nstress=%d\n' "$exit_code" "$(uname -r)" "$STRESS" >"$OUTPUT_DIR/result.txt"
    echo "Results: $OUTPUT_DIR"
    exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

TEMPORARY_DIR="$(mktemp -d /tmp/bpfima-kernel-suite-XXXXXX)"

if [[ ! -d /sys/module/bpfima ]]; then
    insmod "$BUILD_DIR/bpfima.ko" >"$OUTPUT_DIR/load.log" 2>&1 || error "Module load failed; see $OUTPUT_DIR/load.log"
    OWN_MODULE=1
    [[ -r /sys/kernel/btf/bpfima && -r "$SECURITYFS_DIR/status" ]] || error "Loaded module did not publish BTF and SecurityFS"
    echo "PASS: module load publishes BTF and SecurityFS"
else
    echo "Using existing module; it will remain loaded after the tests"
fi

run_suite() {
    local name="$1"
    shift
    local status=0

    echo "Running $name ..."
    TMPDIR="$TEMPORARY_DIR" timeout --signal=TERM --kill-after=15s "${TIMEOUT_SECONDS}s" \
        "$@" >"$OUTPUT_DIR/$name.log" 2>&1 &
    CHILD_PID=$!
    wait "$CHILD_PID" || status=$?
    CHILD_PID=""
    cat "$OUTPUT_DIR/$name.log"
    if [[ $status -ne 0 ]]; then
        echo "FAIL: $name exited with status $status" >&2
        RESULT=1
    fi
}

run_suite security-regression "$BUILD_DIR/security-regression" "$BUILD_DIR/security-regression.bpf.o" "$BUILD_DIR"
INTERACTION_ARGS=("$BUILD_DIR/module-interactions" "$BUILD_DIR/module-interactions.bpf.o" "$SECURITYFS_DIR")
[[ $STRESS -eq 0 ]] || INTERACTION_ARGS+=(--stress)
run_suite module-interactions "${INTERACTION_ARGS[@]}"
exit "$RESULT"
