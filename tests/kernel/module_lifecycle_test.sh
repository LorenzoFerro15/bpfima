#!/bin/bash

# Exercise production lifecycle ordering without loading modules or touching BPF.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../../scripts/test_utils.sh"
TEST_ROOT="$(mktemp -d /tmp/bpfima-lifecycle-XXXXXX)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export TEST_ROOT

cat > "$TEST_ROOT/bpfima-tool" <<'EOF'
#!/bin/bash
set -euo pipefail
echo "$1" >> "$TEST_ROOT/events"
if [[ "$1" == load ]]; then
    [[ -e "$TEST_ROOT/module" ]]
    echo "new audited state" > "$TEST_ROOT/policy-pin"
    touch "$TEST_ROOT/hooks"
    exit 0
elif [[ "$1" == policy-init ]]; then
    [[ -e "$TEST_ROOT/module" && -e "$TEST_ROOT/policy-pin" ]]
    exit 0
fi
[[ "$1" == unload ]]
if [[ -e "$TEST_ROOT/module" ]]; then
    [[ ! -e "$TEST_ROOT/detach-failure" ]] || exit 1
    rm -f "$TEST_ROOT/hooks"
else
    [[ ! -e "$TEST_ROOT/pin-failure" ]] || exit 1
    rm -f "$TEST_ROOT/hooks" "$TEST_ROOT/policy-pin"
fi
EOF
chmod +x "$TEST_ROOT/bpfima-tool"

lsmod() {
    if [[ -e "$TEST_ROOT/module" ]]; then
        echo "bpfima 126976 1"
    fi
}
rmmod() {
    [[ "$1" == bpfima ]] || return 1
    echo rmmod >> "$TEST_ROOT/events"
    [[ ! -e "$TEST_ROOT/hooks" ]] || return 1
    [[ -e "$TEST_ROOT/policy-pin" ]] || return 1
    local failures
    failures=$(cat "$TEST_ROOT/remove-failures")
    if [[ $failures -gt 0 ]]; then
        echo $((failures - 1)) > "$TEST_ROOT/remove-failures"
        return 1
    fi
    rm "$TEST_ROOT/module"
}
sleep() { :; }
sudo() { "$@"; }
insmod() {
    [[ ! -e "$TEST_ROOT/module" && ! -e "$TEST_ROOT/policy-pin" ]] || return 1
    echo insmod >> "$TEST_ROOT/events"
    touch "$TEST_ROOT/module"
}
wait_for_module() { [[ -e "$TEST_ROOT/module" ]]; }
wait_for_securityfs() { [[ -e "$TEST_ROOT/module" ]]; }

reset_fixture() {
    rm -f "$TEST_ROOT/module" "$TEST_ROOT/hooks" "$TEST_ROOT/detach-failure" "$TEST_ROOT/pin-failure"
    echo "old audited state" > "$TEST_ROOT/policy-pin"
    echo 0 > "$TEST_ROOT/remove-failures"
    : > "$TEST_ROOT/events"
}
assert_released() {
    [[ ! -e "$TEST_ROOT/module" && ! -e "$TEST_ROOT/hooks" && ! -e "$TEST_ROOT/policy-pin" ]]
}

reset_fixture
touch "$TEST_ROOT/module" "$TEST_ROOT/hooks"
cleanup_bpfima_epoch "$TEST_ROOT"
assert_released
[[ $(cat "$TEST_ROOT/events") == $'unload\nrmmod\nunload' ]]
echo "PASS: live authority survives hook detach and is unpinned only after module removal"

reset_fixture
cleanup_bpfima_epoch "$TEST_ROOT"
assert_released
cleanup_bpfima_epoch "$TEST_ROOT"
assert_released
echo "PASS: stale pins are removed when the module is absent; repeated cleanup succeeds"

reset_fixture
touch "$TEST_ROOT/module" "$TEST_ROOT/hooks"
echo 2 > "$TEST_ROOT/remove-failures"
cleanup_bpfima_epoch "$TEST_ROOT"
assert_released
[[ $(cat "$TEST_ROOT/events") == $'unload\nrmmod\nrmmod\nrmmod\nunload' ]]
echo "PASS: delayed module-reference release is retried before policy pin removal"

reset_fixture
touch "$TEST_ROOT/module" "$TEST_ROOT/hooks"
echo 10 > "$TEST_ROOT/remove-failures"
if cleanup_bpfima_epoch "$TEST_ROOT"; then
    echo "FAIL: busy module was reported as removed" >&2
    exit 1
fi
[[ -e "$TEST_ROOT/module" && ! -e "$TEST_ROOT/hooks" ]]
[[ $(cat "$TEST_ROOT/policy-pin") == "old audited state" ]]
[[ $(tail -1 "$TEST_ROOT/events") == rmmod ]]
echo "PASS: failed module removal preserves the authority pin and reports failure"

reset_fixture
touch "$TEST_ROOT/module" "$TEST_ROOT/hooks" "$TEST_ROOT/detach-failure"
if cleanup_bpfima_epoch "$TEST_ROOT"; then
    echo "FAIL: hook detach failure was ignored" >&2
    exit 1
fi
[[ -e "$TEST_ROOT/module" && -e "$TEST_ROOT/hooks" && -e "$TEST_ROOT/policy-pin" ]]
[[ $(cat "$TEST_ROOT/events") == unload ]]
echo "PASS: hook cleanup failure prevents module removal"

reset_fixture
touch "$TEST_ROOT/module" "$TEST_ROOT/hooks" "$TEST_ROOT/pin-failure"
if cleanup_bpfima_epoch "$TEST_ROOT"; then
    echo "FAIL: stale pin cleanup failure was ignored" >&2
    exit 1
fi
[[ ! -e "$TEST_ROOT/module" && -e "$TEST_ROOT/policy-pin" ]]
echo "PASS: pin cleanup failure prevents a successful epoch reset"

reset_fixture
load_bpf_hook "$TEST_ROOT/hook.o" "$TEST_ROOT"
[[ $(cat "$TEST_ROOT/events") == $'unload\ninsmod\nload\npolicy-init' ]]
[[ $(cat "$TEST_ROOT/policy-pin") == "new audited state" ]]
echo "PASS: shared hook loader cleans stale pins before loading a fresh module"

: > "$TEST_ROOT/events"
load_bpf_hook "$TEST_ROOT/hook.o" "$TEST_ROOT"
[[ $(cat "$TEST_ROOT/events") == $'load\npolicy-init' ]]
cleanup_bpf "$TEST_ROOT"
assert_released
echo "PASS: shared hook reload retains the live module; privileged cleanup retires its pin"
