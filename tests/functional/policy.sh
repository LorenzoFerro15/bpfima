#!/bin/bash

set -e

# VERIFY THAT POLICY MAPS ARE CORRECTLY UPDATED

# Configuration
MAP_DIR="/sys/fs/bpf"
POLICY_MAP="${MAP_DIR}/bpfima_policy_map"
CGROUP_MAP="${MAP_DIR}/bpfima_cgroup_patterns_map"
PATH_MAP="${MAP_DIR}/bpfima_path_patterns_map"
HOOK_MAP="${MAP_DIR}/bpfima_hook_config_map"

test_result() {
    if [ $? -eq 0 ]; then
        echo "  [PASS] $1"
    else
        echo "  [FAIL] $1"
        exit 1
    fi
}

verify_policy_map() {
    local exp_enabled=$1
    local exp_log=$2
    local exp_size=$3
    local exp_depth=$4
    local exp_actions=$5
    local exp_filters=$6

    echo "  Verifying Main Policy (En=$exp_enabled, Log=$exp_log, Size=$exp_size, Depth=$exp_depth, Actions=$exp_actions, Filters=$exp_filters)..."

    local dump=$(bpftool map dump pinned "$POLICY_MAP" -j)

    # Target .formatted.value instead of .value
    local act_enabled=$(echo "$dump" | jq -r '.[0].formatted.value.enabled // 0')
    local act_log=$(echo "$dump" | jq -r '.[0].formatted.value.log_level // 0')
    local act_size=$(echo "$dump" | jq -r '.[0].formatted.value.min_file_size // 0')
    local act_depth=$(echo "$dump" | jq -r '.[0].formatted.value.max_path_depth // 0')
    local act_actions=$(echo "$dump" | jq -r '.[0].formatted.value.action_flags // 0')
    local act_filters=$(echo "$dump" | jq -r '.[0].formatted.value.filter_flags // 0')

    [ "$act_enabled" == "$exp_enabled" ] || { echo "FAIL: enabled mismatch (got $act_enabled, exp $exp_enabled)"; exit 1; }
    [ "$act_log" == "$exp_log" ] || { echo "FAIL: log_level mismatch (got $act_log, exp $exp_log)"; exit 1; }
    [ "$act_size" == "$exp_size" ] || { echo "FAIL: min_file_size mismatch (got $act_size, exp $min_file_size)"; exit 1; }
    [ "$act_depth" == "$exp_depth" ] || { echo "FAIL: max_path_depth mismatch (got $act_depth, exp $exp_depth)"; exit 1; }
    [ "$act_actions" == "$exp_actions" ] || { echo "FAIL: action_flags mismatch (got $act_actions, exp $exp_actions)"; exit 1; }
    [ "$act_filters" == "$exp_filters" ] || { echo "FAIL: filter_flags mismatch (got $act_filters, exp $exp_filters)"; exit 1; }
    test_result "Main Policy verified"
}

verify_pattern() {
    local map_path=$1
    local key=$2
    local exp_pattern=$3
    local exp_enabled=$4
    local exp_match_type=$5
    local map_name=$(basename "$map_path")

    local dump=$(bpftool map dump pinned "$map_path" -j)

    # Target .formatted.key and .formatted.value
    local act_enabled=$(echo "$dump" | jq -r ".[] | select((.formatted.key | tostring) == \"$key\") | .formatted.value.enabled // 0")
    local act_match=$(echo "$dump" | jq -r ".[] | select((.formatted.key | tostring) == \"$key\") | .formatted.value.match_type // 0")
    local act_pattern=$(echo "$dump" | jq -r ".[] | select((.formatted.key | tostring) == \"$key\") | .formatted.value.pattern | if type==\"string\" then . else (map(select(. > 0)) | implode) end // \"\"")

    [ "$act_pattern" == "$exp_pattern" ] || { echo "FAIL: $map_name key $key pattern mismatch (got '$act_pattern', exp '$exp_pattern')"; exit 1; }
    [ "$act_enabled" == "$exp_enabled" ] || { echo "FAIL: $map_name key $key enabled mismatch (got $act_enabled, exp $exp_enabled)"; exit 1; }
    [ "$act_match" == "$exp_match_type" ] || { echo "FAIL: $map_name key $key match_type mismatch (got $act_match, exp $exp_match_type)"; exit 1; }
    test_result "$map_name Key $key verified"
}

verify_hook() {
    local key=$1
    local exp_flags=$2

    local dump=$(bpftool map dump pinned "$HOOK_MAP" -j)
    local act_flags=$(echo "$dump" | jq -r ".[] | select((.formatted.key | tostring) == \"$key\") | .formatted.value.flags // 0")

    [ "$act_flags" == "$exp_flags" ] || { echo "FAIL: Hook $key flags mismatch (got $act_flags, exp $exp_flags)"; exit 1; }
    test_result "Hook $key verified"
}

# --- PHASE 1: Apply Policy 1 ---
echo "=== Phase 1: Applying Policy 1 ==="
kubectl apply -f policy1.yaml
sleep 5 # Wait for reconciliation

# Expected: Enabled(1), Log(2), Size(100), Depth(32), Actions(127), Filters(255)
verify_policy_map 1 2 100 32 127 255

# Cgroup Patterns (Map, Key, Pattern, Enabled, MatchType)
verify_pattern "$CGROUP_MAP" 0 "/" 1 0
verify_pattern "$CGROUP_MAP" 1 "init.scope" 1 0

# Path Patterns (Map, Key, Pattern, Enabled, MatchType)
verify_pattern "$PATH_MAP" 0 "/proc/" 1 1
verify_pattern "$PATH_MAP" 1 "/sbin/" 1 1
verify_pattern "$PATH_MAP" 2 "/afs/" 1 1

# Hooks (0: lsm_bprm_check_security enabled=7, ...)
verify_hook 0 7
verify_hook 1 7
verify_hook 2 7
verify_hook 3 7
verify_hook 4 7
verify_hook 5 7
verify_hook 6 7


# --- PHASE 2: Apply Policy 2 ---
echo ""
echo "=== Phase 2: Applying Policy 2 ==="
kubectl apply -f policy2.yaml
sleep 3

verify_policy_map 1 1 0 16 0 0

verify_pattern "$CGROUP_MAP" 0 "/" 1 0
verify_pattern "$CGROUP_MAP" 1 "system.slice" 1 1

verify_pattern "$PATH_MAP" 0 "/dev/" 1 1
verify_pattern "$PATH_MAP" 1 "/tmp/" 1 1
verify_pattern "$PATH_MAP" 2 "/bin/" 1 1

verify_hook 0 0
verify_hook 1 0
verify_hook 2 0
verify_hook 3 0
verify_hook 4 0
verify_hook 5 0
verify_hook 6 0


# --- PHASE 3: Remove Policies & Check Default ---
echo ""
echo "=== Phase 3: Removing Policies (Fallback to Default) ==="
kubectl delete Policy policy-1
kubectl delete Policy policy-2
sleep 3

verify_policy_map 1 2 0 32 103 0

verify_pattern "$CGROUP_MAP" 0 "/" 1 0
verify_pattern "$CGROUP_MAP" 1 "init.scope" 1 0

verify_pattern "$PATH_MAP" 0 "/proc/" 1 1
verify_pattern "$PATH_MAP" 1 "/sys/" 1 1

verify_hook 0 7
verify_hook 1 7
verify_hook 2 7
verify_hook 3 7
verify_hook 4 7
verify_hook 5 7
verify_hook 6 0

echo ""
echo "All policy transitions verified successfully!"
exit 0