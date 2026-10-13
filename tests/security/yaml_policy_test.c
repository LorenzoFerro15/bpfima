#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "../../tools/yaml_parser.h"

static int parse_text(const char *text, struct yaml_policy *policy,
                      char cgroups[][256], char paths[][256], struct yaml_hook_config *hooks)
{
    char path[] = "/tmp/bpfima-yaml-test-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *file = fdopen(fd, "w");
    assert(file && fputs(text, file) >= 0 && fclose(file) == 0);
    int ret = parse_yaml_policy(path, policy, cgroups, MAX_CGROUP_PATTERNS,
                                paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS);
    unlink(path);
    return ret;
}

int main(void)
{
    struct yaml_policy policy;
    char cgroups[MAX_CGROUP_PATTERNS][256];
    char paths[MAX_PATH_PATTERNS][256];
    struct yaml_hook_config hooks[MAX_HOOK_CONFIGS];
    const char *valid = "policy:\n  enabled: true\n  log_level: 2\n  measure_enabled: true\n"
                        "hooks:\n  - name: lsm_socket_connect\n    enabled: true\n"
                        "  - name: lsm_bprm_check_security\n    enabled: true\n";

    memset(hooks, 0x41, sizeof(hooks));
    assert(parse_text(valid, &policy, cgroups, paths, hooks) == 0);
    for (size_t i = 2 * sizeof(*hooks); i < sizeof(hooks); i++)
        assert(((unsigned char *)hooks)[i] == 0);
    struct bpfima_policy_snapshot snapshot;
    assert(build_policy_from_yaml(&snapshot, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == 0);
    assert(snapshot.config.enabled == 1 && snapshot.config.log_level == 2 &&
           (snapshot.config.action_flags & POLICY_ACTION_EXTEND_TPM));
    assert(snapshot.hooks[HOOK_LSM_SOCKET_CONNECT].flags & HOOK_FLAG_ENABLED);
    assert(snapshot.hooks[HOOK_LSM_BPRM_CHECK_SECURITY].flags & HOOK_FLAG_ENABLED);
    assert(snapshot.hooks[HOOK_LSM_INODE_SETATTR].flags & HOOK_FLAG_ENABLED);
    for (int i = 0; i < MAX_IGNORE_PATTERNS; i++)
        assert(!snapshot.cgroups[i].enabled && !snapshot.paths[i].enabled);
    snprintf(hooks[0].hook_name, sizeof(hooks[0].hook_name), "unknown_hook");
    assert(build_policy_from_yaml(&snapshot, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == -EINVAL);
    policy.measure_enabled = 0;
    assert(build_policy_from_yaml(&snapshot, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == -EINVAL);
    const char *invalid[] = {"policy:\n  enabled: typo\n", "policy:\n  log_level: -1\n",
                             "policy:\n  log_level: 4294967296\n", "policy:\n  unknown: true\n",
                             "filters:\n  cgroup_patterns: [a,b,c,d,e,f,g,h,i]\n",
                             "filters:\n  path_patterns: [abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl]\n"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        assert(parse_text(invalid[i], &policy, cgroups, paths, hooks) < 0);
    assert(parse_yaml_policy("config/policy.yaml", &policy, cgroups, MAX_CGROUP_PATTERNS,
                             paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == 0);
    assert(parse_yaml_policy("config/policy-minimal.yaml", &policy, cgroups, MAX_CGROUP_PATTERNS,
                             paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == 0);
    assert(parse_text("policy:\n  enabled: true\n  measure_enabled: true\n  log_level: 2\n  filter_flags: 0x10\n  min_file_size: 8192\n  max_path_depth: 16\n", &policy, cgroups, paths, hooks) == 0);
    assert(build_policy_from_yaml(&snapshot, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == 0);
    assert(snapshot.config.filter_flags == 16 && snapshot.config.min_file_size == 8192 && snapshot.config.max_path_depth == 16);
    policy.appraise_enabled = 1;
    assert(build_policy_from_yaml(&snapshot, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == -EOPNOTSUPP);
    puts("PASS: YAML initialization, complete policy snapshots, named hooks, and invalid values");
    return 0;
}
