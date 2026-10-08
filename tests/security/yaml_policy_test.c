#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "../../tools/yaml_parser.h"

static struct bpfima_policy_config written_policy;
static __u32 hook_keys[MAX_HOOK_CONFIGS];
static int hook_count;
static int cleared_patterns;
static int fail_fd;

/* Check the production parser/updater without modifying kernel maps. */
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    (void)flags;
    if (fd == fail_fd) {
        errno = EIO;
        return -1;
    }
    if (fd == 1)
        memcpy(&written_policy, value, sizeof(written_policy));
    if (fd == 4)
        hook_keys[hook_count++] = *(__u32 *)key;
    if ((fd == 2 || fd == 3) && !((struct bpfima_pattern_entry *)value)->enabled)
        cleared_patterns++;
    return 0;
}

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
    assert(update_maps_from_policy(1, 2, 3, 4, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) == 0);
    assert(hook_count == 2 && hook_keys[0] == HOOK_LSM_SOCKET_CONNECT &&
           hook_keys[1] == HOOK_LSM_BPRM_CHECK_SECURITY);
    assert(cleared_patterns == MAX_CGROUP_PATTERNS + MAX_PATH_PATTERNS);
    assert(written_policy.enabled == 1 && written_policy.log_level == 2 &&
           (written_policy.action_flags & POLICY_ACTION_EXTEND_TPM));
    fail_fd = 2;
    assert(update_maps_from_policy(1, 2, 3, 4, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                   paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS) < 0);
    fail_fd = 0;
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
    puts("PASS: YAML initialization, named hooks, pattern replacement, invalid values, and update errors");
    return 0;
}
