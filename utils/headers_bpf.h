#ifndef HEADERS_BPF_H
#define HEADERS_BPF_H

/* Headers for BPF hooks */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
/* Policy configuration structures (userspace-compatible definitions) */
#define MAX_IGNORE_PATTERNS 8  
#define MAX_PATTERN_LEN 64
#define MAX_PATH_FILTERS 8 

/* Policy filter flags */
#define POLICY_FILTER_SYSTEM_CGROUPS    (1 << 0)
#define POLICY_FILTER_PROC_SYS          (1 << 1)
#define POLICY_FILTER_DEV               (1 << 2)
#define POLICY_FILTER_READONLY_FILES    (1 << 3)
#define POLICY_FILTER_SMALL_FILES       (1 << 4)
#define POLICY_FILTER_NON_EXECUTABLE    (1 << 5)
#define POLICY_FILTER_LIBRARIES         (1 << 6)
#define POLICY_FILTER_TMP_FILES         (1 << 7)

/* Policy action flags */
#define POLICY_ACTION_EXTEND_TPM        (1 << 0)
#define POLICY_ACTION_LOG_SECURITYFS    (1 << 1)
#define POLICY_ACTION_LOG_KERNEL        (1 << 2)
#define POLICY_ACTION_ALERT_SUSPICIOUS  (1 << 3)
#define POLICY_ACTION_BLOCK             (1 << 4)
#define POLICY_ACTION_TRACK_CONTAINER   (1 << 5)
#define POLICY_ACTION_BUILD_DEPS        (1 << 6)

/* Hook-specific flags */
#define HOOK_FLAG_ENABLED               (1 << 0)
#define HOOK_FLAG_TRACK_CONTAINERS      (1 << 1)
#define HOOK_FLAG_MEASURE_HASH          (1 << 2)

/* Hook identifiers */
enum bpfima_hook_id {
    HOOK_LSM_BPRM_CHECK_SECURITY = 0,
    HOOK_LSM_FILE_OPEN,
    HOOK_LSM_FILE_POST_OPEN,
    HOOK_LSM_MMAP_FILE,
    HOOK_LSM_SOCKET_CONNECT,
    HOOK_LSM_CONTAINER_EVENTS,
    HOOK_KPROBE_FILE_OPEN,
    HOOK_MAX
};

/* Policy configuration structure (BPF-compatible) */
struct bpfima_policy_config {
    __u8 enabled;
    __u32 filter_flags;
    __u32 action_flags;
    __u32 min_file_size;
    __u32 max_path_depth;
    __u32 log_level;
    __u32 reserved[2];
};

/* Pattern entry for matching */
struct bpfima_pattern_entry {
    char pattern[MAX_PATTERN_LEN];
    __u8 enabled;
    __u8 match_type;
    __u16 reserved;
};

/* Per-hook configuration */
struct bpfima_hook_config {
    __u32 flags;
    __u32 filter_override;
    __u32 action_override;
    __u32 reserved[1];
};

/* Global policy map - single entry with main configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpfima_policy_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpfima_policy_map SEC(".maps");

/* Cgroup ignore patterns map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpfima_pattern_entry);
    __uint(max_entries, MAX_IGNORE_PATTERNS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpfima_cgroup_patterns_map SEC(".maps");

/* Path ignore patterns map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpfima_pattern_entry);
    __uint(max_entries, MAX_PATH_FILTERS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpfima_path_patterns_map SEC(".maps");

/* Per-hook configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpfima_hook_config);
    __uint(max_entries, HOOK_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bpfima_hook_config_map SEC(".maps");

/* Helper struct useful to prevent the verifier from losing track of a string size */
struct string_ctx {
    char data[MAX_PATTERN_LEN];
};

#include "bpf_kfunc_defs.h"

/* Policy helper functions for BPF hooks */

static __attribute__((noinline, unused)) bool bpfima_should_ignore_cgroup(const char *cgroup_name, struct bpfima_policy_config *policy)
{
    u32 filter_flags = policy ? policy->filter_flags : POLICY_FILTER_SYSTEM_CGROUPS;
    return bpfima_policy_should_ignore_cgroup(cgroup_name, filter_flags);
}

static __attribute__((noinline, unused)) bool bpfima_should_ignore_path(const char *path, struct bpfima_policy_config *policy)
{
    u32 filter_flags = policy ? policy->filter_flags : POLICY_FILTER_PROC_SYS;
    return bpfima_policy_should_ignore_path(path, filter_flags);
}

static __attribute__((noinline, unused)) bool bpfima_is_container_cgroup(const char *cgroup_name)
{
    if (!cgroup_name || cgroup_name[0] == '\0')
        return false;

    if (cgroup_name[0] == '/' && cgroup_name[1] == '\0')
        return false;
    if (cgroup_name[0] == 'i' && cgroup_name[1] == 'n')
        return false;
    if (cgroup_name[0] == 's' && cgroup_name[1] == 'y')
        return false;
    if (cgroup_name[0] == 'u' && cgroup_name[1] == 's')
        return false;

    return true;
}

static __attribute__((noinline, unused)) struct bpfima_policy_config *bpfima_get_policy(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&bpfima_policy_map, &key);
}

static __attribute__((noinline, unused)) struct bpfima_hook_config *bpfima_get_hook_config(enum bpfima_hook_id hook_id)
{
    __u32 key = hook_id;
    return bpf_map_lookup_elem(&bpfima_hook_config_map, &key);
}

static __attribute__((noinline, unused)) bool bpfima_should_process(enum bpfima_hook_id hook_id)
{
    struct bpfima_policy_config *policy = bpfima_get_policy();
    if (!policy)
        return true;
    
    if (!policy->enabled)
        return false;
    
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(hook_id);
    if (!hook_cfg)
        return true;
    
    if (!(hook_cfg->flags & HOOK_FLAG_ENABLED))
        return false;
    
    return true;
}

#endif /* HEADERS_BPF_H */