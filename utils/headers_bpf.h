#ifndef HEADERS_BPF_H
#define HEADERS_BPF_H

/* Headers for BPF hooks */
#include "../vmlinux.h"
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

/* Policy helper functions for BPF hooks */
static __always_inline int bpfima_strcmp_n(const char *s1, const char *s2, int n)
{
    #pragma unroll
    for (int i = 0; i < 32 && i < n; i++) {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

/* Simple prefix match */
static __always_inline bool bpfima_starts_with(const char *str, const char *prefix)
{
    if (!str || !prefix)
        return false;
    
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (prefix[i] == '\0')
            return true;
        if (str[i] != prefix[i])
            return false;
    }
    return true;
}

static __always_inline bool bpfima_should_ignore_cgroup(const char *cgroup_name, struct bpfima_policy_config *policy)
{
    if (!policy) {
        if (bpfima_strcmp_n(cgroup_name, "/", 2) == 0 && cgroup_name[1] == '\0')
            return true;  /* Exact match for "/" only */
        if (bpfima_strcmp_n(cgroup_name, "init.scope", 11) == 0)
            return true;
        return false;
    }
    
    if (!(policy->filter_flags & POLICY_FILTER_SYSTEM_CGROUPS)) {
        return false;
    }
    
    if (bpfima_strcmp_n(cgroup_name, "/", 2) == 0 && cgroup_name[1] == '\0')
        return true;  
    if (bpfima_strcmp_n(cgroup_name, "init.scope", 11) == 0)
        return true;
    
    return false;
}

static __always_inline bool bpfima_should_ignore_path(const char *path, struct bpfima_policy_config *policy)
{
    if (!policy) {
        if (bpfima_starts_with(path, "/proc/"))
            return true;
        if (bpfima_starts_with(path, "/sys/"))
            return true;
        return false;
    }
    
    if (!(policy->filter_flags & POLICY_FILTER_PROC_SYS)) {
        return false;
    }
    
    if (bpfima_starts_with(path, "/proc/"))
        return true;
    if (bpfima_starts_with(path, "/sys/"))
        return true;
    
    return false;
}

/* Check if cgroup name represents an actual container (not just any cgroup) */
static __always_inline bool bpfima_is_container_cgroup(const char *cgroup_name)
{
    if (!cgroup_name || cgroup_name[0] == '\0')
        return false;
    
    /* Filter out root and system management cgroups */
    if (bpfima_strcmp_n(cgroup_name, "/", 2) == 0 && cgroup_name[1] == '\0')
        return false;  /* Root cgroup */
    if (bpfima_strcmp_n(cgroup_name, "init.scope", 11) == 0)
        return false;
    if (bpfima_strcmp_n(cgroup_name, "system.slice", 13) == 0)
        return false;  /* System services, not containers */
    if (bpfima_strcmp_n(cgroup_name, "user.slice", 11) == 0)
        return false;  /* User processes, not containers */
    
    /* Any other cgroup name is likely a container */
    /* Real containers typically have names like:
     * - docker-<hash>.scope
     * - libpod-<hash>.scope  
     * - cri-containerd-<hash>.scope
     * - Or custom names
     */
    return true;
}

/* Get main policy configuration */
static __always_inline struct bpfima_policy_config *bpfima_get_policy(void)
{
    __u32 key = 0;
    struct bpfima_policy_config *policy = bpf_map_lookup_elem(&bpfima_policy_map, &key);
    return policy;
}

/* Get hook-specific configuration */
static __always_inline struct bpfima_hook_config *bpfima_get_hook_config(enum bpfima_hook_id hook_id)
{
    __u32 key = hook_id;
    struct bpfima_hook_config *cfg = bpf_map_lookup_elem(&bpfima_hook_config_map, &key);
    return cfg;
}

/* Check if hook should process based on policy */
static __always_inline bool bpfima_should_process(enum bpfima_hook_id hook_id)
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