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

/* Policy helper functions for BPF hooks */
/* Compute the length of a string, '\0' excluded */
static __always_inline int bpfima_strlen(const char *str)
{
    if (!str)
        return 0;

    int len = 0;

    for (int i = 0; i < MAX_PATTERN_LEN; i++) {
        if (str[i] == '\0') {
            break;
        }
        len++;
    }

    return len;
}

/* Verify if the two strings match */
static __always_inline int bpfima_strcmp_n(const char *s1, const char *s2, int n)
{
    if (!s1 || !s2)
        return false;

    for (int i = 0; i < MAX_PATTERN_LEN && i < n; i++) {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

/* Verify if str has as prefix the given substring */
static __always_inline bool bpfima_starts_with(const char *str, const char *prefix, int len_str, int len_prefix)
{
    if (!str || !prefix)
        return false;

    if (len_str < len_prefix || len_prefix == 0 || len_prefix >= MAX_PATTERN_LEN)
        return false;

    for (int i = 0; i < len_prefix; i++) {
        if (str[i] != prefix[i])
            return false;
    }
    return true;
}

/* Verify if str has as suffix the given substring */
static __always_inline bool bpfima_ends_with(const char *str, const char *suffix, int len_str, int len_suffix)
{
    if (!str || !suffix)
        return false;

    if (len_str < len_suffix || len_suffix == 0 || len_suffix >= MAX_PATTERN_LEN || len_str >= MAX_PATTERN_LEN)
        return false;

    int start_idx = len_str - len_suffix;

    if (start_idx < 0)
        return false;

    for (int i = 0; i < len_suffix; i++) {
        int idx = start_idx + i;
        if (str[idx] != suffix[i])
            return false;
    }

    return true;
}

/* Verify if str constains the given substring */
static __always_inline bool bpfima_contains(const char *str, const char *contained, int len_str, int len_contained)
{
    if (!str || !contained)
        return false;

    if (len_str < len_contained || len_contained == 0 || len_contained >= MAX_PATTERN_LEN || len_str == 0 || len_str >= MAX_PATTERN_LEN)
        return false;

    int max_start = len_str - len_contained;
    if (max_start < 0 || max_start >= MAX_PATTERN_LEN)
        return false;

    bool found;
    for (int i = 0; i <= max_start; i++) {
        found = true;
        for (int j = 0; j < len_contained; j++) {
            int idx = j + i;
            if (str[idx] != contained[j]) {
                found = false;
                break;
            }
        }
        if (found)
            return true;
    }
    return false;
}

/* This function calls the specific helper functions to verify the match according to the match type specified
*  It is declared as __noinline to prevent state explosion during verification:
*  in this way, it is verified independentely from the rest of the code.
* However, this causes the verifier to lose track of the size of name.
*  Hence the wrapper struct string_ctx is necessary to allow the verifier track the size of this char array.
*/
__noinline bool __bpfima_should_ignore_pattern(const struct string_ctx *name, int len_name, const struct bpfima_pattern_entry *entry) {
    if (!name || !entry)
        return false;

    int len_pattern = bpfima_strlen(entry->pattern);

    if (entry->match_type == 0) {
        if (len_name == len_pattern && bpfima_strcmp_n(name->data, entry->pattern, len_pattern) == 0)
            return true;
    } else if (entry->match_type == 1) {
        if (bpfima_starts_with(name->data, entry->pattern, len_name, len_pattern))
            return true;
    } else if (entry->match_type == 2) {
        if (bpfima_ends_with(name->data, entry->pattern, len_name, len_pattern))
            return true;
    } else if (entry->match_type == 3) {
        if (bpfima_contains(name->data, entry->pattern, len_name, len_pattern))
            return true;
    }

    return false;
}

/* Helper function to check if the given pattern is present in the BPF map */
static __always_inline bool bpfima_should_ignore_pattern(const char *name, void *map) {
    int len_name = bpfima_strlen(name);

    for (__u32 i = 0; i < MAX_IGNORE_PATTERNS; i++) {
        __u32 key = i;
        const struct bpfima_pattern_entry *entry = bpf_map_lookup_elem(map, &key);

        if (!entry || !entry->enabled)
            continue;

        if (__bpfima_should_ignore_pattern((struct string_ctx*)name, len_name, entry))
            return true;
    }

    return false;
}

static __always_inline bool bpfima_should_ignore_cgroup(const char *cgroup_name, struct bpfima_policy_config *policy)
{
    if (!policy) {
        if (bpfima_strcmp_n(cgroup_name, "/", bpfima_strlen("/")) == 0 && cgroup_name[1] == '\0')
            return true;  /* Exact match for "/" only */
        if (bpfima_strcmp_n(cgroup_name, "init.scope", bpfima_strlen("init.scope")) == 0)
            return true;
        return false;
    }

    if (!(policy->filter_flags & POLICY_FILTER_SYSTEM_CGROUPS)) {
        return false;
    }

    return bpfima_should_ignore_pattern(cgroup_name, &bpfima_cgroup_patterns_map);
}

static __always_inline bool bpfima_should_ignore_path(const char *path, struct bpfima_policy_config *policy)
{
    if (!policy) {
        if (bpfima_starts_with(path, "/proc/", bpfima_strlen(path), bpfima_strlen("/proc/")))
            return true;
        if (bpfima_starts_with(path, "/sys/", bpfima_strlen(path), bpfima_strlen("/sys/")))
            return true;
        return false;
    }

    if ((policy->filter_flags & POLICY_FILTER_PROC_SYS)) {
         if (bpfima_starts_with(path, "/proc/", bpfima_strlen(path), bpfima_strlen("/proc/")))
            return true;
        if (bpfima_starts_with(path, "/sys/", bpfima_strlen(path), bpfima_strlen("/sys/")))
            return true;
    }

    if ((policy->filter_flags & POLICY_FILTER_DEV)) {
        if (bpfima_starts_with(path, "/dev/", bpfima_strlen(path), bpfima_strlen("/dev/")))
            return true;
    }

    if ((policy->filter_flags & POLICY_FILTER_TMP_FILES)) {
        if (bpfima_starts_with(path, "/tmp/", bpfima_strlen(path), bpfima_strlen("/tmp/")))
            return true;
    }

    return bpfima_should_ignore_pattern(path, &bpfima_path_patterns_map);

}

/* Check if cgroup name represents an actual container (not just any cgroup) */
static __always_inline bool bpfima_is_container_cgroup(const char *cgroup_name)
{
    if (!cgroup_name || cgroup_name[0] == '\0')
        return false;

    /* Filter out root and system management cgroups */
    if (bpfima_strcmp_n(cgroup_name, "/", bpfima_strlen("/")) == 0 && cgroup_name[1] == '\0')
        return false;  /* Root cgroup */
    if (bpfima_strcmp_n(cgroup_name, "init.scope", bpfima_strlen("init.scope")) == 0)
        return false;
    if (bpfima_strcmp_n(cgroup_name, "system.slice", bpfima_strlen("system.slice")) == 0)
        return false;  /* System services, not containers */
    if (bpfima_strcmp_n(cgroup_name, "user.slice", bpfima_strlen("user.slice")) == 0)
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