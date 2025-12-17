/**
 * bpfima_policy_user.h - Userspace policy definitions
 *
 * This header provides userspace-compatible policy definitions that match
 * the kernel-side policy structures defined in bpfima_policy.h.
 *
 * Use this header in userspace tools to avoid duplicating policy flag definitions.
 */

#ifndef BPFIMA_POLICY_USER_H
#define BPFIMA_POLICY_USER_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAX_IGNORE_PATTERNS 32
#define MAX_PATTERN_LEN 64

#define MAX_PATH_FILTERS 64

/* Policy filter flags (what to filter/skip) - must match bpfima_policy.h */
#define POLICY_FILTER_SYSTEM_CGROUPS (1 << 0) /* Filter system cgroups */
#define POLICY_FILTER_PROC_SYS (1 << 1)       /* Filter /proc, /sys paths */
#define POLICY_FILTER_DEV (1 << 2)            /* Filter /dev paths */
#define POLICY_FILTER_READONLY_FILES (1 << 3) /* Filter readonly file opens */
#define POLICY_FILTER_SMALL_FILES (1 << 4)    /* Filter files below min size */
#define POLICY_FILTER_NON_EXECUTABLE (1 << 5) /* Filter non-executable files */
#define POLICY_FILTER_LIBRARIES (1 << 6)      /* Filter .so libraries */
#define POLICY_FILTER_TMP_FILES (1 << 7)      /* Filter /tmp files */

/* Policy action flags (what to do when matched) - must match bpfima_policy.h */
#define POLICY_ACTION_EXTEND_TPM (1 << 0)       /* Extend measurement to TPM */
#define POLICY_ACTION_LOG_SECURITYFS (1 << 1)   /* Log to securityfs */
#define POLICY_ACTION_LOG_KERNEL (1 << 2)       /* Log to kernel log (printk) */
#define POLICY_ACTION_ALERT_SUSPICIOUS (1 << 3) /* Alert on suspicious activity */
#define POLICY_ACTION_BLOCK (1 << 4)            /* Block the operation (future) */
#define POLICY_ACTION_TRACK_CONTAINER (1 << 5)  /* Track per-container */
#define POLICY_ACTION_BUILD_DEPS (1 << 6)       /* Build dependency chain */

/* Hook-specific flags - must match bpfima_policy.h */
#define HOOK_FLAG_ENABLED (1 << 0)          /* Hook is enabled */
#define HOOK_FLAG_TRACK_CONTAINERS (1 << 1) /* Track containers in this hook */
#define HOOK_FLAG_MEASURE_HASH (1 << 2)     /* Calculate file hashes */

/**
 * struct bpfima_policy_config - Main policy configuration
 * Must match kernel-side struct bpfima_policy_config
 */
struct bpfima_policy_config
{
    u8 enabled;
    u32 filter_flags;
    u32 action_flags;
    u32 min_file_size;
    u32 max_path_depth;
    u32 log_level;
    u32 reserved[2];
};

/**
 * struct bpfima_pattern_entry - Pattern for matching
 * Must match kernel-side struct bpfima_pattern_entry
 */
struct bpfima_pattern_entry
{
    char pattern[MAX_PATTERN_LEN];
    u8 enabled;
    u8 match_type;
    u16 reserved;
};

/**
 * struct bpfima_hook_config - Per-hook configuration
 * Must match kernel-side struct bpfima_hook_config
 */
struct bpfima_hook_config
{
    u32 flags;
    u32 filter_override;
    u32 action_override;
    u32 reserved[1];
};

/* Hook identifiers - must match kernel-side enum bpfima_hook_id */
enum bpfima_hook_id
{
    HOOK_LSM_BPRM_CHECK_SECURITY = 0,
    HOOK_LSM_FILE_OPEN,
    HOOK_LSM_FILE_POST_OPEN,
    HOOK_LSM_MMAP_FILE,
    HOOK_LSM_SOCKET_CONNECT,
    HOOK_LSM_CONTAINER_EVENTS,
    HOOK_KPROBE_FILE_OPEN,
    HOOK_MAX
};

/* Default policy values */
#define DEFAULT_FILTER_FLAGS 0

#define DEFAULT_ACTION_FLAGS (POLICY_ACTION_EXTEND_TPM |      \
                              POLICY_ACTION_LOG_SECURITYFS |  \
                              POLICY_ACTION_LOG_KERNEL |      \
                              POLICY_ACTION_TRACK_CONTAINER | \
                              POLICY_ACTION_BUILD_DEPS)

#define DEFAULT_MIN_FILE_SIZE 0
#define DEFAULT_MAX_PATH_DEPTH 32
#define DEFAULT_LOG_LEVEL 2 

/* Default Patterns - must match bpfima_policy.h */
#define DEFAULT_CGROUP_PATTERN_1 "/"
#define DEFAULT_CGROUP_PATTERN_2 "init.scope"
#define DEFAULT_PATH_PATTERN_1 "/proc/"
#define DEFAULT_PATH_PATTERN_2 "/sys/" 

#endif /* BPFIMA_POLICY_USER_H */
