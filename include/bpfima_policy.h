#ifndef BPFIMA_POLICY_H
#define BPFIMA_POLICY_H

#include <linux/types.h>

/* Maximum number of ignore patterns */
#define MAX_IGNORE_PATTERNS 32
#define MAX_PATTERN_LEN 64

/* Maximum number of path filters */
#define MAX_PATH_FILTERS 64

/* Policy filter flags (what to filter/skip) */
#define POLICY_FILTER_SYSTEM_CGROUPS    (1 << 0)  /* Filter system cgroups */
#define POLICY_FILTER_PROC_SYS          (1 << 1)  /* Filter /proc, /sys paths */
#define POLICY_FILTER_DEV               (1 << 2)  /* Filter /dev paths */
#define POLICY_FILTER_READONLY_FILES    (1 << 3)  /* Filter readonly file opens */
#define POLICY_FILTER_SMALL_FILES       (1 << 4)  /* Filter files below min size */
#define POLICY_FILTER_NON_EXECUTABLE    (1 << 5)  /* Filter non-executable files */
#define POLICY_FILTER_LIBRARIES         (1 << 6)  /* Filter .so libraries */
#define POLICY_FILTER_TMP_FILES         (1 << 7)  /* Filter /tmp files */

/* Policy action flags (what to do when matched) */
#define POLICY_ACTION_EXTEND_TPM        (1 << 0)  /* Extend measurement to TPM */
#define POLICY_ACTION_LOG_SECURITYFS    (1 << 1)  /* Log to securityfs */
#define POLICY_ACTION_LOG_KERNEL        (1 << 2)  /* Log to kernel log (printk) */
#define POLICY_ACTION_ALERT_SUSPICIOUS  (1 << 3)  /* Alert on suspicious activity */
#define POLICY_ACTION_BLOCK             (1 << 4)  /* Block the operation (future) */
#define POLICY_ACTION_TRACK_CONTAINER   (1 << 5)  /* Track per-container */
#define POLICY_ACTION_BUILD_DEPS        (1 << 6)  /* Build dependency chain */

/* Hook-specific flags */
#define HOOK_FLAG_ENABLED               (1 << 0)  /* Hook is enabled */
#define HOOK_FLAG_TRACK_CONTAINERS      (1 << 1)  /* Track containers in this hook */
#define HOOK_FLAG_MEASURE_HASH          (1 << 2)  /* Calculate file hashes */

/**
 * struct bpfima_policy_config - Main policy configuration
 * @enabled: Global enable/disable flag
 * @filter_flags: Bitmask of POLICY_FILTER_* flags
 * @action_flags: Bitmask of POLICY_ACTION_* flags
 * @min_file_size: Minimum file size to measure (bytes)
 * @max_path_depth: Maximum path depth to track
 * @log_level: Logging verbosity (0=none, 1=errors, 2=info, 3=debug)
 * @merkle_history_max_size: Maximum entries in merkle_root_history before trimming
 * @merkle_history_scope: Scope of circular buffer (0=global, 1=root-only)
 * @reserved: Reserved for future use
 */
struct bpfima_policy_config {
    u8 enabled;
    u32 filter_flags;
    u32 action_flags;
    u32 min_file_size;
    u32 max_path_depth;
    u32 log_level;
    u32 merkle_history_max_size;
    u8 merkle_history_scope;
    u32 reserved[1];
};

/**
 * struct bpfima_pattern_entry - Pattern for matching (cgroups, paths, etc.)
 * @pattern: Pattern string to match
 * @enabled: Whether this pattern is active
 * @match_type: 0=exact, 1=prefix, 2=suffix, 3=contains
 */
struct bpfima_pattern_entry {
    char pattern[MAX_PATTERN_LEN];
    u8 enabled;
    u8 match_type;
    u16 reserved;
};

/**
 * struct bpfima_hook_config - Per-hook configuration
 * @flags: Bitmask of HOOK_FLAG_* flags
 * @filter_override: Hook-specific filter flag overrides
 * @action_override: Hook-specific action flag overrides
 * @reserved: Reserved for future use
 */
struct bpfima_hook_config {
    u32 flags;
    u32 filter_override;
    u32 action_override;
    u32 reserved[1];
};

/* Hook identifiers for per-hook configuration */
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

/* Default policy values - LESS STRICT: track everything by default */
#define DEFAULT_FILTER_FLAGS 0  /* No filtering - track all user processes and containers */

#define DEFAULT_ACTION_FLAGS (POLICY_ACTION_EXTEND_TPM | \
                              POLICY_ACTION_LOG_SECURITYFS | \
                              POLICY_ACTION_LOG_KERNEL | \
                              POLICY_ACTION_TRACK_CONTAINER | \
                              POLICY_ACTION_BUILD_DEPS)

#define DEFAULT_MIN_FILE_SIZE 0
#define DEFAULT_MAX_PATH_DEPTH 32
#define DEFAULT_LOG_LEVEL 2  /* Info level */

/* Default Patterns */
#define DEFAULT_CGROUP_PATTERN_1 "/"
#define DEFAULT_CGROUP_PATTERN_2 "init.scope"
#define DEFAULT_PATH_PATTERN_1 "/proc/"
#define DEFAULT_PATH_PATTERN_2 "/sys/"

/* Circular buffer defaults */
#define DEFAULT_MERKLE_HISTORY_MAX_SIZE 1000
#define MERKLE_HISTORY_SCOPE_GLOBAL 0
#define MERKLE_HISTORY_SCOPE_ROOT_ONLY 1
#define DEFAULT_MERKLE_HISTORY_SCOPE MERKLE_HISTORY_SCOPE_GLOBAL

/* Policy change tracking */
#define MAX_POLICY_CHANGES_STR 1024
#define MAX_POLICY_STRING_SIZE 512

/**
 * struct policy_change_entry - Single policy change record
 * @list: Linked list node
 * @change_hash: SHA-256 hash of the policy_string
 * @policy_string: Full policy configuration string (e.g., "enabled=1,filter_flags=0x0,action_flags=0x3F,min_file_size=0,log_level=2")
 * @timestamp: Timestamp when change occurred (jiffies)
 */
struct policy_change_entry {
    struct list_head list;
    u8 change_hash[MERKLE_HASH_SIZE];
    char policy_string[MAX_POLICY_STRING_SIZE];
};

/**
 * struct bpfima_policy_namespace - Per-namespace policy configuration
 * @namespace_id: Namespace/container identifier
 * @policy: Policy configuration for this namespace
 * @changes_str: Concatenated string of all policy changes (e.g., "filter_flags=0x7,action_flags=0x3F")
 * @changes_hash: SHA-256 hash of the changes_str
 * @list: Linked list node
 * @change_history: List of policy_change_entry records
 * @change_history_lock: Spinlock protecting the change history list
 */
struct bpfima_policy_namespace {
    char namespace_id[CONTAINER_ID_MAX_LEN];
    struct bpfima_policy_config policy;
    char changes_str[MAX_POLICY_CHANGES_STR];
    u8 changes_hash[MERKLE_HASH_SIZE];
    struct list_head list;
    struct list_head change_history;
    spinlock_t change_history_lock;
};


#endif /* BPFIMA_POLICY_H */
