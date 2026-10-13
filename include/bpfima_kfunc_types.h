#ifndef BPFIMA_KFUNC_TYPES_H
#define BPFIMA_KFUNC_TYPES_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define BPFIMA_EVENT_NAME_SIZE 256
#define BPFIMA_NAMESPACE_SIZE 128
#define BPFIMA_DEPENDENCIES_SIZE 256
#define BPFIMA_EVENT_DATA_SIZE 256
#define BPFIMA_PATH_SIZE 256
#define BPFIMA_PCR_BUFFER_SIZE 80

#define BPFIMA_MEASUREMENT_HAS_DEPENDENCIES (1U << 0)

/* Fixed-size, pointer-free request shared by the module and BPF programs. */
struct bpfima_measurement_request
{
    char event_name[BPFIMA_EVENT_NAME_SIZE];
    char namespace_id[BPFIMA_NAMESPACE_SIZE];
    char dependencies[BPFIMA_DEPENDENCIES_SIZE];
    char additional_data[BPFIMA_EVENT_DATA_SIZE];
    __u32 additional_data_len;
    __u32 flags;
};

/**
 * struct bpfima_policy_config - Shared policy output and map value
 * @enabled: Global enable/disable flag
 * @filter_flags: Bitmask of POLICY_FILTER_* flags
 * @action_flags: Bitmask of POLICY_ACTION_* flags
 * @min_file_size: Minimum file size to measure (bytes)
 * @max_path_depth: Maximum path depth to track
 * @log_level: Logging verbosity (0=none, 1=errors, 2=info, 3=debug)
 * @merkle_history_max_size: Maximum entries before trimming Merkle root history
 * @merkle_history_scope: Scope of circular buffer (0=global, 1=root-only)
 * @reserved: Reserved for future use
 */
struct bpfima_policy_config
{
    __u8 enabled;
    __u32 filter_flags;
    __u32 action_flags;
    __u32 min_file_size;
    __u32 max_path_depth;
    __u32 log_level;
    __u32 merkle_history_max_size;
    __u8 merkle_history_scope;
    __u32 reserved[1];
};

/* Maximum number of ignore patterns */
#define MAX_IGNORE_PATTERNS 8
#define MAX_PATTERN_LEN 64

/* Maximum number of path filters */
#define MAX_PATH_FILTERS 8

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
 * struct bpfima_pattern_entry - Pattern for matching (cgroups, paths, etc.)
 * @pattern: Pattern string to match
 * @enabled: Whether this pattern is active
 * @match_type: 0=exact, 1=prefix, 2=suffix, 3=contains
 */
struct bpfima_pattern_entry {
    char pattern[MAX_PATTERN_LEN];
    __u8 enabled;
    __u8 match_type;
    __u16 reserved;
};

/**
 * struct bpfima_hook_config - Per-hook configuration
 * @flags: Bitmask of HOOK_FLAG_* flags
 * @filter_override: Hook-specific filter flag overrides
 * @action_override: Hook-specific action flag overrides
 * @reserved: Reserved for future use
 */
struct bpfima_hook_config {
    __u32 flags;
    __u32 filter_override;
    __u32 action_override;
    __u32 reserved[1];
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
    HOOK_LSM_INODE_SETATTR,
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


/* Policy map ABI: control at key 0, immutable active/staging states at 1/2. */
#define BPFIMA_POLICY_VERSION 2
#define BPFIMA_POLICY_NAMESPACES 32
#define BPFIMA_POLICY_MAP_ENTRIES 3
#define BPFIMA_POLICY_MAP_FLAGS (1U << 7) /* RDONLY_PROG; the module also requires BPF_MAP_FREEZE. */
#define BPFIMA_POLICY_FILE (1U << 0)
#define BPFIMA_POLICY_READONLY (1U << 1)
#define BPFIMA_POLICY_EXECUTABLE (1U << 2)

struct bpfima_policy_snapshot
{
    struct bpfima_policy_config config;
    struct bpfima_pattern_entry cgroups[MAX_IGNORE_PATTERNS];
    struct bpfima_pattern_entry paths[MAX_PATH_FILTERS];
    struct bpfima_hook_config hooks[HOOK_MAX];
};

struct bpfima_policy_record
{
    char namespace_id[BPFIMA_NAMESPACE_SIZE];
    struct bpfima_policy_snapshot snapshot;
};

struct bpfima_policy_state
{
    __u64 generation;
    __u32 namespace_count;
    __u32 reserved;
    struct bpfima_policy_record records[BPFIMA_POLICY_NAMESPACES + 1];
};

/* Empty namespace_id selects the root policy. Zero expected_generation is unconditional. */
struct bpfima_policy_request
{
    __u32 version;
    __u32 reserved;
    __u64 expected_generation;
    struct bpfima_policy_record record;
};

struct bpfima_policy_context
{
    char namespace_id[BPFIMA_NAMESPACE_SIZE];
    char cgroup[BPFIMA_NAMESPACE_SIZE];
    char path[BPFIMA_PATH_SIZE];
    __u64 file_size;
    __u32 hook;
    __u32 flags;
};

struct bpfima_policy_result
{
    __u64 generation;
    struct bpfima_policy_config config;
    struct bpfima_hook_config hook;
    __u32 skip;
};

_Static_assert(sizeof(struct bpfima_policy_snapshot) == 1252, "policy snapshot ABI changed");
_Static_assert(sizeof(struct bpfima_policy_state) == 45560, "policy map ABI changed");
_Static_assert(sizeof(struct bpfima_policy_request) == 1400, "policy request ABI changed");
_Static_assert(sizeof(struct bpfima_policy_result) == 64, "policy result ABI changed");

_Static_assert(sizeof(struct bpfima_measurement_request) == 904,
               "bpfima measurement request layout changed");
_Static_assert(sizeof(struct bpfima_policy_config) == 36,
               "bpfima policy configuration layout changed");

#endif /* BPFIMA_KFUNC_TYPES_H */
