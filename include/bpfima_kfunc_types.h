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

_Static_assert(sizeof(struct bpfima_measurement_request) == 904,
               "bpfima measurement request layout changed");
_Static_assert(sizeof(struct bpfima_policy_config) == 36,
               "bpfima policy configuration layout changed");

#endif /* BPFIMA_KFUNC_TYPES_H */
