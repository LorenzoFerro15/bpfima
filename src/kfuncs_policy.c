/**
 * kfuncs_policy.c - BPF kfunc implementations for policy updates
 *
 * This file implements BPF kernel functions (kfuncs) that allow eBPF programs
 * to dynamically update policy configurations for specific namespaces.
 */

#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_kfuncs.h"

/**
 * bpfima_policy_update_filter_flags - Update filter flags for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_flags: New filter flags value
 *
 * This kfunc allows eBPF programs to dynamically update the filter flags
 * for a specific namespace. The change is tracked as a string and hashed.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_policy_update_filter_flags(const char *namespace_id, u32 new_flags)
{
    if (!namespace_id)
        return -EINVAL;

    return bpfima_policy_namespace_update_filter_flags(namespace_id, new_flags);
}

/**
 * bpfima_policy_update_action_flags - Update action flags for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_flags: New action flags value
 *
 * This kfunc allows eBPF programs to dynamically update the action flags
 * for a specific namespace. The change is tracked as a string and hashed.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_policy_update_action_flags(const char *namespace_id, u32 new_flags)
{
    if (!namespace_id)
        return -EINVAL;

    return bpfima_policy_namespace_update_action_flags(namespace_id, new_flags);
}

/**
 * bpfima_policy_update_min_file_size - Update minimum file size for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_size: New minimum file size value
 *
 * This kfunc allows eBPF programs to dynamically update the minimum file size
 * threshold for a specific namespace. The change is tracked as a string and hashed.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_policy_update_min_file_size(const char *namespace_id, u32 new_size)
{
    if (!namespace_id)
        return -EINVAL;

    return bpfima_policy_namespace_update_min_file_size(namespace_id, new_size);
}

/**
 * bpfima_policy_update_log_level - Update log level for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_level: New log level value
 *
 * This kfunc allows eBPF programs to dynamically update the log level
 * for a specific namespace. The change is tracked as a string and hashed.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_policy_update_log_level(const char *namespace_id, u32 new_level)
{
    if (!namespace_id)
        return -EINVAL;

    return bpfima_policy_namespace_update_log_level(namespace_id, new_level);
}

/**
 * bpfima_policy_get_changes_hash - Get the hash of all policy changes for a namespace
 * @namespace_id: Namespace/container identifier
 * @hash_out: Buffer to store the hash output (must be at least MERKLE_HASH_SIZE bytes)
 * @hash_size: Size of the hash buffer
 *
 * This kfunc retrieves the SHA-256 hash of all concatenated policy changes
 * for a specific namespace. The hash is computed over the changes_str field
 * which contains all policy modifications as a concatenated string.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_policy_get_changes_hash(const char *namespace_id, u8 *hash_out, u32 hash_size)
{
    if (!namespace_id || !hash_out)
        return -EINVAL;

    return bpfima_policy_namespace_get_changes_hash(namespace_id, hash_out, hash_size);
}
