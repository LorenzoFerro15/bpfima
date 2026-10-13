/**
 * kfuncs_policy.c - BPF kfunc implementations for policy updates
 *
 * This file implements BPF kernel functions (kfuncs) that allow eBPF programs
 * to dynamically update policy configurations for specific namespaces.
 */

#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_kfuncs.h"
#include "bpfima_kfunc_buffer.h"

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
__bpf_kfunc int bpfima_policy_update_filter_flags(const char *namespace_id, u32 namespace_id__sz, u32 new_flags)
{
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), namespace_id, namespace_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    return bpfima_policy_namespace_update_filter_flags(id, new_flags);
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
__bpf_kfunc int bpfima_policy_update_action_flags(const char *namespace_id, u32 namespace_id__sz, u32 new_flags)
{
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), namespace_id, namespace_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    return bpfima_policy_namespace_update_action_flags(id, new_flags);
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
__bpf_kfunc int bpfima_policy_update_min_file_size(const char *namespace_id, u32 namespace_id__sz, u32 new_size)
{
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), namespace_id, namespace_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    return bpfima_policy_namespace_update_min_file_size(id, new_size);
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
__bpf_kfunc int bpfima_policy_update_log_level(const char *namespace_id, u32 namespace_id__sz, u32 new_level)
{
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), namespace_id, namespace_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    return bpfima_policy_namespace_update_log_level(id, new_level);
}

/**
 * bpfima_policy_get_changes_hash - Get the hash of all policy changes for a namespace
 * @namespace_id: Namespace/container identifier
 * @hash_out: Buffer to store the hash output (must be at least MERKLE_HASH_SIZE bytes)
 * @hash_out__sz: Size of the hash buffer
 *
 * This kfunc retrieves the SHA-256 hash of all concatenated policy changes
 * for a specific namespace. The hash is computed over the changes_str field
 * which contains all policy modifications as a concatenated string.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_policy_get_changes_hash(const char *namespace_id, u32 namespace_id__sz,
                                                u8 *hash_out, u32 hash_out__sz)
{
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), namespace_id, namespace_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    if (!hash_out || hash_out__sz != MERKLE_HASH_SIZE)
        return -EINVAL;

    return bpfima_policy_namespace_get_changes_hash(id, hash_out, hash_out__sz);
}

/* Compatibility filters read the same authoritative map as production resolution. */
__bpf_kfunc bool bpfima_policy_should_ignore_cgroup(const char *cgroup_name__nullable,
                                                   u32 cgroup_name__sz, u32 filter_flags)
{
    char name[BPFIMA_NAMESPACE_SIZE];
    if (bpfima_copy_kfunc_string(name, sizeof(name), cgroup_name__nullable, cgroup_name__sz, false))
        return false;
    return bpfima_policy_match_root(name, filter_flags, false);
}

__bpf_kfunc bool bpfima_policy_should_ignore_path(const char *path__nullable, u32 path__sz, u32 filter_flags)
{
    char path[BPFIMA_PATH_SIZE];
    if (bpfima_copy_kfunc_string(path, sizeof(path), path__nullable, path__sz, false))
        return false;
    return bpfima_policy_match_root(path, filter_flags, true);
}

__bpf_kfunc int bpfima_policy_resolve(const void *data, u32 data__sz, void *output, u32 output__sz)
{
    struct bpfima_policy_context context;

    if (!data || data__sz != sizeof(context) || !output ||
        output__sz != sizeof(struct bpfima_policy_result))
        return -EINVAL;
    memcpy(&context, data, sizeof(context));
    return bpfima_policy_resolve_context(&context, output);
}
