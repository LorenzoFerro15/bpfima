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

/**
 * bpfima_policy_should_ignore_cgroup - Check if a cgroup should be ignored based on policy
 */
__bpf_kfunc bool bpfima_policy_should_ignore_cgroup(const char *cgroup_name__nullable, u32 filter_flags)
{
    if (!cgroup_name__nullable || cgroup_name__nullable[0] == '\0')
        return false;

    if (cgroup_name__nullable[0] == '/' && cgroup_name__nullable[1] == '\0')
        return true;
    if (strncmp(cgroup_name__nullable, "init.scope", 10) == 0)
        return true;

    if (!(filter_flags & POLICY_FILTER_SYSTEM_CGROUPS))
        return false;

    struct bpfima_pattern_entry *p = bpfima_policy_get_cgroup_patterns();
    if (!p)
        return false;

    for (int i = 0; i < MAX_IGNORE_PATTERNS; i++) {
        if (!p[i].enabled)
            continue;
        if (p[i].match_type == 0 && strcmp(cgroup_name__nullable, p[i].pattern) == 0)
            return true;
        if (p[i].match_type == 1 && strncmp(cgroup_name__nullable, p[i].pattern, strlen(p[i].pattern)) == 0)
            return true;
        if (p[i].match_type == 2) {
            size_t len_name = strlen(cgroup_name__nullable);
            size_t len_p = strlen(p[i].pattern);
            if (len_name >= len_p && strcmp(cgroup_name__nullable + len_name - len_p, p[i].pattern) == 0)
                return true;
        }
        if (p[i].match_type == 3 && strstr(cgroup_name__nullable, p[i].pattern) != NULL)
            return true;
    }
    return false;
}

/**
 * bpfima_policy_should_ignore_path - Check if a file path should be ignored based on policy
 */
__bpf_kfunc bool bpfima_policy_should_ignore_path(const char *path__nullable, u32 filter_flags)
{
    if (!path__nullable || path__nullable[0] == '\0')
        return false;

    if ((filter_flags & POLICY_FILTER_PROC_SYS)) {
        if (strncmp(path__nullable, "/proc/", 6) == 0 || strncmp(path__nullable, "/sys/", 5) == 0)
            return true;
    }
    if ((filter_flags & POLICY_FILTER_DEV)) {
        if (strncmp(path__nullable, "/dev/", 5) == 0)
            return true;
    }
    if ((filter_flags & POLICY_FILTER_TMP_FILES)) {
        if (strncmp(path__nullable, "/tmp/", 5) == 0)
            return true;
    }

    struct bpfima_pattern_entry *p = bpfima_policy_get_path_patterns();
    if (!p)
        return false;

    for (int i = 0; i < MAX_PATH_FILTERS; i++) {
        if (!p[i].enabled)
            continue;
        if (p[i].match_type == 0 && strcmp(path__nullable, p[i].pattern) == 0)
            return true;
        if (p[i].match_type == 1 && strncmp(path__nullable, p[i].pattern, strlen(p[i].pattern)) == 0)
            return true;
        if (p[i].match_type == 2) {
            size_t len_name = strlen(path__nullable);
            size_t len_p = strlen(p[i].pattern);
            if (len_name >= len_p && strcmp(path__nullable + len_name - len_p, p[i].pattern) == 0)
                return true;
        }
        if (p[i].match_type == 3 && strstr(path__nullable, p[i].pattern) != NULL)
            return true;
    }
    return false;
}
