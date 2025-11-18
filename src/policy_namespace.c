/**
 * policy_namespace.c - Per-namespace policy configuration and tracking
 *
 * This file implements per-namespace/container policy management,
 * allowing dynamic policy updates that are tracked with hash values.
 * Instead of tracking dependencies, we track all policy changes as
 * a concatenated string and compute its hash.
 */

#include "bpfima_common.h"
#include "bpfima_policy.h"

/* Global list of per-namespace policies */
static LIST_HEAD(policy_namespace_list);
static DEFINE_SPINLOCK(policy_namespace_lock);

/**
 * bpfima_policy_namespace_init - Initialize namespace policy subsystem
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_namespace_init(void)
{
    pr_info("bpfima: Initializing per-namespace policy subsystem\n");
    return 0;
}

/**
 * bpfima_policy_namespace_cleanup - Clean up namespace policy subsystem
 */
void bpfima_policy_namespace_cleanup(void)
{
    struct bpfima_policy_namespace *policy_ns, *tmp;
    unsigned long flags;

    pr_info("bpfima: Cleaning up per-namespace policy subsystem\n");

    spin_lock_irqsave(&policy_namespace_lock, flags);
    list_for_each_entry_safe(policy_ns, tmp, &policy_namespace_list, list) {
        list_del(&policy_ns->list);
        kfree(policy_ns);
    }
    spin_unlock_irqrestore(&policy_namespace_lock, flags);
}

/**
 * find_policy_namespace - Find policy configuration for a namespace
 * @namespace_id: Namespace identifier to search for
 *
 * Must be called with policy_namespace_lock held.
 *
 * Returns: Pointer to policy_namespace if found, NULL otherwise
 */
static struct bpfima_policy_namespace *find_policy_namespace(const char *namespace_id)
{
    struct bpfima_policy_namespace *policy_ns;

    if (!namespace_id)
        return NULL;

    list_for_each_entry(policy_ns, &policy_namespace_list, list) {
        if (strcmp(policy_ns->namespace_id, namespace_id) == 0)
            return policy_ns;
    }

    return NULL;
}

/**
 * update_changes_string - Append a policy change to the changes string
 * @policy_ns: Policy namespace to update
 * @field_name: Name of the field that changed
 * @new_value: New value of the field
 *
 * Appends "field_name=new_value," to the changes_str and recalculates hash.
 * Must be called with policy_namespace_lock held.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int update_changes_string(struct bpfima_policy_namespace *policy_ns,
                                 const char *field_name, u32 new_value)
{
    int len, remaining;
    char temp[64];
    int ret;

    if (!policy_ns || !field_name)
        return -EINVAL;

    /* Format the new change entry */
    ret = snprintf(temp, sizeof(temp), "%s=0x%x,", field_name, new_value);
    if (ret < 0 || ret >= sizeof(temp))
        return -EINVAL;

    /* Check if there's space in the changes string */
    len = strlen(policy_ns->changes_str);
    remaining = MAX_POLICY_CHANGES_STR - len - 1;

    if (remaining < ret) {
        pr_warn("bpfima: Policy changes string full for namespace %s\n",
                policy_ns->namespace_id);
        return -ENOSPC;
    }

    /* Append the change */
    strncat(policy_ns->changes_str, temp, remaining);

    /* Recalculate hash of the entire changes string */
    ret = calculate_sha256_hash(policy_ns->changes_str,
                                strlen(policy_ns->changes_str),
                                policy_ns->changes_hash);
    if (ret < 0) {
        pr_err("bpfima: Failed to calculate policy changes hash: %d\n", ret);
        return ret;
    }

    pr_info("bpfima: Updated policy for namespace %s: %s\n",
            policy_ns->namespace_id, temp);

    return 0;
}

/**
 * bpfima_policy_namespace_get_or_create - Get or create policy namespace
 * @namespace_id: Namespace identifier
 *
 * Returns: Pointer to policy_namespace, or ERR_PTR on failure
 */
struct bpfima_policy_namespace *bpfima_policy_namespace_get_or_create(const char *namespace_id)
{
    struct bpfima_policy_namespace *policy_ns;
    struct bpfima_policy_config *global_policy;
    unsigned long flags;
    int ret;

    if (!namespace_id || strlen(namespace_id) == 0)
        return ERR_PTR(-EINVAL);

    spin_lock_irqsave(&policy_namespace_lock, flags);

    /* Check if already exists */
    policy_ns = find_policy_namespace(namespace_id);
    if (policy_ns) {
        spin_unlock_irqrestore(&policy_namespace_lock, flags);
        return policy_ns;
    }

    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    /* Create new policy namespace */
    policy_ns = kzalloc(sizeof(*policy_ns), GFP_KERNEL);
    if (!policy_ns)
        return ERR_PTR(-ENOMEM);

    /* Initialize with namespace ID */
    strscpy(policy_ns->namespace_id, namespace_id, CONTAINER_ID_MAX_LEN);

    /* Copy global policy as starting point */
    global_policy = bpfima_policy_get();
    memcpy(&policy_ns->policy, global_policy, sizeof(policy_ns->policy));

    /* Initialize changes string */
    memset(policy_ns->changes_str, 0, MAX_POLICY_CHANGES_STR);
    snprintf(policy_ns->changes_str, MAX_POLICY_CHANGES_STR, "initialized,");

    /* Calculate initial hash */
    ret = calculate_sha256_hash(policy_ns->changes_str,
                                strlen(policy_ns->changes_str),
                                policy_ns->changes_hash);
    if (ret < 0) {
        pr_err("bpfima: Failed to calculate initial policy hash: %d\n", ret);
        kfree(policy_ns);
        return ERR_PTR(ret);
    }

    /* Add to list */
    spin_lock_irqsave(&policy_namespace_lock, flags);
    /* Double-check it wasn't created while we were allocating */
    if (find_policy_namespace(namespace_id)) {
        spin_unlock_irqrestore(&policy_namespace_lock, flags);
        kfree(policy_ns);
        return find_policy_namespace(namespace_id);
    }
    list_add(&policy_ns->list, &policy_namespace_list);
    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    pr_info("bpfima: Created policy namespace for %s\n", namespace_id);

    return policy_ns;
}

/**
 * bpfima_policy_namespace_update_filter_flags - Update filter flags for namespace
 * @namespace_id: Namespace identifier
 * @new_flags: New filter flags value
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_namespace_update_filter_flags(const char *namespace_id, u32 new_flags)
{
    struct bpfima_policy_namespace *policy_ns;
    unsigned long flags;
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    spin_lock_irqsave(&policy_namespace_lock, flags);
    policy_ns->policy.filter_flags = new_flags;
    ret = update_changes_string(policy_ns, "filter_flags", new_flags);
    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    return ret;
}

/**
 * bpfima_policy_namespace_update_action_flags - Update action flags for namespace
 * @namespace_id: Namespace identifier
 * @new_flags: New action flags value
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_namespace_update_action_flags(const char *namespace_id, u32 new_flags)
{
    struct bpfima_policy_namespace *policy_ns;
    unsigned long flags;
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    spin_lock_irqsave(&policy_namespace_lock, flags);
    policy_ns->policy.action_flags = new_flags;
    ret = update_changes_string(policy_ns, "action_flags", new_flags);
    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    return ret;
}

/**
 * bpfima_policy_namespace_update_min_file_size - Update min file size for namespace
 * @namespace_id: Namespace identifier
 * @new_size: New minimum file size value
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_namespace_update_min_file_size(const char *namespace_id, u32 new_size)
{
    struct bpfima_policy_namespace *policy_ns;
    unsigned long flags;
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    spin_lock_irqsave(&policy_namespace_lock, flags);
    policy_ns->policy.min_file_size = new_size;
    ret = update_changes_string(policy_ns, "min_file_size", new_size);
    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    return ret;
}

/**
 * bpfima_policy_namespace_update_log_level - Update log level for namespace
 * @namespace_id: Namespace identifier
 * @new_level: New log level value
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_namespace_update_log_level(const char *namespace_id, u32 new_level)
{
    struct bpfima_policy_namespace *policy_ns;
    unsigned long flags;
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    spin_lock_irqsave(&policy_namespace_lock, flags);
    policy_ns->policy.log_level = new_level;
    ret = update_changes_string(policy_ns, "log_level", new_level);
    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    return ret;
}

/**
 * bpfima_policy_namespace_get_changes_hash - Get hash of policy changes for namespace
 * @namespace_id: Namespace identifier
 * @hash_out: Buffer to store hash output
 * @hash_size: Size of the hash buffer (should be MERKLE_HASH_SIZE)
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_namespace_get_changes_hash(const char *namespace_id, u8 *hash_out, u32 hash_size)
{
    struct bpfima_policy_namespace *policy_ns;
    unsigned long flags;

    if (!hash_out || hash_size < MERKLE_HASH_SIZE)
        return -EINVAL;

    spin_lock_irqsave(&policy_namespace_lock, flags);
    policy_ns = find_policy_namespace(namespace_id);
    if (!policy_ns) {
        spin_unlock_irqrestore(&policy_namespace_lock, flags);
        return -ENOENT;
    }

    memcpy(hash_out, policy_ns->changes_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&policy_namespace_lock, flags);

    return 0;
}
