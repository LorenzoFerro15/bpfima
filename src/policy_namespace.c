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
#include "bpfima_container.h"
#include "bpfima_merkle.h"

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
    struct policy_change_entry *change, *tmp_change;
    unsigned long flags;

    pr_info("bpfima: Cleaning up per-namespace policy subsystem\n");

    spin_lock_irqsave(&policy_namespace_lock, flags);
    list_for_each_entry_safe(policy_ns, tmp, &policy_namespace_list, list) {
        /* Clean up change history */
        spin_lock(&policy_ns->change_history_lock);
        list_for_each_entry_safe(change, tmp_change, &policy_ns->change_history, list) {
            list_del(&change->list);
            kfree(change);
        }
        spin_unlock(&policy_ns->change_history_lock);
        
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
 * record_policy_change_and_extend - Record policy change and extend Merkle tree
 * @policy_ns: Policy namespace
 * @namespace_id: Namespace identifier
 *
 * Creates a policy change entry with full policy string, hashes it,
 * extends the container leaf hash, and extends the Merkle root.
 * Must be called with policy_namespace_lock held.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int record_policy_change_and_extend(struct bpfima_policy_namespace *policy_ns,
                                           const char *namespace_id)
{
    struct policy_change_entry *change_entry;
    struct container_node *container;
    unsigned long flags, container_flags;
    int ret;
    char policy_string[MAX_POLICY_STRING_SIZE];

    if (!policy_ns || !namespace_id)
        return -EINVAL;

    /* Format the full policy string */
    ret = snprintf(policy_string, sizeof(policy_string),
                   "enabled=%u,filter_flags=0x%x,action_flags=0x%x,min_file_size=%u,max_path_depth=%u,log_level=%u",
                   policy_ns->policy.enabled,
                   policy_ns->policy.filter_flags,
                   policy_ns->policy.action_flags,
                   policy_ns->policy.min_file_size,
                   policy_ns->policy.max_path_depth,
                   policy_ns->policy.log_level);
    
    if (ret < 0 || ret >= sizeof(policy_string)) {
        pr_err("bpfima: Failed to format policy string\n");
        return -EINVAL;
    }

    /* Create a new policy change entry */
    change_entry = kzalloc(sizeof(*change_entry), GFP_ATOMIC);
    if (!change_entry)
        return -ENOMEM;

    /* Copy the policy string */
    strscpy(change_entry->policy_string, policy_string, MAX_POLICY_STRING_SIZE);

    /* Calculate hash of the policy string */
    ret = calculate_sha256_hash(policy_string, strlen(policy_string),
                                change_entry->change_hash);
    if (ret < 0) {
        pr_err("bpfima: Failed to calculate policy change hash: %d\n", ret);
        kfree(change_entry);
        return ret;
    }

    /* Add to change history */
    spin_lock_irqsave(&policy_ns->change_history_lock, flags);
    list_add_tail(&change_entry->list, &policy_ns->change_history);
    spin_unlock_irqrestore(&policy_ns->change_history_lock, flags);

    pr_info("bpfima: Recorded policy change for namespace %s\n", namespace_id);

    /* Find the container to extend its leaf hash */
    spin_lock_irqsave(&container_list_lock, container_flags);
    container = find_container_by_id(namespace_id);
    
    if (container) {
        spin_unlock_irqrestore(&container_list_lock, container_flags);
        
        /* Extend container leaf hash with the policy change hash */
        ret = extend_container_leaf_hash(container, change_entry->change_hash);
        if (ret < 0) {
            pr_err("bpfima: Failed to extend container leaf hash: %d\n", ret);
            return ret;
        }

        pr_info("bpfima: Extended leaf hash for namespace %s\n", namespace_id);

        /* Extend Merkle root with the updated container leaf hash */
        ret = extend_merkle_root(container->leaf_hash);
        if (ret < 0) {
            pr_err("bpfima: Failed to extend Merkle root: %d\n", ret);
            return ret;
        }

        pr_info("bpfima: Extended Merkle root for policy change in namespace %s\n", namespace_id);
    } else {
        spin_unlock_irqrestore(&container_list_lock, container_flags);
        pr_warn("bpfima: Container not found for namespace %s, policy change recorded but not extended\n",
                namespace_id);
    }

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

    /* Initialize change history */
    INIT_LIST_HEAD(&policy_ns->change_history);
    spin_lock_init(&policy_ns->change_history_lock);

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
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
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
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
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
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
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
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
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
