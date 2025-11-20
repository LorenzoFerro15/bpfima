#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_measurements.h"

static LIST_HEAD(policy_namespace_list);
static DEFINE_MUTEX(bpfima_policy_namespace_mutex);

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

    pr_info("bpfima: Cleaning up per-namespace policy subsystem\n");

    mutex_lock(&bpfima_policy_namespace_mutex);
    list_for_each_entry_safe(policy_ns, tmp, &policy_namespace_list, list) {
        spin_lock(&policy_ns->change_history_lock);
        list_for_each_entry_safe(change, tmp_change, &policy_ns->change_history, list) {
            list_del(&change->list);
            kfree(change);
        }
        spin_unlock(&policy_ns->change_history_lock);
        
        list_del(&policy_ns->list);
        kfree(policy_ns);
    }
    mutex_unlock(&bpfima_policy_namespace_mutex);
}

/**
 * find_policy_namespace - Find policy configuration for a namespace
 * @namespace_id: Namespace identifier to search for
 *
 * Must be called with bpfima_policy_namespace_mutex held.
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
 * Must be called with bpfima_policy_namespace_mutex held.
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

    ret = snprintf(temp, sizeof(temp), "%s=0x%x,", field_name, new_value);
    if (ret < 0 || ret >= sizeof(temp))
        return -EINVAL;

    len = strlen(policy_ns->changes_str);
    remaining = MAX_POLICY_CHANGES_STR - len - 1;

    if (remaining < ret) {
        pr_warn("bpfima: Policy changes string full for namespace %s\n",
                policy_ns->namespace_id);
        return -ENOSPC;
    }

    strncat(policy_ns->changes_str, temp, remaining);

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
 * Must be called with bpfima_policy_namespace_mutex held.
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

    change_entry = kzalloc(sizeof(*change_entry), GFP_ATOMIC);
    if (!change_entry)
        return -ENOMEM;

    strscpy(change_entry->policy_string, policy_string, MAX_POLICY_STRING_SIZE);

    ret = calculate_sha256_hash(policy_string, strlen(policy_string),
                                change_entry->change_hash);
    if (ret < 0) {
        pr_err("bpfima: Failed to calculate policy change hash: %d\n", ret);
        kfree(change_entry);
        return ret;
    }

    spin_lock_irqsave(&policy_ns->change_history_lock, flags);
    list_add_tail(&change_entry->list, &policy_ns->change_history);
    spin_unlock_irqrestore(&policy_ns->change_history_lock, flags);

    pr_info("bpfima: Recorded policy change for namespace %s\n", namespace_id);

    spin_lock_irqsave(&container_list_lock, container_flags);
    container = find_container_by_id(namespace_id);
    
    if (container) {
        char policy_hash_hex[MERKLE_HASH_SIZE * 2 + 1];
        struct measurement_entry *meas_entry;
        int i;
        
        spin_unlock_irqrestore(&container_list_lock, container_flags);
        
        for (i = 0; i < MERKLE_HASH_SIZE; i++) {
            snprintf(&policy_hash_hex[i * 2], 3, "%02x", change_entry->change_hash[i]);
        }
        policy_hash_hex[MERKLE_HASH_SIZE * 2] = '\0';
        
        u8 measurement_digest[MERKLE_HASH_SIZE];
        char measurement_data[512];
        
        snprintf(measurement_data, sizeof(measurement_data), "policy_update %s", policy_hash_hex);
        
        ret = calculate_sha256_hash(measurement_data, strlen(measurement_data), measurement_digest);
        if (ret < 0) {
            pr_err("bpfima: Failed to calculate measurement hash for policy update: %d\n", ret);
            return ret;
        }
        
        meas_entry = create_measurement_entry("policy_update", policy_hash_hex, "", measurement_digest, GFP_KERNEL);
        if (!meas_entry) {
            pr_err("bpfima: Failed to create measurement entry for policy update\n");
            return -ENOMEM;
        }
        
        spin_lock_irqsave(&container->measurement_lock, flags);
        list_add_tail(&meas_entry->list, &container->measurement_list);
        spin_unlock_irqrestore(&container->measurement_lock, flags);
        
        atomic_inc(&container->measurement_count);
        
        ret = extend_container_leaf_hash(container, measurement_digest);
        if (ret < 0) {
            pr_err("bpfima: Failed to extend container leaf hash: %d\n", ret);
            return ret;
        }

        pr_info("bpfima: Extended leaf hash for namespace %s\n", namespace_id);

        ret = add_merkle_root_history_entry(container->leaf_hash, container->id);
        if (ret < 0) {
            pr_warn("bpfima: Failed to add merkle root history entry: %d\n", ret);
        }
        
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
 * Uses mutex locking to safely create namespaces without race conditions.
 * Since we use a mutex instead of spinlock, we can safely allocate memory
 * while holding the lock, eliminating the check-then-act race condition.
 *
 * Returns: Pointer to policy_namespace, or ERR_PTR on failure
 */
struct bpfima_policy_namespace *bpfima_policy_namespace_get_or_create(const char *namespace_id)
{
    struct bpfima_policy_namespace *policy_ns;
    struct bpfima_policy_config *global_policy;
    int ret;

    if (!namespace_id || strlen(namespace_id) == 0)
        return ERR_PTR(-EINVAL);

    mutex_lock(&bpfima_policy_namespace_mutex);

    policy_ns = find_policy_namespace(namespace_id);
    if (policy_ns) {
        mutex_unlock(&bpfima_policy_namespace_mutex);
        return policy_ns;
    }

    policy_ns = kzalloc(sizeof(*policy_ns), GFP_KERNEL);
    if (!policy_ns) {
        mutex_unlock(&bpfima_policy_namespace_mutex);
        return ERR_PTR(-ENOMEM);
    }

    strscpy(policy_ns->namespace_id, namespace_id, CONTAINER_ID_MAX_LEN);

    global_policy = bpfima_policy_get();
    memcpy(&policy_ns->policy, global_policy, sizeof(policy_ns->policy));

    INIT_LIST_HEAD(&policy_ns->change_history);
    spin_lock_init(&policy_ns->change_history_lock);

    memset(policy_ns->changes_str, 0, MAX_POLICY_CHANGES_STR);
    snprintf(policy_ns->changes_str, MAX_POLICY_CHANGES_STR, "initialized,");

    ret = calculate_sha256_hash(policy_ns->changes_str,
                                strlen(policy_ns->changes_str),
                                policy_ns->changes_hash);
    if (ret < 0) {
        pr_err("bpfima: Failed to calculate initial policy hash: %d\n", ret);
        mutex_unlock(&bpfima_policy_namespace_mutex);
        kfree(policy_ns);
        return ERR_PTR(ret);
    }

    list_add(&policy_ns->list, &policy_namespace_list);
    mutex_unlock(&bpfima_policy_namespace_mutex);

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
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    mutex_lock(&bpfima_policy_namespace_mutex);
    policy_ns->policy.filter_flags = new_flags;
    ret = update_changes_string(policy_ns, "filter_flags", new_flags);
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
    mutex_unlock(&bpfima_policy_namespace_mutex);

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
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    mutex_lock(&bpfima_policy_namespace_mutex);
    policy_ns->policy.action_flags = new_flags;
    ret = update_changes_string(policy_ns, "action_flags", new_flags);
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
    mutex_unlock(&bpfima_policy_namespace_mutex);

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
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    mutex_lock(&bpfima_policy_namespace_mutex);
    policy_ns->policy.min_file_size = new_size;
    ret = update_changes_string(policy_ns, "min_file_size", new_size);
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
    mutex_unlock(&bpfima_policy_namespace_mutex);

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
    int ret;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    mutex_lock(&bpfima_policy_namespace_mutex);
    policy_ns->policy.log_level = new_level;
    ret = update_changes_string(policy_ns, "log_level", new_level);
    if (ret == 0) {
        ret = record_policy_change_and_extend(policy_ns, namespace_id);
    }
    mutex_unlock(&bpfima_policy_namespace_mutex);

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

    if (!hash_out || hash_size < MERKLE_HASH_SIZE)
        return -EINVAL;

    mutex_lock(&bpfima_policy_namespace_mutex);
    policy_ns = find_policy_namespace(namespace_id);
    if (!policy_ns) {
        mutex_unlock(&bpfima_policy_namespace_mutex);
        return -ENOENT;
    }

    memcpy(hash_out, policy_ns->changes_hash, MERKLE_HASH_SIZE);
    mutex_unlock(&bpfima_policy_namespace_mutex);

    return 0;
}
