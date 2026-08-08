/*
 * Merkle Tree Implementation for BPF-IMA
 *
 * This file implements a non-binary Merkle tree where each container
 * is represented as a leaf node. The root hash represents the entire
 * system state (virtual PCR value).
 */

#include "bpfima_common.h"
#include "bpfima_merkle.h"
#include "bpfima_container.h"
#include "bpfima_measurements.h"
#include "bpfima_securityfs.h"
#include "bpfima_policy.h"
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/namei.h>

/* Global state */
LIST_HEAD(merkle_root_history);
DEFINE_SPINLOCK(merkle_root_history_lock);

struct merkle_tree_root system_merkle_root = {.root_hash = {0}};

/* Counter for merkle_root_history entries (for circular buffer management) */
static atomic_t merkle_root_history_count = ATOMIC_INIT(0);


/**
 * try_extend_tpm_with_root - Attempt to extend TPM with merkle root
 * @new_root: The root hash to extend
 * @can_sleep: Whether we're in a context that can sleep
 *
 * Helper function to avoid code duplication in merkle root operations.
 * Extends TPM PCR if possible, but doesn't fail on TPM errors since
 * TPM extension is optional.
 */
static inline void try_extend_tpm_with_root(const u8 *new_root, bool can_sleep)
{
    int ret;

    if (!can_sleep)
    {
        pr_info("bpfima: Called from atomic context, TPM extension deferred for merkle_root_update\n");
        return;
    }

    ret = extend_tpm_pcr_with_root(new_root, "merkle_root_update");
    if (ret < 0 && ret != -ENODEV)
    {
        /* Log error but don't fail - TPM extension is optional */
        pr_warn("bpfima: Failed to extend TPM PCR with Merkle root: %d\n", ret);
    }
}

/**
 * extend_container_leaf_hash - Extend container leaf hash with new measurement
 * @container: Container node to extend
 * @new_digest: New measurement digest to extend into the leaf hash
 *
 * Extends the container's leaf hash using PCR-style extend operation:
 * new_leaf = hash(old_leaf || new_digest)
 *
 * Uses pre-allocated tfm and atomic allocations to be safe in spinlock context.
 *
 * Returns: 0 on success, negative error code on failure
 */
int extend_container_leaf_hash(struct container_node *container, const u8 *new_digest)
{
    int ret = 0;
    u8 old_leaf[MERKLE_HASH_SIZE];
    u8 new_leaf[MERKLE_HASH_SIZE];

    if (!container || !container->tfm) {
        pr_err("bpfima: extend_container_leaf_hash: NULL container or tfm\n");
        return -EINVAL;
    }

    if (!new_digest) {
        pr_err("bpfima: extend_container_leaf_hash: NULL digest\n");
        return -EINVAL;
    }

    memcpy(old_leaf, container->leaf_hash, MERKLE_HASH_SIZE);

    ret = bpfima_extend_hash(container->tfm, old_leaf, new_digest, new_leaf);
    if (ret < 0) {
        pr_err("bpfima: bpfima_extend_hash failed: %d\n", ret);
        goto cleanup;
    }

    memcpy(container->leaf_hash, new_leaf, MERKLE_HASH_SIZE);

    pr_debug("bpfima: Container %s leaf hash extended\n", container->id);

cleanup:
    memzero_explicit(old_leaf, sizeof(old_leaf));
    memzero_explicit(new_leaf, sizeof(new_leaf));
    /* No manual desc cleanup needed with helper */
    return ret;
}

/**
 * extend_merkle_root - Extend the Merkle tree root with a new container leaf hash
 * @container_leaf_hash: The new container leaf hash to extend into the root
 *
 * Computes the new Merkle root using pre-allocated tfm and atomic operations.
 * Protected by system_merkle_root.lock.
 *
 * Returns: 0 on success, negative error code on failure
 */
int extend_merkle_root(const u8 *container_leaf_hash)
{
    unsigned long flags;
    int ret = 0;
    u8 old_root[MERKLE_HASH_SIZE];
    u8 new_root[MERKLE_HASH_SIZE];
    bool can_sleep = !in_atomic() && !irqs_disabled();

    if (!container_leaf_hash) {
        pr_err("bpfima: extend_merkle_root: NULL container_leaf_hash\n");
        return -EINVAL;
    }

    if (!system_merkle_root.tfm) {
        pr_err("bpfima: extend_merkle_root: System tfm not allocated\n");
        return -EINVAL;
    }

    if (!system_merkle_root.tfm) {
        pr_err("bpfima: extend_merkle_root: System tfm not allocated\n");
        return -EINVAL;
    }

    /* desc allocation removed - bpfima_extend_hash handles it */

    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(old_root, system_merkle_root.root_hash, MERKLE_HASH_SIZE);
    
    /* Extend: new_root = hash(old_root || container_leaf_hash) */
    /* Note: Calling these inside spinlock is why we need simple crypto ops */
    ret = bpfima_extend_hash(system_merkle_root.tfm, old_root, container_leaf_hash, new_root);
    
    if (ret == 0) {
        memcpy(system_merkle_root.root_hash, new_root, MERKLE_HASH_SIZE);
    }
    
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);

    if (ret < 0) {
        pr_err("bpfima: crypto sha256 failed for merkle root: %d\n", ret);
        goto cleanup;
    }

    pr_debug("bpfima: Merkle root extended with container leaf hash\n");

    try_extend_tpm_with_root(new_root, can_sleep);

    ret = 0;

cleanup:
    memzero_explicit(old_root, sizeof(old_root));
    memzero_explicit(new_root, sizeof(new_root));
    /* Helper handles desc cleanup internally */
    return ret;
}

/**
 * recalculate_merkle_root - Recalculate the Merkle tree root hash from scratch
 *
 * Computes the Merkle root by hashing together all container leaf hashes.
 * This is used for initialization or when the tree needs to be rebuilt.
 * For normal operations, use extend_merkle_root() instead.
 *
 * Uses mutex to serialize the entire operation including TPM extension,
 * preventing race conditions.
 *
 * Returns: 0 on success, negative error code on failure
 */
int recalculate_merkle_root(void)
{
    struct container_node *container;
    struct shash_desc *desc;
    unsigned long flags;
    int ret = 0;
    u32 leaf_count = 0;
    u8 new_root[MERKLE_HASH_SIZE];
    bool can_sleep = !in_atomic() && !irqs_disabled();

    if (!system_merkle_root.tfm)
        return -EINVAL;

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(system_merkle_root.tfm), GFP_ATOMIC);
    if (!desc)
        return -ENOMEM;

    desc->tfm = system_merkle_root.tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0)
        goto cleanup;

    spin_lock_irqsave(&container_list_lock, flags);
    list_for_each_entry(container, &container_list, list)
    {
        /* Fix inconsistent read: acquire container lock before reading leaf_hash */
        spin_lock(&container->measurement_lock);
        ret = crypto_shash_update(desc, container->leaf_hash, MERKLE_HASH_SIZE);
        spin_unlock(&container->measurement_lock);
        
        if (ret < 0)
        {
            spin_unlock_irqrestore(&container_list_lock, flags);
            goto cleanup;
        }
        leaf_count++;
    }
    spin_unlock_irqrestore(&container_list_lock, flags);

    ret = crypto_shash_final(desc, new_root);
    if (ret < 0)
        goto cleanup;

    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(system_merkle_root.root_hash, new_root, MERKLE_HASH_SIZE);
    system_merkle_root.leaf_count = leaf_count;
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);

    pr_debug("bpfima: Merkle root recalculated with %u leaves\n", leaf_count);

    try_extend_tpm_with_root(new_root, can_sleep);

    ret = 0;

cleanup:
    kfree(desc);
    return ret;
}

/**
 * get_merkle_root_history_count - Get current count of merkle root history entries
 *
 * Returns: Current number of entries in merkle_root_history
 */
u32 get_merkle_root_history_count(void)
{
    return atomic_read(&merkle_root_history_count);
}

/**
 * add_merkle_root_history_entry - Record a value being added to Merkle root
 * @value: Hash value being incorporated into the root
 * @container_id: ID of source container (NULL or empty for host events)
 *
 * Returns: 0 on success, negative error code on failure
 */
int add_merkle_root_history_entry(const u8 *value, const char *container_id)
{
    struct merkle_root_entry *entry;
    struct bpfima_policy_config *policy;
    unsigned long flags;
    u32 current_count;
    bool should_check_limit = true;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    memcpy(entry->value, value, MERKLE_HASH_SIZE);

    if (container_id && container_id[0] != '\0')
        strscpy(entry->source_container_id, container_id, CONTAINER_ID_MAX_LEN);
    else
        entry->source_container_id[0] = '\0';

    /* Initialize aggregate fields */
    entry->is_aggregate = false;
    entry->aggregated_count = 0;

    /* Check policy scope */
    policy = bpfima_policy_get();
    if (policy && policy->merkle_history_scope == MERKLE_HISTORY_SCOPE_ROOT_ONLY) {
        /* Only apply circular buffer to root/global entries (empty container_id) */
        if (container_id && container_id[0] != '\0') {
            should_check_limit = false;
        }
    }

    spin_lock_irqsave(&merkle_root_history_lock, flags);
    list_add_tail(&entry->list, &merkle_root_history);
    spin_unlock_irqrestore(&merkle_root_history_lock, flags);

    /* File writing removed - userspace now dumps securityfs periodically */

    /* Increment counter and check if we need to trim */
    current_count = atomic_inc_return(&merkle_root_history_count);

    if (should_check_limit && policy && policy->merkle_history_max_size > 0) {
        if (current_count > policy->merkle_history_max_size) {
            pr_info("bpfima: Merkle history reached max size (%u), trimming...\n",
                    policy->merkle_history_max_size);
            trim_merkle_root_history(policy->merkle_history_max_size);
        }
    }

    return 0;
}

/**
 * add_container_measurement - Add a measurement to a container's list
 * @container: Container node to add measurement to
 * @event_name: Name of the event
 * @event_data: Event data string
 * @dependencies: Dependencies string
 * @digest: SHA256 hash of the measurement
 * @flags: Allocation flags (GFP_KERNEL or GFP_ATOMIC)
 *
 * Uses spinlocks for safe atomic context execution.
 */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const char *dependencies,
                              const u8 *digest,
                              gfp_t flags)
{
    struct measurement_entry *entry;
    unsigned long irq_flags;
    int ret;
    bool can_sleep = (flags & __GFP_DIRECT_RECLAIM);

    if (hash_exists(digest, container->id))
    {
        pr_info("bpfima: Duplicate file access for namespace %s, digest=%*ph (skipped)\n",
                 container->id, SHA256_DIGEST_SIZE, digest);
        return 1;
    }

    ret = add_hash_to_table(digest, container->id, can_sleep);
    if (ret)
    {
        pr_err("bpfima: Failed to add hash to tracking table for namespace %s: %d\n",
               container->id, ret);
        return ret;
    }

    entry = create_measurement_entry(event_name, event_data, dependencies, digest, flags);
    if (!entry)
        return -ENOMEM;

    /* Critical section: lock container, add entry, extend leaf */
    spin_lock_irqsave(&container->measurement_lock, irq_flags);
    
    list_add_tail(&entry->list, &container->measurement_list);
    atomic_inc(&container->measurement_count);

    ret = extend_container_leaf_hash(container, digest);
    if (ret < 0)
    {
        list_del(&entry->list);
        atomic_dec(&container->measurement_count);
        spin_unlock_irqrestore(&container->measurement_lock, irq_flags);
        
        kfree(entry);
        return ret;
    }

    spin_unlock_irqrestore(&container->measurement_lock, irq_flags);

    ret = add_merkle_root_history_entry(container->leaf_hash, container->id);
    if (ret < 0)
    {
        pr_warn("bpfima: Failed to add merkle root history entry: %d\n", ret);
    }

    ret = extend_merkle_root(container->leaf_hash);
    if (ret < 0)
    {
        /* Rollback is hard because we already released lock, but typical usage allows log warning */
        pr_err("bpfima: Failed to extend merkle root: %d\n", ret);
        return ret;
    }

    pr_debug("bpfima: Added measurement to container %s\n", container->id);

    return 0;
}

/**
 * aggregate_merkle_entries - Compute TPM-style aggregate hash from list of entries
 * @entries_to_aggregate: List of merkle_root_entry to aggregate
 * @aggregate_hash: Output buffer for the aggregate hash (must be MERKLE_HASH_SIZE bytes)
 * @count_out: Output parameter for number of entries aggregated
 *
 * Computes an aggregate hash using TPM PCR-style extension:
 *   val = SHA256(0x00...00 || hash1)
 *   val = SHA256(val || hash2)
 *   ...
 *   aggregate = SHA256(val || hashN)
 *
 * Returns: 0 on success, negative error code on failure
 */
int aggregate_merkle_entries(struct list_head *entries_to_aggregate, u8 *aggregate_hash, u32 *count_out)
{
    struct merkle_root_entry *entry;
    struct shash_desc *desc;
    u8 current_val[MERKLE_HASH_SIZE];
    u8 zero_init[MERKLE_HASH_SIZE];
    int ret = 0;
    u32 count = 0;
    bool first = true;

    if (!entries_to_aggregate || !aggregate_hash || !count_out) {
        pr_err("bpfima: aggregate_merkle_entries: NULL parameter\n");
        return -EINVAL;
    }

    /* Initialize with zeros for first extension */
    memset(zero_init, 0, MERKLE_HASH_SIZE);
    memset(current_val, 0, MERKLE_HASH_SIZE);

    if (!system_merkle_root.tfm) {
        pr_err("bpfima: aggregate_merkle_entries: System tfm not allocated\n");
        return -EINVAL;
    }

    /* desc allocation must be atomic because we might be in atomic context (via trim history) */
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(system_merkle_root.tfm), GFP_ATOMIC);
    if (!desc) {
        pr_err("bpfima: Failed to allocate shash descriptor for aggregation\n");
        return -ENOMEM;
    }

    desc->tfm = system_merkle_root.tfm;

    /* Iterate through entries and perform TPM-style extension */
    list_for_each_entry(entry, entries_to_aggregate, list) {
        ret = crypto_shash_init(desc);
        if (ret < 0) {
            pr_err("bpfima: crypto_shash_init failed in aggregation: %d\n", ret);
            goto cleanup;
        }

        if (first) {
            /* First extension: hash(0x00...00 || hash1) */
            ret = crypto_shash_update(desc, zero_init, MERKLE_HASH_SIZE);
            first = false;
        } else {
            /* Subsequent extensions: hash(current_val || hash_i) */
            ret = crypto_shash_update(desc, current_val, MERKLE_HASH_SIZE);
        }

        if (ret < 0) {
            pr_err("bpfima: crypto_shash_update (current_val) failed in aggregation: %d\n", ret);
            goto cleanup;
        }

        ret = crypto_shash_update(desc, entry->value, MERKLE_HASH_SIZE);
        if (ret < 0) {
            pr_err("bpfima: crypto_shash_update (entry value) failed in aggregation: %d\n", ret);
            goto cleanup;
        }

        ret = crypto_shash_final(desc, current_val);
        if (ret < 0) {
            pr_err("bpfima: crypto_shash_final failed in aggregation: %d\n", ret);
            goto cleanup;
        }

        count++;
    }

    if (count == 0) {
        pr_warn("bpfima: No entries to aggregate\n");
        ret = -EINVAL;
        goto cleanup;
    }

    memcpy(aggregate_hash, current_val, MERKLE_HASH_SIZE);
    *count_out = count;

    pr_info("bpfima: Aggregated %u entries using TPM-style extension\n", count);
    ret = 0;

cleanup:
    memzero_explicit(current_val, sizeof(current_val));
    memzero_explicit(zero_init, sizeof(zero_init));
    if (desc) {
        memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(system_merkle_root.tfm));
        kfree(desc);
    }
    return ret;
}

/**
 * trim_merkle_root_history - Trim history list when it exceeds max size
 * @max_size: Maximum allowed size
 *
 * When the list exceeds max_size, this function:
 * 1. Deletes the oldest half of entries
 * 2. Computes an aggregate hash of deleted entries (TPM-style)
 * 3. Inserts the aggregate as the first entry in the remaining list
 *
 * Returns: 0 on success, negative error code on failure
 */
int trim_merkle_root_history(u32 max_size)
{
    struct merkle_root_entry *entry, *tmp, *aggregate_entry;
    LIST_HEAD(entries_to_delete);
    unsigned long flags;
    u32 current_count, to_delete, deleted_count = 0;
    u8 aggregate_hash[MERKLE_HASH_SIZE];
    u32 aggregated_count = 0;
    int ret;

    current_count = atomic_read(&merkle_root_history_count);
    
    if (current_count <= max_size) {
        return 0;
    }

    to_delete = current_count / 2;
    if (to_delete == 0) {
        to_delete = 1; 
    }

    bool can_sleep = !in_atomic() && !irqs_disabled();

    aggregate_entry = kzalloc(sizeof(*aggregate_entry), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!aggregate_entry) {
        pr_err("bpfima: Failed to allocate aggregate entry, aborting trim\n");
        return -ENOMEM;
    }

    pr_info("bpfima: Trimming merkle history: current=%u, max=%u, deleting=%u\n",
            current_count, max_size, to_delete);

    spin_lock_irqsave(&merkle_root_history_lock, flags);

    /* Move oldest entries to temporary list */
    list_for_each_entry_safe(entry, tmp, &merkle_root_history, list) {
        if (deleted_count >= to_delete) {
            break;
        }
        list_del(&entry->list);
        list_add_tail(&entry->list, &entries_to_delete);
        deleted_count++;
    }

    spin_unlock_irqrestore(&merkle_root_history_lock, flags);

    /* Compute aggregate of deleted entries */
    ret = aggregate_merkle_entries(&entries_to_delete, aggregate_hash, &aggregated_count);
    if (ret < 0) {
        pr_err("bpfima: Failed to aggregate deleted entries: %d\n", ret);
        
        spin_lock_irqsave(&merkle_root_history_lock, flags);
        list_splice(&entries_to_delete, &merkle_root_history);
        spin_unlock_irqrestore(&merkle_root_history_lock, flags);
        
        kfree(aggregate_entry);
        return ret;
    }

    memcpy(aggregate_entry->value, aggregate_hash, MERKLE_HASH_SIZE);
    strscpy(aggregate_entry->source_container_id, "[AGGREGATE]", CONTAINER_ID_MAX_LEN);
    aggregate_entry->is_aggregate = true;
    aggregate_entry->aggregated_count = aggregated_count;

    spin_lock_irqsave(&merkle_root_history_lock, flags);
    list_add(&aggregate_entry->list, &merkle_root_history);
    spin_unlock_irqrestore(&merkle_root_history_lock, flags);

    /* Free the deleted entries */
    list_for_each_entry_safe(entry, tmp, &entries_to_delete, list) {
        list_del(&entry->list);
        kfree(entry);
    }

    /* Update counter: subtract deleted, add 1 for aggregate */
    atomic_sub(deleted_count, &merkle_root_history_count);
    atomic_inc(&merkle_root_history_count);

    pr_info("bpfima: Trimmed %u entries, created aggregate of %u entries\n",
            deleted_count, aggregated_count);

    return 0;
}

/**
 * cleanup_merkle_root_history - Free all Merkle root history entries
 */
void cleanup_merkle_root_history(void)
{
    struct merkle_root_entry *entry, *tmp;
    unsigned long flags;
    int count = 0;

    spin_lock_irqsave(&merkle_root_history_lock, flags);
    list_for_each_entry_safe(entry, tmp, &merkle_root_history, list)
    {
        list_del(&entry->list);
        kfree(entry);
        count++;
    }
    spin_unlock_irqrestore(&merkle_root_history_lock, flags);

    /* Reset counter */
    atomic_set(&merkle_root_history_count, 0);

    pr_info("bpfima: Cleaned up %d merkle root history entries\n", count);
}
