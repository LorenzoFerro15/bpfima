/*
 * Merkle Tree Implementation for BPF-IMA
 * 
 * This file implements a non-binary Merkle tree where each container
 * is represented as a leaf node. The root hash represents the entire
 * system state (virtual PCR value).
 */

// #include <linux/preempt.h>
// #include <linux/irqflags.h>

#include "bpfima_common.h"
#include "bpfima_merkle.h"
#include "bpfima_container.h"
#include "bpfima_measurements.h"
#include "bpfima_securityfs.h"

/* Global state */
LIST_HEAD(host_measurement_list);
DEFINE_SPINLOCK(host_measurement_lock);

LIST_HEAD(merkle_root_history);
DEFINE_SPINLOCK(merkle_root_history_lock);

struct merkle_tree_root system_merkle_root;

/**
 * compute_container_leaf_hash - Compute the leaf hash for a container
 * @container: Container node to compute hash for
 *
 * Computes SHA-256 hash of all measurement digests in the container's
 * measurement list. This hash becomes the container's leaf in the Merkle tree.
 *
 * Returns: 0 on success, negative error code on failure
 */
int compute_container_leaf_hash(struct container_node *container)
{
    struct measurement_entry *entry;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned long flags;
    int ret = 0;
    
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    
    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0)
        goto cleanup;
    
    /* Hash all measurement digests in order */
    spin_lock_irqsave(&container->measurement_lock, flags);
    list_for_each_entry(entry, &container->measurement_list, list) {
        ret = crypto_shash_update(desc, entry->digest, MERKLE_HASH_SIZE);
        if (ret < 0) {
            spin_unlock_irqrestore(&container->measurement_lock, flags);
            goto cleanup;
        }
    }
    spin_unlock_irqrestore(&container->measurement_lock, flags);
    
    /* Finalize the hash */
    ret = crypto_shash_final(desc, container->leaf_hash);
    
cleanup:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/**
 * recalculate_merkle_root - Recalculate the Merkle tree root hash
 *
 * Computes the Merkle root by hashing together all container leaf hashes.
 * The root hash represents the entire system state (virtual PCR value).
 *
 * This function follows the same pattern as process_measurement:
 * 1. Check if we can sleep (atomic context detection)
 * 2. Perform hash calculation
 * 3. Update global state with spinlock protection
 * 4. Release lock before TPM operation (which can sleep)
 * 5. Defer TPM extension if called from atomic context
 *
 * Returns: 0 on success, negative error code on failure
 */
int recalculate_merkle_root(void)
{
    struct container_node *container;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned long flags;
    int ret = 0;
    u32 leaf_count = 0;
    u8 new_root[MERKLE_HASH_SIZE];
    bool can_sleep = !in_atomic() && !irqs_disabled();
    
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), 
                   can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    
    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0)
        goto cleanup;
    
    /* Hash all container leaf hashes together */
    spin_lock_irqsave(&container_list_lock, flags);
    list_for_each_entry(container, &container_list, list) {
        ret = crypto_shash_update(desc, container->leaf_hash, MERKLE_HASH_SIZE);
        if (ret < 0) {
            spin_unlock_irqrestore(&container_list_lock, flags);
            goto cleanup;
        }
        leaf_count++;
    }
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    /* Finalize the root hash */
    ret = crypto_shash_final(desc, new_root);
    if (ret < 0)
        goto cleanup;
    
    /* Update the global Merkle root */
    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(system_merkle_root.root_hash, new_root, MERKLE_HASH_SIZE);
    system_merkle_root.leaf_count = leaf_count;
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);
    
    pr_debug("bpfima: Merkle root recalculated with %u leaves\n", leaf_count);
    
    if (!can_sleep) {
        pr_info("bpfima: Called from atomic context, TPM extension deferred for merkle_root_update\n");
    } else {
        /* 
         * Release lock before performing TPM extension which may sleep
         * Following the same pattern as process_measurement
         */
        ret = extend_tpm_pcr_with_root(new_root, "merkle_root_update");
        if (ret < 0 && ret != -ENODEV) {
            /* Log error but don't fail - TPM extension is optional */
            pr_warn("bpfima: Failed to extend TPM PCR with Merkle root: %d\n", ret);
        }
    }
    
    ret = 0; /* Success regardless of TPM extension result */
    
cleanup:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
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
    unsigned long flags;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    memcpy(entry->value, value, MERKLE_HASH_SIZE);
    
    if (container_id && container_id[0] != '\0')
        strscpy(entry->source_container_id, container_id, CONTAINER_ID_MAX_LEN);
    else
        entry->source_container_id[0] = '\0';
    
    spin_lock_irqsave(&merkle_root_history_lock, flags);
    list_add_tail(&entry->list, &merkle_root_history);
    spin_unlock_irqrestore(&merkle_root_history_lock, flags);
    
    return 0;
}

/**
 * add_container_measurement - Add a measurement to a container's list
 * @container: Container node to add measurement to
 * @event_name: Name of the event
 * @event_data: Event data string
 * @digest: SHA256 hash of the measurement
 *
 * Checks if this file (identified by digest) has already been accessed by this
 * namespace. If so, skips adding a duplicate measurement. If not, adds the
 * measurement to the container's list, updates the container's leaf hash,
 * and recalculates the Merkle root.
 *
 * Returns: 0 on success, negative error code on failure, 1 if duplicate skipped
 */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const u8 *digest)
{
    struct measurement_entry *entry;
    unsigned long flags;
    int ret;
    
    /* Check if this namespace has already accessed this file */
    if (hash_exists(digest, container->id)) {
        pr_info("bpfima: Duplicate file access for namespace %s, digest=%*ph (skipped)\n",
                container->id, SHA256_DIGEST_SIZE, digest);
        return 1; /* Indicate duplicate was skipped */
    }
    
    /* Add to per-namespace hash table */
    ret = add_hash_to_table(digest, container->id, true);
    if (ret) {
        pr_err("bpfima: Failed to add hash to tracking table for namespace %s: %d\n",
               container->id, ret);
        return ret;
    }
    
    /* Create measurement entry using helper function */
    entry = create_measurement_entry(event_name, event_data, digest, GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    /* Add to container's measurement list */
    spin_lock_irqsave(&container->measurement_lock, flags);
    list_add_tail(&entry->list, &container->measurement_list);
    spin_unlock_irqrestore(&container->measurement_lock, flags);
    
    atomic_inc(&container->measurement_count);
    
    /* Recalculate container's leaf hash */
    ret = compute_container_leaf_hash(container);
    if (ret < 0) {
        pr_err("bpfima: Failed to compute leaf hash for container %s: %d\n",
               container->id, ret);
        return ret;
    }
    
    /* Add to Merkle root history */
    ret = add_merkle_root_history_entry(container->leaf_hash, container->id);
    if (ret < 0) {
        pr_warn("bpfima: Failed to add merkle root history entry: %d\n", ret);
        /* Continue anyway, this is not critical */
    }
    
    /* Recalculate Merkle root */
    ret = recalculate_merkle_root();
    if (ret < 0) {
        pr_err("bpfima: Failed to recalculate merkle root: %d\n", ret);
        return ret;
    }
    
    pr_debug("bpfima: Added measurement to container %s, leaf hash updated\n",
             container->id);
    
    return 0;
}

/**
 * add_host_measurement - Add a measurement to the host measurement list
 *
 * Returns: 0 on success, negative error code on failure
 */
int add_host_measurement(const char *event_name,
                        const char *event_data,
                        const u8 *digest)
{
    struct measurement_entry *entry;
    unsigned long flags;
    
    /* Create measurement entry using helper function */
    entry = create_measurement_entry(event_name, event_data, digest, GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    /* Add to host measurement list */
    spin_lock_irqsave(&host_measurement_lock, flags);
    list_add_tail(&entry->list, &host_measurement_list);
    spin_unlock_irqrestore(&host_measurement_lock, flags);
    
    pr_debug("bpfima: Added measurement to host list: %s\n", event_name);
    
    return 0;
}

/**
 * cleanup_host_measurements - Free all host measurement entries
 */
void cleanup_host_measurements(void)
{
    struct measurement_entry *entry, *tmp;
    unsigned long flags;
    int count = 0;
    
    spin_lock_irqsave(&host_measurement_lock, flags);
    list_for_each_entry_safe(entry, tmp, &host_measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
        count++;
    }
    spin_unlock_irqrestore(&host_measurement_lock, flags);
    
    pr_info("bpfima: Cleaned up %d host measurements\n", count);
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
    list_for_each_entry_safe(entry, tmp, &merkle_root_history, list) {
        list_del(&entry->list);
        kfree(entry);
        count++;
    }
    spin_unlock_irqrestore(&merkle_root_history_lock, flags);
    
    pr_info("bpfima: Cleaned up %d merkle root history entries\n", count);
}
