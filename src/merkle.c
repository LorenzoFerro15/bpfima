/*
 * Merkle Tree Implementation for Container Tracking
 * 
 * This file implements a non-binary Merkle tree where each container
 * is represented as a leaf node. The root hash represents the entire
 * system state (virtual PCR value).
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/hash.h>

#include "bpfima_common.h"
#include "bpfima_merkle.h"
#include "bpfima_securityfs.h"

/* Global state */
LIST_HEAD(container_list);
DEFINE_SPINLOCK(container_list_lock);

LIST_HEAD(host_measurement_list);
DEFINE_SPINLOCK(host_measurement_lock);

LIST_HEAD(merkle_root_history);
DEFINE_SPINLOCK(merkle_root_history_lock);

struct merkle_tree_root system_merkle_root;
atomic_t container_count = ATOMIC_INIT(0);

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
 * find_container_by_id - Find a container node by its ID
 * @container_id: Container identifier to search for
 *
 * Must be called with container_list_lock held.
 * Returns: Pointer to container_node if found, NULL otherwise
 */
struct container_node *find_container_by_id(const char *container_id)
{
    struct container_node *container;
    
    list_for_each_entry(container, &container_list, list) {
        if (strcmp(container->id, container_id) == 0)
            return container;
    }
    
    return NULL;
}

/**
 * create_container_node - Create and initialize a new container node
 * @container_id: Unique identifier for the container
 *
 * Returns: Pointer to new container_node on success, ERR_PTR on failure
 */
struct container_node *create_container_node(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;
    int ret;
    
    container = kzalloc(sizeof(*container), GFP_KERNEL);
    if (!container)
        return ERR_PTR(-ENOMEM);
    
    /* Initialize container structure */
    strscpy(container->id, container_id, CONTAINER_ID_MAX_LEN);
    INIT_LIST_HEAD(&container->measurement_list);
    spin_lock_init(&container->measurement_lock);
    memset(container->leaf_hash, 0, MERKLE_HASH_SIZE);
    atomic_set(&container->measurement_count, 0);
    container->securityfs_dir = NULL;
    container->securityfs_measurements_file = NULL;
    
    /* Add to global container list */
    spin_lock_irqsave(&container_list_lock, flags);
    list_add_tail(&container->list, &container_list);
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    atomic_inc(&container_count);
    
    /* Create securityfs directory for this container */
    ret = create_container_securityfs(container);
    if (ret < 0) {
        pr_err("bpfima: Failed to create securityfs for container %s: %d\n",
               container_id, ret);
        /* Remove from list on failure */
        spin_lock_irqsave(&container_list_lock, flags);
        list_del(&container->list);
        spin_unlock_irqrestore(&container_list_lock, flags);
        atomic_dec(&container_count);
        kfree(container);
        return ERR_PTR(ret);
    }
    
    pr_info("bpfima: Created container node for %s\n", container_id);
    return container;
}

/**
 * add_container_measurement - Add a measurement to a container's list
 *
 * Returns: 0 on success, negative error code on failure
 */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const u8 *digest)
{
    struct measurement_entry *entry;
    unsigned long flags;
    int ret;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    /* Initialize measurement entry */
    strscpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX + 1);
    if (event_data)
        strscpy(entry->event_data, event_data, sizeof(entry->event_data));
    else
        entry->event_data[0] = '\0';
    memcpy(entry->digest, digest, MERKLE_HASH_SIZE);
    
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
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    /* Initialize measurement entry */
    strscpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX + 1);
    if (event_data)
        strscpy(entry->event_data, event_data, sizeof(entry->event_data));
    else
        entry->event_data[0] = '\0';
    memcpy(entry->digest, digest, MERKLE_HASH_SIZE);
    
    /* Add to host measurement list */
    spin_lock_irqsave(&host_measurement_lock, flags);
    list_add_tail(&entry->list, &host_measurement_list);
    spin_unlock_irqrestore(&host_measurement_lock, flags);
    
    pr_debug("bpfima: Added measurement to host list: %s\n", event_name);
    
    return 0;
}

/**
 * cleanup_container_measurements - Free all measurements in a container
 * @container: Container to clean up
 */
void cleanup_container_measurements(struct container_node *container)
{
    struct measurement_entry *entry, *tmp;
    
    list_for_each_entry_safe(entry, tmp, &container->measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

/**
 * cleanup_all_containers - Remove and free all container nodes
 */
void cleanup_all_containers(void)
{
    struct container_node *container, *tmp;
    unsigned long flags;
    int count = 0;
    
    spin_lock_irqsave(&container_list_lock, flags);
    list_for_each_entry_safe(container, tmp, &container_list, list) {
        list_del(&container->list);
        spin_unlock_irqrestore(&container_list_lock, flags);
        
        /* Remove securityfs entries */
        remove_container_securityfs(container);
        
        /* Clean up measurements */
        cleanup_container_measurements(container);
        
        /* Free container */
        kfree(container);
        count++;
        
        spin_lock_irqsave(&container_list_lock, flags);
    }
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    pr_info("bpfima: Cleaned up %d containers\n", count);
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
