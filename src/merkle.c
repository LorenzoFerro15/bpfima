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

/*
 * Mutex to serialize merkle root extensions including TPM operations.
 * This prevents race conditions where the merkle root could be modified
 * between updating the hash and extending the TPM.
 */
static DEFINE_MUTEX(bpfima_merkle_root_mutex);

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
 * compute_container_leaf_hash - Compute the leaf hash for a container
 * @container: Container node to compute hash for
 *
 * Computes SHA-256 hash of all measurement digests in the container's
 * measurement list. This hash becomes the container's leaf in the Merkle tree.
 * This is used only for initialization or rebuilding from scratch.
 * For normal operations, use extend_container_leaf_hash() instead.
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

    if (!container) {
        pr_err("bpfima: compute_container_leaf_hash: NULL container\n");
        return -EINVAL;
    }

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        pr_err("bpfima: Failed to allocate sha256 hash: %d\n", ret);
        return ret;
    }

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        pr_err("bpfima: Failed to allocate shash descriptor\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_init failed: %d\n", ret);
        goto cleanup;
    }

    /* Hash all measurement digests in order */
    spin_lock_irqsave(&container->measurement_lock, flags);
    list_for_each_entry(entry, &container->measurement_list, list)
    {
        if (!entry) {
            pr_warn("bpfima: NULL entry in measurement list\n");
            continue;
        }
        ret = crypto_shash_update(desc, entry->digest, MERKLE_HASH_SIZE);
        if (ret < 0)
        {
            pr_err("bpfima: crypto_shash_update failed: %d\n", ret);
            spin_unlock_irqrestore(&container->measurement_lock, flags);
            goto cleanup;
        }
    }
    spin_unlock_irqrestore(&container->measurement_lock, flags);

    /* Finalize the hash */
    ret = crypto_shash_final(desc, container->leaf_hash);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_final failed: %d\n", ret);
    }

cleanup:
    if (desc) {
        memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
        kfree(desc);
    }
    crypto_free_shash(tfm);
    return ret;
}

/**
 * extend_container_leaf_hash - Extend container leaf hash with new measurement
 * @container: Container node to extend
 * @new_digest: New measurement digest to extend into the leaf hash
 *
 * Extends the container's leaf hash using PCR-style extend operation:
 * new_leaf = hash(old_leaf || new_digest)
 *
 * This is more efficient than recomputing the hash from all measurements.
 *
 * Returns: 0 on success, negative error code on failure
 */
int extend_container_leaf_hash(struct container_node *container, const u8 *new_digest)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned long flags;
    int ret = 0;
    u8 old_leaf[MERKLE_HASH_SIZE];
    u8 new_leaf[MERKLE_HASH_SIZE];

    if (!container) {
        pr_err("bpfima: extend_container_leaf_hash: NULL container\n");
        return -EINVAL;
    }

    if (!new_digest) {
        pr_err("bpfima: extend_container_leaf_hash: NULL digest\n");
        return -EINVAL;
    }

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        pr_err("bpfima: Failed to allocate sha256 hash: %d\n", ret);
        return ret;
    }

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        pr_err("bpfima: Failed to allocate shash descriptor\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_init failed: %d\n", ret);
        goto cleanup;
    }

    spin_lock_irqsave(&container->measurement_lock, flags);
    memcpy(old_leaf, container->leaf_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&container->measurement_lock, flags);

    ret = crypto_shash_update(desc, old_leaf, MERKLE_HASH_SIZE);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_update (old_leaf) failed: %d\n", ret);
        goto cleanup;
    }

    ret = crypto_shash_update(desc, new_digest, MERKLE_HASH_SIZE);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_update (new_digest) failed: %d\n", ret);
        goto cleanup;
    }

    ret = crypto_shash_final(desc, new_leaf);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_final failed: %d\n", ret);
        goto cleanup;
    }

    spin_lock_irqsave(&container->measurement_lock, flags);
    memcpy(container->leaf_hash, new_leaf, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&container->measurement_lock, flags);

    pr_debug("bpfima: Container %s leaf hash extended\n", container->id);

cleanup:
    memzero_explicit(old_leaf, sizeof(old_leaf));
    memzero_explicit(new_leaf, sizeof(new_leaf));
    if (desc) {
        memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
        kfree(desc);
    }
    crypto_free_shash(tfm);
    return ret;
}

/**
 * extend_merkle_root - Extend the Merkle tree root with a new container leaf hash
 * @container_leaf_hash: The new container leaf hash to extend into the root
 *
 * Computes the new Merkle root by extending the old root with the new leaf hash:
 * root_new = hash(root_old || leaf_hash_new)
 *
 * This implements a PCR-style extend operation rather than recalculating from
 * all leaves, making it more efficient and following TPM extend semantics.
 *
 * Uses mutex to serialize the entire operation including TPM extension,
 * preventing race conditions where another thread could modify the root
 * between hash update and TPM extension.
 *
 * For atomic context calls, we defer TPM extension as it requires sleeping.
 *
 * Returns: 0 on success, negative error code on failure
 */
int extend_merkle_root(const u8 *container_leaf_hash)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned long flags;
    int ret = 0;
    u8 old_root[MERKLE_HASH_SIZE];
    u8 new_root[MERKLE_HASH_SIZE];
    bool can_sleep = !in_atomic() && !irqs_disabled();

    if (!container_leaf_hash) {
        pr_err("bpfima: extend_merkle_root: NULL container_leaf_hash\n");
        return -EINVAL;
    }

    if (can_sleep)
    {
        mutex_lock(&bpfima_merkle_root_mutex);
    }

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        ret = PTR_ERR(tfm);
        pr_err("bpfima: Failed to allocate sha256 hash for merkle root: %d\n", ret);
        if (can_sleep)
            mutex_unlock(&bpfima_merkle_root_mutex);
        return ret;
    }

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                   can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!desc)
    {
        pr_err("bpfima: Failed to allocate shash descriptor for merkle root\n");
        crypto_free_shash(tfm);
        if (can_sleep)
            mutex_unlock(&bpfima_merkle_root_mutex);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_init failed for merkle root: %d\n", ret);
        goto cleanup;
    }

    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(old_root, system_merkle_root.root_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);

    /* Extend: new_root = hash(old_root || container_leaf_hash) */
    ret = crypto_shash_update(desc, old_root, MERKLE_HASH_SIZE);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_update (old_root) failed: %d\n", ret);
        goto cleanup;
    }

    ret = crypto_shash_update(desc, container_leaf_hash, MERKLE_HASH_SIZE);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_update (leaf_hash) failed: %d\n", ret);
        goto cleanup;
    }

    ret = crypto_shash_final(desc, new_root);
    if (ret < 0) {
        pr_err("bpfima: crypto_shash_final failed for merkle root: %d\n", ret);
        goto cleanup;
    }

    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(system_merkle_root.root_hash, new_root, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);

    pr_debug("bpfima: Merkle root extended with container leaf hash\n");

    try_extend_tpm_with_root(new_root, can_sleep);

    ret = 0;

cleanup:
    memzero_explicit(old_root, sizeof(old_root));
    memzero_explicit(new_root, sizeof(new_root));
    if (desc) {
        memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
        kfree(desc);
    }
    crypto_free_shash(tfm);
    if (can_sleep)
        mutex_unlock(&bpfima_merkle_root_mutex);
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
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned long flags;
    int ret = 0;
    u32 leaf_count = 0;
    u8 new_root[MERKLE_HASH_SIZE];
    bool can_sleep = !in_atomic() && !irqs_disabled();

    if (can_sleep)
    {
        mutex_lock(&bpfima_merkle_root_mutex);
    }

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        if (can_sleep)
            mutex_unlock(&bpfima_merkle_root_mutex);
        return PTR_ERR(tfm);
    }

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                   can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!desc)
    {
        crypto_free_shash(tfm);
        if (can_sleep)
            mutex_unlock(&bpfima_merkle_root_mutex);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0)
        goto cleanup;

    spin_lock_irqsave(&container_list_lock, flags);
    list_for_each_entry(container, &container_list, list)
    {
        ret = crypto_shash_update(desc, container->leaf_hash, MERKLE_HASH_SIZE);
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
    crypto_free_shash(tfm);
    if (can_sleep)
        mutex_unlock(&bpfima_merkle_root_mutex);
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
 * @dependencies: Dependencies string (e.g., previous measurement hash)
 * @digest: SHA256 hash of the measurement
 *
 * Checks if this file (identified by digest) has already been accessed by this
 * namespace. If so, skips adding a duplicate measurement. If not, adds the
 * measurement to the container's list, updates the container's leaf hash,
 * and recalculates the Merkle root.
 *
 * Uses per-container mutex to serialize the entire operation (leaf hash extension
 * and merkle root update) preventing race conditions where inconsistent state
 * could result from interleaved operations.
 *
 * Returns: 0 on success, negative error code on failure, 1 if duplicate skipped
 */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const char *dependencies,
                              const u8 *digest)
{
    struct measurement_entry *entry;
    unsigned long flags;
    int ret;

    if (hash_exists(digest, container->id))
    {
        pr_info("bpfima: Duplicate file access for namespace %s, digest=%*ph (skipped)\n",
                container->id, SHA256_DIGEST_SIZE, digest);
        return 1;
    }

    ret = add_hash_to_table(digest, container->id, true);
    if (ret)
    {
        pr_err("bpfima: Failed to add hash to tracking table for namespace %s: %d\n",
               container->id, ret);
        return ret;
    }

    entry = create_measurement_entry(event_name, event_data, dependencies, digest, GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    mutex_lock(&container->measurement_mutex);

    spin_lock_irqsave(&container->measurement_lock, flags);
    list_add_tail(&entry->list, &container->measurement_list);
    spin_unlock_irqrestore(&container->measurement_lock, flags);

    atomic_inc(&container->measurement_count);

    ret = extend_container_leaf_hash(container, digest);
    if (ret < 0)
    {
        pr_err("bpfima: Failed to extend leaf hash for container %s: %d\n",
               container->id, ret);

        spin_lock_irqsave(&container->measurement_lock, flags);
        list_del(&entry->list);
        spin_unlock_irqrestore(&container->measurement_lock, flags);

        atomic_dec(&container->measurement_count);
        kfree(entry);
        mutex_unlock(&container->measurement_mutex);
        return ret;
    }

    ret = add_merkle_root_history_entry(container->leaf_hash, container->id);
    if (ret < 0)
    {
        pr_warn("bpfima: Failed to add merkle root history entry: %d\n", ret);
    }

    ret = extend_merkle_root(container->leaf_hash);
    if (ret < 0)
    {
        pr_err("bpfima: Failed to extend merkle root: %d\n", ret);

        spin_lock_irqsave(&container->measurement_lock, flags);
        list_del(&entry->list);
        spin_unlock_irqrestore(&container->measurement_lock, flags);

        atomic_dec(&container->measurement_count);
        kfree(entry);
        pr_warn("bpfima: Merkle root extension failed. Container %s leaf hash is now inconsistent.\n",
                container->id);

        mutex_unlock(&container->measurement_mutex);
        return ret;
    }

    mutex_unlock(&container->measurement_mutex);

    pr_debug("bpfima: Added measurement to container %s, leaf hash updated and root extended\n",
             container->id);

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
    struct crypto_shash *tfm;
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

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        pr_err("bpfima: Failed to allocate sha256 for aggregation: %d\n", ret);
        return ret;
    }

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        pr_err("bpfima: Failed to allocate shash descriptor for aggregation\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

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
        memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
        kfree(desc);
    }
    crypto_free_shash(tfm);
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

    aggregate_entry = kzalloc(sizeof(*aggregate_entry), GFP_KERNEL);
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
