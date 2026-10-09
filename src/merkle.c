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
#include "bpfima_policy.h"

/* Global state */
LIST_HEAD(merkle_root_history);
DEFINE_SPINLOCK(merkle_root_history_lock);

struct merkle_tree_root system_merkle_root = {.root_hash = {0}};

/* Counter for merkle_root_history entries (for circular buffer management) */
static atomic_t merkle_root_history_count = ATOMIC_INIT(0);

static struct merkle_root_entry *bpfima_alloc_history_entry(const char *source_id);
static void bpfima_publish_history_entry_locked(struct merkle_root_entry *entry);
static void bpfima_trim_history_locked(const char *source_id);

/* Synchronous measurement and extension transaction. */
DEFINE_MUTEX(bpfima_commit_mutex);
static int bpfima_commit_error;
static bool hardware_anchored;
static bool software_committed;

void __init bpfima_commit_init(void)
{
    mutex_lock(&bpfima_commit_mutex);
    bpfima_commit_error = 0;
    hardware_anchored = false;
    software_committed = false;
    mutex_unlock(&bpfima_commit_mutex);
}

int bpfima_commit_get_error(void)
{
    int ret;

    mutex_lock(&bpfima_commit_mutex);
    ret = bpfima_commit_check_locked();
    mutex_unlock(&bpfima_commit_mutex);
    return ret;
}

bool bpfima_commit_hardware_allowed_locked(void)
{
    lockdep_assert_held(&bpfima_commit_mutex);
    return !software_committed || hardware_anchored;
}

bool bpfima_commit_requires_hardware_locked(void)
{
    lockdep_assert_held(&bpfima_commit_mutex);
    return hardware_anchored;
}

int bpfima_commit_check_locked(void)
{
    lockdep_assert_held(&bpfima_commit_mutex);
    if (!bpfima_commit_error) {
        bool available = bpfima_tpm_available();
        if (hardware_anchored && !available)
            bpfima_commit_error = -ENODEV;
        else if (!bpfima_commit_hardware_allowed_locked() && available)
            bpfima_commit_error = -EIO;
    }
    return bpfima_commit_error;
}

int bpfima_commit_fail_locked(int error)
{
    lockdep_assert_held(&bpfima_commit_mutex);
    if (!bpfima_commit_error)
        bpfima_commit_error = error < 0 ? error : -EIO;
    return bpfima_commit_error;
}

/* Prepare every fallible software operation before publishing an event. */
static int commit_event_locked(struct container_node *container,
                               struct measurement_entry *entry, const u8 *value,
                               const char *source_id, bool deduplicate)
{
    struct merkle_root_entry *history;
    struct hash_entry *hash = NULL;
    u8 old_leaf[MERKLE_HASH_SIZE];
    u8 new_leaf[MERKLE_HASH_SIZE];
    u8 old_root[MERKLE_HASH_SIZE];
    u8 new_root[MERKLE_HASH_SIZE];
    unsigned long flags;
    bool command_started = false;
    int ret;

    lockdep_assert_held(&bpfima_commit_mutex);
    ret = bpfima_commit_check_locked();
    if (ret)
        return ret;
    if (!value || !system_merkle_root.tfm ||
        (container && (!entry || !container->tfm)))
        return -EINVAL;

    if (deduplicate) {
        if (!container)
            return -EINVAL;
        if (hash_exists(entry->digest, container->id))
            return 1;
        hash = bpfima_alloc_hash_entry(entry->digest, container->id);
        if (!hash)
            return -ENOMEM;
    }

    history = bpfima_alloc_history_entry(source_id);
    if (!history) {
        ret = -ENOMEM;
        goto free_hash;
    }

    if (container) {
        spin_lock_irqsave(&container->measurement_lock, flags);
        memcpy(old_leaf, container->leaf_hash, MERKLE_HASH_SIZE);
        spin_unlock_irqrestore(&container->measurement_lock, flags);
        ret = bpfima_extend_hash(container->tfm, old_leaf, entry->digest, new_leaf);
        if (ret)
            goto free_history;
        value = new_leaf;
    }

    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(old_root, system_merkle_root.root_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);
    ret = bpfima_extend_hash(system_merkle_root.tfm, old_root, value, new_root);
    if (ret)
        goto free_history;
    memcpy(history->value, value, MERKLE_HASH_SIZE);

    /* Hardware comes first: all software publication below is infallible. */
    ret = extend_tpm_pcr_with_root(new_root, "merkle_root_update",
                                   bpfima_commit_hardware_allowed_locked(), &command_started);
    if (ret && (command_started || ret != -ENODEV || hardware_anchored)) {
        /* A failed TPM command may have changed the PCR; automatic retry is unsafe. */
        if (command_started || ret != -ENOMEM) {
            ret = bpfima_commit_fail_locked(ret);
            pr_warn("bpfima: TPM commit failed (%d); recover the PCR and reload before further measurements\n", ret);
        }
        goto free_history;
    }
    if (!ret)
        hardware_anchored = true;

    /* Nothing below can fail a software commit. Root readers wait for publication. */
    spin_lock_irqsave(&system_merkle_root.lock, flags);
    if (container) {
        spin_lock(&container->measurement_lock);
        list_add_tail(&entry->list, &container->measurement_list);
        atomic_inc(&container->measurement_count);
        memcpy(container->leaf_hash, new_leaf, MERKLE_HASH_SIZE);
    }
    bpfima_publish_history_entry_locked(history);
    memcpy(system_merkle_root.root_hash, new_root, MERKLE_HASH_SIZE);
    if (container)
        spin_unlock(&container->measurement_lock);
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);

    /* Concurrent duplicate callers remain blocked until this commit completes. */
    if (hash)
        bpfima_publish_hash_entry_locked(hash);
    software_committed = true;
    bpfima_trim_history_locked(source_id);
    ret = 0;
    goto clear_hashes;

free_history:
    if (ret > 0)
        ret = -EIO;
    kfree(history);
free_hash:
    kfree(hash);
clear_hashes:
    memzero_explicit(old_leaf, sizeof(old_leaf));
    memzero_explicit(new_leaf, sizeof(new_leaf));
    memzero_explicit(old_root, sizeof(old_root));
    memzero_explicit(new_root, sizeof(new_root));
    return ret;
}

int bpfima_commit_measurement_locked(struct container_node *container,
                                     struct measurement_entry *entry, bool deduplicate)
{
    if (!container || !entry)
        return -EINVAL;
    return commit_event_locked(container, entry, entry->digest, container->id, deduplicate);
}

int bpfima_commit_root_locked(const u8 *value, const char *source_id)
{
    return commit_event_locked(NULL, NULL, value, source_id, false);
}

int add_container_measurement(struct container_node *container,
                              const char *event_name, const char *event_data,
                              const char *dependencies, const u8 *digest, gfp_t flags)
{
    struct measurement_entry *entry;
    int ret;

    if (!container || !event_name || !digest)
        return -EINVAL;
    if (in_atomic() || irqs_disabled())
        return -EWOULDBLOCK;

    mutex_lock(&bpfima_commit_mutex);
    ret = bpfima_commit_check_locked();
    if (ret)
        goto unlock;
    if (hash_exists(digest, container->id)) {
        ret = 1;
        goto unlock;
    }
    entry = create_measurement_entry(event_name, event_data, dependencies, digest, flags);
    if (!entry) {
        ret = -ENOMEM;
        goto unlock;
    }
    ret = bpfima_commit_measurement_locked(container, entry, true);
    if (ret)
        kfree(entry);
unlock:
    mutex_unlock(&bpfima_commit_mutex);
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

static int trim_merkle_root_history_locked(u32 max_size);

static struct merkle_root_entry *bpfima_alloc_history_entry(const char *source_id)
{
    struct merkle_root_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);

    if (!entry)
        return NULL;
    if (source_id)
        strscpy(entry->source_container_id, source_id, CONTAINER_ID_MAX_LEN);
    return entry;
}

static void bpfima_publish_history_entry_locked(struct merkle_root_entry *entry)
{
    unsigned long flags;

    lockdep_assert_held(&bpfima_commit_mutex);
    spin_lock_irqsave(&merkle_root_history_lock, flags);
    list_add_tail(&entry->list, &merkle_root_history);
    atomic_inc(&merkle_root_history_count);
    spin_unlock_irqrestore(&merkle_root_history_lock, flags);
}

static void bpfima_trim_history_locked(const char *source_id)
{
    struct bpfima_policy_config policy;

    lockdep_assert_held(&bpfima_commit_mutex);
    bpfima_policy_get_config(&policy);
    if (policy.merkle_history_scope == MERKLE_HISTORY_SCOPE_ROOT_ONLY &&
        source_id && source_id[0])
        return;
    if (policy.merkle_history_max_size &&
        get_merkle_root_history_count() > policy.merkle_history_max_size)
        trim_merkle_root_history_locked(policy.merkle_history_max_size);
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
static int trim_merkle_root_history_locked(u32 max_size)
{
    struct merkle_root_entry *entry, *tmp, *aggregate_entry;
    LIST_HEAD(entries_to_delete);
    unsigned long flags;
    u32 current_count, to_delete, deleted_count = 0;
    u8 aggregate_hash[MERKLE_HASH_SIZE];
    u32 aggregated_count = 0;
    int ret;

    lockdep_assert_held(&bpfima_commit_mutex);
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
