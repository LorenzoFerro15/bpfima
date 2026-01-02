/*
 * Hash Utility Functions for BPF-IMA
 * 
 * Common hash calculation and tracking functions used across
 * the BPF-IMA module for SHA256 operations and duplicate detection.
 * 
 * Refactored to use per-CPU crypto descriptors to ensure safety
 * atomic contexts and improve performance by avoiding repeated allocations.
 */

#include "bpfima_common.h"
#include <linux/percpu.h>
#include <crypto/hash.h>

#define HASH_TABLE_BITS 8

/* Global hash table for duplicate detection */
static DEFINE_HASHTABLE(sha256_hash_table, HASH_TABLE_BITS);
static DEFINE_SPINLOCK(hash_table_lock);

/* Per-CPU crypto transform and descriptor */
/* We only need one TFM globally, but descriptors must be per-CPU */
static struct crypto_shash *sha256_tfm;
struct bpfima_shash_desc {
    struct shash_desc desc;
    /* Reserve space for SHA256 context state */
    char ctx[128]; // SHA256 context is roughly 100-112 bytes usually
};

static DEFINE_PER_CPU(struct bpfima_shash_desc, percpu_shash_desc);


/**
 * bpfima_hash_init - Initialize the hash subsystem
 * 
 * Allocates the global SHA256 transform and confirms per-CPU
 * descriptors are ready for use.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_hash_init(void)
{
    sha256_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256_tfm)) {
        pr_err("bpfima: Failed to allocate SHA256 transform: %ld\n", PTR_ERR(sha256_tfm));
        return PTR_ERR(sha256_tfm);
    }
    
    if (crypto_shash_descsize(sha256_tfm) > sizeof(((struct bpfima_shash_desc *)0)->ctx)) {
        pr_err("bpfima: SHA256 desc size too large for static allocation\n");
        crypto_free_shash(sha256_tfm);
        return -EINVAL;
    }

    pr_info("bpfima: Hash subsystem initialized (per-CPU buffers)\n");
    return 0;
}

/**
 * bpfima_hash_cleanup - Cleanup the hash subsystem
 * 
 * Frees the global SHA256 transform.
 */
void bpfima_hash_cleanup(void)
{
    if (sha256_tfm) {
        crypto_free_shash(sha256_tfm);
        sha256_tfm = NULL;
    }
    cleanup_hash_table();
    pr_info("bpfima: Hash subsystem cleaned up\n");
}


/**
 * calculate_sha256_hash - Compute SHA256 hash digest of input data
 * @data: Input data buffer to hash
 * @len: Length of input data in bytes
 * @digest: Output buffer to store SHA256 digest (must be SHA256_DIGEST_SIZE bytes)
 *
 * Uses pre-allocated per-CPU crypto descriptors to ensure safety in atomic
 * contexts (no memory allocation). Disables preemption to ensure exclusive
 * access to the per-CPU buffer.
 *
 * Returns: 0 on success, negative error code on failure
 */
int calculate_sha256_hash(const void *data, size_t len, u8 *digest)
{
    struct bpfima_shash_desc *b_desc;
    struct shash_desc *desc;
    int ret;

    if (!sha256_tfm)
        return -EINVAL;

    /* Get pointer to per-CPU descriptor and disable preemption */
    b_desc = get_cpu_ptr(&percpu_shash_desc);
    desc = &b_desc->desc;
    
    desc->tfm = sha256_tfm;
    
    ret = crypto_shash_digest(desc, data, len, digest);

    /* Re-enable preemption */
    put_cpu_ptr(&percpu_shash_desc);

    return ret;
}

/**
 * hash_exists - Check if a SHA256 hash already exists for a specific namespace
 * @hash_value: SHA256 digest to search for (must be SHA256_DIGEST_SIZE bytes)
 * @namespace_id: Namespace identifier to check (NULL for host/global namespace)
 *
 * Searches the hash table to determine if a measurement with the given SHA256 hash
 * has already been recorded for the specified namespace. A file accessed by different
 * namespaces will have separate entries. Uses a simple hash function based on the 
 * first 4 bytes of the SHA256 digest. The function is thread-safe using spinlock protection.
 *
 * Returns: true if hash exists for this namespace, false if not found
 */
bool hash_exists(const u8 *hash_value, const char *namespace_id)
{
    struct hash_entry *entry;
    u32 hash_key;
    unsigned long flags;
    bool found = false;
    const char *ns_to_check = namespace_id ? namespace_id : "";
    
    hash_key = *(u32*)hash_value;

    spin_lock_irqsave(&hash_table_lock, flags);
    
    hash_for_each_possible(sha256_hash_table, entry, hash_node, hash_key) {
        /* Match both hash AND namespace */
        if (memcmp(entry->sha256_hash, hash_value, SHA256_DIGEST_SIZE) == 0 &&
            strcmp(entry->namespace_id, ns_to_check) == 0) {
            found = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&hash_table_lock, flags);
    
    return found;
}

/**
 * add_hash_to_table - Add a new SHA256 hash to the hash table for a namespace
 * @hash_value: SHA256 digest to add (must be SHA256_DIGEST_SIZE bytes)
 * @namespace_id: Namespace identifier (NULL for host/global namespace)
 * @can_sleep: Whether the current context allows sleeping for memory allocation
 *
 * Adds a new hash entry to the hash table to track that this file has been
 * accessed by the specified namespace. The same file accessed by different
 * namespaces will have separate entries. If the same namespace re-accesses
 * the file, it should be checked with hash_exists() first to avoid duplicates.
 * Uses appropriate memory allocation flags based on the calling context.
 * The function is thread-safe using spinlock protection.
 *
 * Returns: 0 on success, negative error code on failure
 */
int add_hash_to_table(const u8 *hash_value, const char *namespace_id, bool can_sleep)
{
    struct hash_entry *new_entry;
    u32 hash_key;
    unsigned long flags;
    const char *ns_to_store = namespace_id ? namespace_id : "";
    
    new_entry = kzalloc(sizeof(*new_entry), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!new_entry)
        return -ENOMEM;
    
    memcpy(new_entry->sha256_hash, hash_value, SHA256_DIGEST_SIZE);
    strscpy(new_entry->namespace_id, ns_to_store, CONTAINER_ID_MAX_LEN);
    
    /* Use first 4 bytes of SHA256 as hash key */
    hash_key = *(u32*)hash_value;
    
    spin_lock_irqsave(&hash_table_lock, flags);
    hash_add(sha256_hash_table, &new_entry->hash_node, hash_key);
    spin_unlock_irqrestore(&hash_table_lock, flags);
    
    return 0;
}

/**
 * cleanup_hash_table - Clean up all entries in the SHA256 hash table
 *
 * Iterates through all buckets of the hash table and frees all hash entries.
 * This function should be called during module cleanup to prevent memory leaks.
 * Uses irqsave locking to ensure safe cleanup in any context.
 */
void cleanup_hash_table(void)
{
    struct hash_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;
    int count = 0;

    spin_lock_irqsave(&hash_table_lock, flags);
    
    hash_for_each_safe(sha256_hash_table, bkt, tmp, entry, hash_node) {
        hash_del(&entry->hash_node);
        kfree(entry);
        count++;
    }
    
    spin_unlock_irqrestore(&hash_table_lock, flags);
    
    pr_info("bpfima: Hash table cleaned up. Freed %d hash entries\n", count);
}

/**
 * bpfima_extend_hash - Extend a hash value with new data using SHA256
 * @tfm: Crypto transform to use
 * @old_hash: Current hash value
 * @new_data: Data to extend with
 * @out_hash: Buffer to store the result
 *
 * Computes: out_hash = SHA256(old_hash || new_data)
 *
 * This function is used where explicit TFM is passed (e.g. from container nodes)
 * so it still uses the existing allocation pattern unless we also migrate
 * container nodes to use per-CPU tfm. For now, we leave it as is to avoid
 * breaking container logic, but mark it safe if tfm is valid.
 */
int bpfima_extend_hash(struct crypto_shash *tfm, const u8 *old_hash, const u8 *new_data, u8 *out_hash)
{
    struct shash_desc *desc;
    int ret;
    
    if (!tfm || !old_hash || !new_data || !out_hash)
        return -EINVAL;

    /* Always use GFP_ATOMIC to be safe in spinlock contexts (common for extend ops) */
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
    if (!desc)
        return -ENOMEM;

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret < 0)
        goto out;

    ret = crypto_shash_update(desc, old_hash, SHA256_DIGEST_SIZE);
    if (ret < 0)
        goto out;

    ret = crypto_shash_update(desc, new_data, SHA256_DIGEST_SIZE);
    if (ret < 0)
        goto out;

    ret = crypto_shash_final(desc, out_hash);

out:
    if (desc) {
        memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
        kfree(desc);
    }
    return ret;
}
