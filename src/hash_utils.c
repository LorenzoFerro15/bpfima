/*
 * Hash Utility Functions for BPF-IMA
 * 
 * Common hash calculation and tracking functions used across
 * the BPF-IMA module for SHA256 operations and duplicate detection.
 */

#include "bpfima_common.h"

#define HASH_TABLE_BITS 8

/* Global hash table for duplicate detection */
static DEFINE_HASHTABLE(sha256_hash_table, HASH_TABLE_BITS);
static DEFINE_SPINLOCK(hash_table_lock);

/**
 * calculate_sha256_hash - Compute SHA256 hash digest of input data
 * @data: Input data buffer to hash
 * @len: Length of input data in bytes
 * @digest: Output buffer to store SHA256 digest (must be SHA256_DIGEST_SIZE bytes)
 *
 * Allocates crypto transform and descriptor to compute SHA256 hash using kernel
 * crypto API. The function handles all memory allocation/deallocation internally.
 *
 * Returns: 0 on success, negative error code on failure
 */
int calculate_sha256_hash(const void *data, size_t len, u8 *digest)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, data, len, digest);

    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/**
 * hash_exists - Check if a SHA256 hash already exists in the hash table
 * @hash_value: SHA256 digest to search for (must be SHA256_DIGEST_SIZE bytes)
 *
 * Searches the hash table to determine if a measurement with the given SHA256 hash
 * has already been recorded. Uses a simple hash function based on the first 4 bytes
 * of the SHA256 digest. The function is thread-safe using spinlock protection.
 *
 * Returns: true if hash exists, false if not found
 */
bool hash_exists(const u8 *hash_value)
{
    struct hash_entry *entry;
    u32 hash_key;
    unsigned long flags;
    bool found = false;
    
    hash_key = *(u32*)hash_value;

    spin_lock_irqsave(&hash_table_lock, flags);
    
    hash_for_each_possible(sha256_hash_table, entry, hash_node, hash_key) {
        if (memcmp(entry->sha256_hash, hash_value, SHA256_DIGEST_SIZE) == 0) {
            found = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&hash_table_lock, flags);
    
    return found;
}

/**
 * add_hash_to_table - Add a new SHA256 hash to the hash table
 * @hash_value: SHA256 digest to add (must be SHA256_DIGEST_SIZE bytes)
 * @can_sleep: Whether the current context allows sleeping for memory allocation
 *
 * Adds a new hash entry to the hash table to track that this measurement has been
 * recorded. Uses appropriate memory allocation flags based on the calling context.
 * The function is thread-safe using spinlock protection.
 *
 * Returns: 0 on success, negative error code on failure
 */
int add_hash_to_table(const u8 *hash_value, bool can_sleep)
{
    struct hash_entry *new_entry;
    u32 hash_key;
    unsigned long flags;
    
    new_entry = kzalloc(sizeof(*new_entry), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!new_entry)
        return -ENOMEM;
    
    memcpy(new_entry->sha256_hash, hash_value, SHA256_DIGEST_SIZE);
    
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
