#ifndef BPFIMA_COMMON_H
#define BPFIMA_COMMON_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <crypto/sha2.h>
#include <linux/ima.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/tpm.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/hashtable.h>

/* Constants */
#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX 255
#define TPM_PCR_INDEX 23
#define HASH_TABLE_BITS 8

/* Container tracking and Merkle tree constants */
#define CONTAINER_ID_MAX_LEN 128
#define MERKLE_HASH_SIZE SHA256_DIGEST_SIZE

/* TPM serialization mutex - defined in tpm_ops.c */
extern struct mutex bpfima_tpm_mutex;

/**
 * struct measurement_entry - Represents a single measurement/extension event
 * @list: Linked list node for maintaining measurement list
 * @event_name: Event name/description
 * @event_data: Additional event data
 * @dependencies: Dependencies string (e.g., previous measurement hash)
 * @digest: SHA-256 hash of the measurement
 */
struct measurement_entry
{
    struct list_head list;
    char event_name[IMA_EVENT_NAME_LEN_MAX + 1];
    char event_data[256];
    char dependencies[256];
    u8 digest[MERKLE_HASH_SIZE];
};

/**
 * struct container_node - Represents a container/pod with its measurement list
 * @list: Linked list node for maintaining list of all containers
 * @id: Unique container identifier
 * @measurement_list: List of measurements specific to this container
 * @measurement_lock: Spinlock protecting the measurement list data structure
 * @measurement_mutex: Mutex for serializing measurement additions including Merkle updates
 * @leaf_hash: Current SHA-256 hash representing this container (Merkle leaf)
 * @measurement_count: Number of measurements in this container's list
 * @securityfs_dir: SecurityFS directory for this container
 * @securityfs_measurements_file: SecurityFS file for container measurements
 * @securityfs_policy_file: SecurityFS file for policy configuration
 * @securityfs_policy_changes_file: SecurityFS file for policy change history
 */
struct container_node
{
    struct list_head list;
    char id[CONTAINER_ID_MAX_LEN];
    struct list_head measurement_list;
    spinlock_t measurement_lock;
    struct crypto_shash *tfm;
    u8 leaf_hash[MERKLE_HASH_SIZE];
    atomic_t measurement_count;
    struct dentry *securityfs_dir;
    struct dentry *securityfs_measurements_file;
    struct dentry *securityfs_policy_file;
    struct dentry *securityfs_policy_changes_file;
};

/**
 * struct merkle_root_entry - Tracks values extended into the Merkle tree root
 * @list: Linked list node
 * @value: Hash value that was added to the Merkle root calculation
 * @source_container_id: ID of the container that triggered this extension
 * @is_aggregate: True if this entry represents an aggregate of multiple deleted entries
 * @aggregated_count: Number of entries aggregated (0 if not an aggregate)
 */
struct merkle_root_entry
{
    struct list_head list;
    u8 value[MERKLE_HASH_SIZE];
    char source_container_id[CONTAINER_ID_MAX_LEN];
    bool is_aggregate;
    u32 aggregated_count;
};

/**
 * struct merkle_tree_root - Non-binary Merkle tree with one leaf per container
 * @root_hash: Current Merkle root hash (virtual PCR value)
 * @lock: Spinlock for thread-safe tree operations
 * @leaf_count: Number of leaf nodes (containers) in the tree
 * @tfm: Pre-allocated SHA256 transform for atomic operations
 */
struct merkle_tree_root
{
    u8 root_hash[MERKLE_HASH_SIZE];
    spinlock_t lock;
    u32 leaf_count;
    struct crypto_shash *tfm;
};

struct hash_entry
{
    struct hlist_node hash_node;
    u8 sha256_hash[SHA256_DIGEST_SIZE];
    char namespace_id[CONTAINER_ID_MAX_LEN];
};

int calculate_sha256_hash(const void *data, size_t len, u8 *digest);
bool hash_exists(const u8 *hash_value, const char *namespace_id);
int add_hash_to_table(const u8 *hash_value, const char *namespace_id, bool can_sleep);
void cleanup_hash_table(void);
int bpfima_hash_init(void);
void bpfima_hash_cleanup(void);

int extend_tpm_pcr(const u8 *hash_value, const char *event_name);
int extend_tpm_pcr_with_root(const u8 *root_hash, const char *event_name);



int create_container_securityfs(struct container_node *container);
void remove_container_securityfs(struct container_node *container);

/**
 * bpfima_extend_hash - Extend a hash value with new data using SHA256
 * @tfm: Crypto transform to use (must be allocated by caller)
 * @old_hash: Current hash value (must be SHA256_DIGEST_SIZE)
 * @new_data: Data to extend with (must be SHA256_DIGEST_SIZE checks context)
 * @out_hash: Buffer to store the result
 *
 * Computes: out_hash = SHA256(old_hash || new_data)
 * Handles shash descriptor allocation internally (atomic/kernel based on context).
 *
 * Returns: 0 on success, negative error code on failure.
 */
int bpfima_extend_hash(struct crypto_shash *tfm, const u8 *old_hash, const u8 *new_data, u8 *out_hash);

#endif /* BPFIMA_COMMON_H */
