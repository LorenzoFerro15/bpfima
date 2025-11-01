#ifndef BPFIMA_COMMON_H
#define BPFIMA_COMMON_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <crypto/sha2.h>

/* Constants */
#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX 255
#define TPM_PCR_INDEX 23
#define HASH_TABLE_BITS 8

/* Container tracking and Merkle tree constants */
#define CONTAINER_ID_MAX_LEN 128
#define MERKLE_HASH_SIZE SHA256_DIGEST_SIZE

/**
 * struct measurement_entry - Represents a single measurement/extension event
 * @list: Linked list node for maintaining measurement list
 * @event_name: Event name/description
 * @event_data: Additional event data
 * @digest: SHA-256 hash of the measurement
 */
struct measurement_entry {
    struct list_head list;
    char event_name[IMA_EVENT_NAME_LEN_MAX + 1];
    char event_data[256];
    u8 digest[MERKLE_HASH_SIZE];
};

/**
 * struct container_node - Represents a container/pod with its measurement list
 * @list: Linked list node for maintaining list of all containers
 * @id: Unique container identifier
 * @measurement_list: List of measurements specific to this container
 * @measurement_lock: Spinlock protecting the measurement list
 * @leaf_hash: Current SHA-256 hash representing this container (Merkle leaf)
 * @measurement_count: Number of measurements in this container's list
 * @securityfs_dir: SecurityFS directory for this container
 * @securityfs_measurements_file: SecurityFS file for container measurements
 */
struct container_node {
    struct list_head list;
    char id[CONTAINER_ID_MAX_LEN];
    struct list_head measurement_list;
    spinlock_t measurement_lock;
    u8 leaf_hash[MERKLE_HASH_SIZE];
    atomic_t measurement_count;
    struct dentry *securityfs_dir;
    struct dentry *securityfs_measurements_file;
};

/**
 * struct merkle_root_entry - Tracks values extended into the Merkle tree root
 * @list: Linked list node
 * @value: Hash value that was added to the Merkle root calculation
 * @source_container_id: ID of the container that triggered this extension
 */
struct merkle_root_entry {
    struct list_head list;
    u8 value[MERKLE_HASH_SIZE];
    char source_container_id[CONTAINER_ID_MAX_LEN];
};

/**
 * struct merkle_tree_root - Non-binary Merkle tree with one leaf per container
 * @root_hash: Current Merkle root hash (virtual PCR value)
 * @lock: Spinlock for thread-safe tree operations
 * @leaf_count: Number of leaf nodes (containers) in the tree
 */
struct merkle_tree_root {
    u8 root_hash[MERKLE_HASH_SIZE];
    spinlock_t lock;
    u32 leaf_count;
};

/* Legacy BPF-IMA structures */
struct bpf_ima_template_entry {
    struct list_head list;
    char event_name[IMA_EVENT_NAME_LEN_MAX + 1];
    char event_data[256];
    u8 digest[IMA_DIGEST_SIZE];
};

struct hash_entry {
    struct hlist_node hash_node;
    u8 sha256_hash[SHA256_DIGEST_SIZE];
};

/* Hash utility functions */
int calculate_sha256_hash(const void *data, size_t len, u8 *digest);
bool hash_exists(const u8 *hash_value);
int add_hash_to_table(const u8 *hash_value, bool can_sleep);
void cleanup_hash_table(void);

/* TPM operations */
int extend_tpm_pcr(const u8 *hash_value, const char *event_name);
int extend_tpm_pcr_with_root(const u8 *root_hash, const char *event_name);

#endif /* BPFIMA_COMMON_H */
