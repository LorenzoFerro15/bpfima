#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ima.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <linux/tpm.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <crypto/sha2.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/hashtable.h>

#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_kfuncs.h"

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
 *
 * This structure tracks individual measurements that are extended into
 * either the host measurement list or a container-specific measurement list.
 */

/**
 * struct container_node - Represents a container/pod with its measurement list
 * @list: Linked list node for maintaining list of all containers
 * @id: Unique container identifier (e.g., container ID, pod name)
 * @measurement_list: List of measurements specific to this container
 * @measurement_lock: Spinlock protecting the measurement list
 * @leaf_hash: Current SHA-256 hash representing this container (Merkle leaf)
 * @measurement_count: Number of measurements in this container's list
 * @securityfs_dir: SecurityFS directory for this container
 * @securityfs_measurements_file: SecurityFS file for container measurements
 *
 * Each container has its own measurement list that tracks all events
 * related to that specific container. The leaf_hash is used as the
 * container's leaf value in the Merkle tree root calculation.
 */

/**
 * struct merkle_root_entry - Tracks values extended into the Merkle tree root
 * @list: Linked list node
 * @value: Hash value that was added to the Merkle root calculation
 * @source_container_id: ID of the container that triggered this extension
 *                        (empty string for host events)
 *
 * This list keeps track of all values that have been incorporated into
 * the Merkle tree root. Each time a container's leaf hash changes or
 * a host event occurs, the new value is recorded here before being
 * added to the Merkle root calculation.
 */
/**
 * struct merkle_tree_root - Non-binary Merkle tree with one leaf per container
 * @root_hash: Current Merkle root hash (virtual PCR value)
 * @lock: Spinlock for thread-safe tree operations
 * @leaf_count: Number of leaf nodes (containers) in the tree
 *
 * The Merkle tree root is calculated by hashing together all container
 * leaf hashes. This represents the virtual PCR value that reflects the
 * entire system state. The root is recalculated whenever any container's
 * leaf hash changes.
 */

static LIST_HEAD(bpf_measurement_list);
static DEFINE_SPINLOCK(measurement_list_lock);
static atomic_t measurement_count = ATOMIC_INIT(0);

/* Container tracking and Merkle tree globals */
LIST_HEAD(container_list);            /* List of all container_node structures */
DEFINE_SPINLOCK(container_list_lock); /* Protects container_list */

static LIST_HEAD(host_measurement_list);     /* Host-level measurement list */
static DEFINE_SPINLOCK(host_measurement_lock); /* Protects host measurement list */

static LIST_HEAD(merkle_root_history);       /* List of merkle_root_entry structures */
static DEFINE_SPINLOCK(merkle_root_history_lock); /* Protects merkle root history */

struct merkle_tree_root system_merkle_root; /* The Merkle tree root (virtual PCR) */
atomic_t container_count = ATOMIC_INIT(0);

EXPORT_SYMBOL(container_list);
EXPORT_SYMBOL(container_list_lock);
EXPORT_SYMBOL(system_merkle_root);
EXPORT_SYMBOL(container_count);

/* SecurityFS interface */
static struct dentry *bpfima_dir = NULL;
static struct dentry *measurements_file = NULL;
static struct dentry *status_file = NULL;
static char bpfima_dir_name[32] = "bpfima";

/* SecurityFS interface for container tracking and Merkle tree */
static struct dentry *containers_dir = NULL;           /* /sys/kernel/security/bpfima/containers/ */
static struct dentry *host_measurements_file = NULL;   /* Host measurement list */
static struct dentry *merkle_root_file = NULL;         /* Current Merkle root hash */
static struct dentry *merkle_root_history_file = NULL; /* History of root extensions */
static struct dentry *container_list_file = NULL;      /* List of all containers */

__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len);
__bpf_kfunc int bpf_ima_get_measurement_count(void);
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size);
__bpf_kfunc int bpf_tpm_is_available(void);
__bpf_kfunc int bpf_ima_print_measurement_list(void);
__bpf_kfunc int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size);

/* Container tracking kfunc declarations */
__bpf_kfunc int bpf_container_create_or_get(const char *container_id);
__bpf_kfunc int bpf_container_add_measurement(const char *container_id, const char *event_name, const char *event_data, const u8 *digest, u32 digest_size);
__bpf_kfunc int bpf_host_add_measurement(const char *event_name, const char *event_data, const u8 *digest, u32 digest_size);
__bpf_kfunc int bpf_get_merkle_root(u8 *root_hash, u32 hash_size);

/* Task 6: Enhanced query kfuncs for bidirectional communication */
__bpf_kfunc int bpf_container_get_count(void);
__bpf_kfunc int bpf_container_get_measurement_count(const char *container_id);
__bpf_kfunc int bpf_container_exists(const char *container_id);
__bpf_kfunc int bpf_get_container_leaf_hash(const char *container_id, u8 *leaf_hash, u32 hash_size);

/*
 * Forward declarations for Merkle tree helper functions
 * (needed by kfuncs defined before the actual implementations)
 */

/* External function declarations from modular components */
int calculate_sha256_hash(const void *data, size_t len, u8 *digest);
bool hash_exists(const u8 *hash_value);
int add_hash_to_table(const u8 *hash_value, bool can_sleep);
void cleanup_hash_table(void);
int extend_tpm_pcr(const u8 *hash_value, const char *event_name);

__bpf_kfunc_start_defs();

/*
 * process_measurement - Core function to process measurement data with TPM integration
 * @event_name: Name/identifier of the event being measured
 * @data: Event data payload to be measured
 * @data_len: Length of event data in bytes
 *
 * This function performs the complete measurement workflow:
 * 1. Computes SHA256 hash of the input data
 * 2. Checks if this hash has already been recorded (duplicate detection)
 * 3. If not a duplicate, creates a measurement entry and adds it to the global list
 * 4. Adds the hash to the tracking table and attempts TPM PCR extension
 * 5. Handles atomic context by deferring TPM operations
 * 6. Uses appropriate memory allocation flags based on context
 *
 * The function maintains atomicity between list operations and TPM operations
 * using a spinlock, but allows interrupts to prevent scheduling while atomic bugs.
 *
 * Returns: Total number of measurements recorded, negative error code on failure,
 *         or existing count if duplicate detected
 */
static int process_measurement(const char *event_name, const char *data, u32 data_len)
{
    struct bpf_ima_template_entry *entry;
    int ret = 0;
    u8 hash_value[SHA256_DIGEST_SIZE];
    bool can_sleep = !in_atomic() && !irqs_disabled();

    ret = calculate_sha256_hash(data, data_len, hash_value);
    if (ret) {
        printk(KERN_ERR "Failed to calculate SHA256 hash: %d\n", ret);
        return ret;
    }

    if (hash_exists(hash_value)) {
        printk(KERN_INFO "IMA_DUPLICATE: event=%s digest=%*ph (skipped)\n", 
               event_name, IMA_DIGEST_SIZE, hash_value);
        return atomic_read(&measurement_count);
    }

    entry = kzalloc(sizeof(*entry), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;

    strncpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX);
    entry->event_name[IMA_EVENT_NAME_LEN_MAX] = '\0';
    
    strncpy(entry->event_data, data, min_t(u32, data_len, sizeof(entry->event_data) - 1));
    entry->event_data[sizeof(entry->event_data) - 1] = '\0';
    
    memcpy(entry->digest, hash_value, IMA_DIGEST_SIZE);

    ret = add_hash_to_table(hash_value, can_sleep);
    if (ret) {
        printk(KERN_ERR "Failed to add hash to tracking table: %d\n", ret);
        kfree(entry);
        return ret;
    }

    spin_lock(&measurement_list_lock);

    list_add_tail(&entry->list, &bpf_measurement_list);
    atomic_inc(&measurement_count);
    
    if (!can_sleep) {
        printk(KERN_INFO "Called from atomic context, TPM extension deferred for event: %s\n", event_name);
        spin_unlock(&measurement_list_lock);
    } else {
        /* release lock before performing TPM extension which may sleep */
        spin_unlock(&measurement_list_lock);
        extend_tpm_pcr(hash_value, event_name);
    }

    printk(KERN_INFO "IMA_MEASUREMENT: event=%s count=%d digest=%*ph\n", 
           event_name, atomic_read(&measurement_count), IMA_DIGEST_SIZE, hash_value);
    
    return atomic_read(&measurement_count);
}

/*
 * bpf_ima_extend_measurement - BPF kfunc to add measurement to list and extend TPM PCR
 * @event_name: Name/identifier of the event being measured (must not be null or empty)
 * @data: Event data payload to be measured (must not be null or empty) 
 * @data_len: Length of event data in bytes (must be > 0)
 *
 * This is the main entry point for BPF programs to record integrity measurements.
 * Performs comprehensive parameter validation before delegating to process_measurement.
 * Validates that event_name and data are not null, empty, or zero-length.
 * 
 * Can be called from both atomic and non-atomic contexts. TPM operations will be
 * deferred if called from atomic context to prevent scheduling while atomic bugs.
 *
 * Returns: Total number of measurements recorded, negative error code on validation failure
 */
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len)
{
    printk(KERN_INFO "bpfima: event_name='%s' namespace_id='%s' dependencies='%s' additional_data_len=%u", 
        event_name ? event_name : "(null)", 
        namespace_id ? namespace_id : "(null)", 
        dependencies ? dependencies : "(null)", 
        additional_data_len);
    if (additional_data && additional_data_len > 0) {
        char buf[129];
        size_t print_len = additional_data_len < 128 ? additional_data_len : 128;
        memcpy(buf, additional_data, print_len);
        buf[print_len] = '\0';
        printk(KERN_INFO "bpfima: additional_data='%s'", buf);
    }
    size_t total_len = 0;
    char *concat_data = NULL;
    size_t offset = 0;
    int ret = -1;
    char separator = '|';

    if (!event_name && !namespace_id && !dependencies && !additional_data) {
        printk(KERN_ERR "bpfima: All parameters are null\n");
        return -EINVAL;
    }
    if (event_name && strlen(event_name) == 0) {
        printk(KERN_ERR "bpfima: Empty event_name not allowed\n");
        return -EINVAL;
    }
    if (event_name)
        total_len += strlen(event_name);
    if (namespace_id)
        total_len += strlen(namespace_id);
    if (dependencies)
        total_len += strlen(dependencies);
    if (additional_data && additional_data_len > 0)
        total_len += additional_data_len;
    if (total_len == 0) {
        printk(KERN_ERR "bpfima: No valid data to concatenate\n");
        return -EINVAL;
    }
    concat_data = kmalloc(total_len, GFP_KERNEL);
    if (!concat_data) {
        printk(KERN_ERR "bpfima: kmalloc failed\n");
        return -ENOMEM;
    }

    if (namespace_id) {
        size_t len = strlen(namespace_id);
        memcpy(concat_data + offset, namespace_id, len);
        offset += len;
        memcpy(concat_data + offset, &separator, 1);
        offset += 1;
    }
    if (dependencies) {
        size_t len = strlen(dependencies);
        memcpy(concat_data + offset, dependencies, len);
        offset += len;
        memcpy(concat_data + offset, &separator, 1);
        offset += 1;
    }
    if (additional_data && additional_data_len > 0) {
        memcpy(concat_data + offset, additional_data, additional_data_len);
        offset += additional_data_len;
        memcpy(concat_data + offset, &separator, 1);
        offset += 1;
    }
    ret = process_measurement(event_name ? event_name : "", concat_data, total_len);
    kfree(concat_data);
    return ret;
}

/*
 * bpf_ima_get_measurement_count - BPF kfunc to get total number of recorded measurements
 *
 * Returns the current count of measurements stored in the global measurement list.
 * This is an atomic operation that reads the measurement counter without locking.
 * Safe to call from any context including atomic contexts.
 *
 * Returns: Current number of measurements as integer
 */
__bpf_kfunc int bpf_ima_get_measurement_count(void)
{
    return atomic_read(&measurement_count);
}

/*
 * bpf_ima_get_pcr_value - BPF kfunc to retrieve TPM PCR value or simulation
 * @pcr_buf: Output buffer to store PCR value string (minimum 80 bytes)
 * @buf_size: Size of output buffer in bytes
 *
 * Attempts to read the actual TPM PCR value if available and not in atomic context.
 * If TPM is unavailable or called from atomic context, returns a simulation string.
 * The function handles atomic context detection to prevent scheduling while atomic bugs.
 *
 * Output format:
 * - Real TPM: "PCR23_REAL:abc123def456..."
 * - Simulation: "PCR23_MEASUREMENTS_N_HASH_SIMULATION"
 * - Atomic context: "PCR23_MEASUREMENTS_N_ATOMIC_CONTEXT"
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1]; 
    int ret;
    bool can_sleep = !in_atomic() && !irqs_disabled();
    
    if (!pcr_buf) {
        printk(KERN_ERR "bpfima: pcr_buf is null\n");
        return -EINVAL;
    }
    
    if (buf_size < 80) {
        printk(KERN_ERR "bpfima: buf_size too small: %u (minimum 80)\n", buf_size);
        return -EINVAL;
    }
    
    if (!can_sleep) {
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_ATOMIC_CONTEXT", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_INFO "Called from atomic context, using simulation\n");
        return 0;
    }
    
    chip = tpm_default_chip();
    if (!chip) {
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_INFO "TPM not available, using simulation\n");
        return 0;
    }
    
    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;
    
    ret = tpm_pcr_read(chip, TPM_PCR_INDEX, digest);
    if (ret < 0) {
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_WARNING "TPM PCR read failed (%d), using simulation\n", ret);
        tpm_put_ops(chip);
        return ret;
    }
    
    snprintf(pcr_buf, buf_size, "PCR%d_REAL:", TPM_PCR_INDEX);
    for (int i = 0; i < SHA256_DIGEST_SIZE && strlen(pcr_buf) < buf_size - 3; i++) {
        snprintf(pcr_buf + strlen(pcr_buf), buf_size - strlen(pcr_buf), 
                 "%02x", digest[0].digest[i]);
    }
    
    tpm_put_ops(chip);
    return 0;
}

/*
 * bpf_tpm_is_available - BPF kfunc to check TPM hardware availability
 *
 * Attempts to acquire the default TPM chip to test if TPM hardware is available
 * and accessible. This is a lightweight check that doesn't perform any operations
 * on the TPM, just verifies that the chip can be obtained.
 *
 * Safe to call from any context as it only performs chip acquisition/release.
 *
 * Returns: 1 if TPM is available, 0 if not available
 */
__bpf_kfunc int bpf_tpm_is_available(void)
{
    struct tpm_chip *chip;
    
    chip = tpm_default_chip();
    if (!chip)
        return 0; 
        
    tpm_put_ops(chip);
    return 1; 
}

/*
 * bpf_ima_print_measurement_list - BPF kfunc to print all measurements in structured format
 *
 * Outputs a formatted list of all recorded measurements to kernel log (dmesg).
 * Uses interrupt-disabling spinlock to safely traverse the measurement list.
 * Each measurement entry shows event name, truncated data (50 chars max), and full digest.
 *
 * Output format:
 * === BPF-IMA Measurement List ===
 * Total measurements: N
 * PCR Index: 23
 * ----------------------------------------
 * [1] Event: event_name
 *     Data: event_data...
 *     Digest: abc123def456...
 *     --------
 * === End of Measurement List ===
 *
 * Safe to call from any context. Uses irqsave locking for list traversal.
 *
 * Returns: Total number of measurements printed
 */
__bpf_kfunc int bpf_ima_print_measurement_list(void)
{
    struct bpf_ima_template_entry *entry;
    int count = 0;
    unsigned long flags;
    
    printk(KERN_INFO "=== BPF-IMA Measurement List ===");
    printk(KERN_INFO "Total measurements: %d", atomic_read(&measurement_count));
    printk(KERN_INFO "PCR Index: %d", TPM_PCR_INDEX);
    printk(KERN_INFO "----------------------------------------");
    
    spin_lock_irqsave(&measurement_list_lock, flags);
    
    if (list_empty(&bpf_measurement_list)) {
        printk(KERN_INFO "No measurements recorded.");
    } else {
        list_for_each_entry(entry, &bpf_measurement_list, list) {
            count++;
            printk(KERN_INFO "[%d] Event: %s", count, entry->event_name);
            printk(KERN_INFO "    Data: %.50s%s", entry->event_data, 
                   strlen(entry->event_data) > 50 ? "..." : "");
            printk(KERN_INFO "    Digest: %*ph", IMA_DIGEST_SIZE, entry->digest);
            printk(KERN_INFO "    --------");
        }
    }
    
    spin_unlock_irqrestore(&measurement_list_lock, flags);
    
    printk(KERN_INFO "=== End of Measurement List ===");
    
    return atomic_read(&measurement_count);
}
/*
 * bpf_ima_file_hash_simple - Simple file hash using scalar file representation
 * @file_scalar: File pointer cast to u64 scalar (to bypass eBPF verifier)
 * @digest: Output buffer to store hash (must be 32 bytes)
 * @digest_size: Size of digest buffer in bytes (must be 32)
 *
 * This function accepts a file pointer cast to scalar from eBPF to bypass
 * verifier restrictions, then casts it back to use with ima_file_hash.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size)
{
    int ret;
    struct file *filep;
    char *filename = NULL;
    char *path_buf = NULL;
    bool can_sleep = !in_atomic() && !irqs_disabled();

    printk(KERN_DEBUG "bpfima: Simple IMA file hash called, file_scalar=%llx, digest=%p, size=%u\n", 
           file_scalar, digest, digest_size);

    if (!file_scalar || !digest || digest_size != 32) {
        printk(KERN_ERR "bpfima: Invalid parameters for IMA file hashing\n");
        return -EINVAL;
    }

    /* Interpret the incoming scalar as a direct pointer to struct file */
    filep = (struct file *)(uintptr_t)file_scalar;

    if (IS_ERR_OR_NULL(filep)) {
        printk(KERN_ERR "bpfima: File pointer appears invalid (filep=%p)\n", filep);
        return -EINVAL;
    }

    path_buf = kzalloc(PATH_MAX, can_sleep ? GFP_KERNEL : GFP_ATOMIC);

    if (path_buf) {
        filename = d_path(&filep->f_path, path_buf, PATH_MAX);
        if (!IS_ERR(filename)) {
            printk(KERN_INFO "bpfima: Hashing file: %s\n", filename);
        } else {
            printk(KERN_DEBUG "bpfima: Could not get full path, error: %ld\n", PTR_ERR(filename));
            if (filep->f_path.dentry && filep->f_path.dentry->d_name.name) {
                printk(KERN_INFO "bpfima: Hashing file (name only): %s\n", 
                       filep->f_path.dentry->d_name.name);
            }
        }
        kfree(path_buf);
    }

    ret = ima_file_hash(filep, digest, digest_size);
    if (ret < 0) {
        printk(KERN_ERR "bpfima: IMA file hash failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "bpfima: Successfully computed IMA file hash\n");
    return 0;
}

/*
 * Container tracking kfuncs - callable from eBPF programs
 */
/* ===== Task 6: Enhanced Query kfuncs for Bidirectional Communication ===== */

/**
 * bpf_container_get_count - Get the total number of tracked containers
 *
 * Returns: Number of containers currently being tracked
 */
__bpf_kfunc int bpf_container_get_count(void)
{
    return atomic_read(&container_count);
}

/**
 * bpf_container_get_measurement_count - Get measurement count for a container
 * @container_id: Container identifier
 *
 * Returns: Number of measurements in the container, or negative error code
 */
__bpf_kfunc int bpf_container_get_measurement_count(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;
    int count;
    
    if (!container_id || container_id[0] == '\0')
        return -EINVAL;
    
    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    if (!container) {
        spin_unlock_irqrestore(&container_list_lock, flags);
        return -ENOENT;
    }
    count = atomic_read(&container->measurement_count);
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    return count;
}

/**
 * bpf_container_exists - Check if a container is being tracked
 * @container_id: Container identifier
 *
 * Returns: 1 if container exists, 0 if not, negative error code on failure
 */
__bpf_kfunc int bpf_container_exists(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;
    
    if (!container_id || container_id[0] == '\0')
        return -EINVAL;
    
    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    return container ? 1 : 0;
}

/**
 * bpf_get_container_leaf_hash - Get the Merkle leaf hash for a container
 * @container_id: Container identifier
 * @leaf_hash: Buffer to store the leaf hash (must be MERKLE_HASH_SIZE bytes)
 * @hash_size: Size of the buffer (must be MERKLE_HASH_SIZE)
 *
 * Retrieves the current leaf hash for the specified container.
 * The leaf hash represents the current state of all measurements in the container.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_get_container_leaf_hash(const char *container_id, u8 *leaf_hash, u32 hash_size)
{
    struct container_node *container;
    unsigned long flags;
    
    if (!container_id || !leaf_hash)
        return -EINVAL;
    
    if (hash_size != MERKLE_HASH_SIZE)
        return -EINVAL;
    
    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    if (!container) {
        spin_unlock_irqrestore(&container_list_lock, flags);
        return -ENOENT;
    }
    
    memcpy(leaf_hash, container->leaf_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    return 0;
}

__bpf_kfunc_end_defs();

/*
 * Forward declarations for securityfs functions only
 * (Merkle tree function declarations are earlier, before kfuncs)
 */
static int create_container_securityfs(struct container_node *container);
static void remove_container_securityfs(struct container_node *container);

/*
 * Merkle Tree Implementation for Container Tracking
 */

/**
 * compute_container_leaf_hash - Compute the leaf hash for a container
 * @container: Container node to compute hash for
 *
 * Computes SHA-256 hash of all measurement digests in the container's
 * measurement list. This hash becomes the container's leaf in the Merkle tree.
 * The hash is computed by concatenating all measurement digests in order
 * and hashing the result.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int compute_container_leaf_hash(struct container_node *container)
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
 * Must be called with container_list_lock held or from a context where
 * container list is stable.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int recalculate_merkle_root(void)
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
    
    /* Add the new Merkle root to the general measurement list */
    {
        struct bpf_ima_template_entry *pcr_entry;
        
        pcr_entry = kzalloc(sizeof(*pcr_entry), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
        if (pcr_entry) {
            pcr_entry->event_name[0] = '\0';
            pcr_entry->event_data[0] = '\0';
            memcpy(pcr_entry->digest, new_root, IMA_DIGEST_SIZE);
            
            spin_lock(&measurement_list_lock);
            list_add_tail(&pcr_entry->list, &bpf_measurement_list);
            atomic_inc(&measurement_count);
            spin_unlock(&measurement_list_lock);
            
            pr_debug("bpfima: Added Merkle root to general measurement list\n");
        }
    }
    
    /* Extend the Merkle root to physical TPM PCR */
    if (can_sleep) {
        extend_tpm_pcr(new_root, "merkle_root");
        pr_debug("bpfima: Extended Merkle root to TPM PCR\n");
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
 * Adds an entry to the merkle_root_history list to track what values
 * have been incorporated into the Merkle root over time.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int add_merkle_root_history_entry(const u8 *value, const char *container_id)
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
 * Searches the container_list for a container with the given ID.
 * Must be called with container_list_lock held.
 *
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
EXPORT_SYMBOL(find_container_by_id);

/**
 * create_container_node - Create and initialize a new container node
 * @container_id: Unique identifier for the container
 *
 * Allocates and initializes a new container_node structure, adds it to
 * the global container list, and creates its securityfs directory.
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
EXPORT_SYMBOL(create_container_node);

/**
 * add_container_measurement - Add a measurement to a container's list
 * @container: Container to add measurement to
 * @event_name: Event name/description
 * @event_data: Additional event data
 * @digest: SHA-256 digest of the measurement
 *
 * Adds a new measurement entry to the container's measurement list,
 * recalculates the container's leaf hash, updates the Merkle root,
 * and records the change in the root history.
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
    
    /* Recalculate Merkle root (this will also extend to PCR and update general list) */
    ret = recalculate_merkle_root();
    if (ret < 0) {
        pr_err("bpfima: Failed to recalculate merkle root: %d\n", ret);
        return ret;
    }
    
    pr_debug("bpfima: Added measurement to container %s, leaf hash updated\n",
             container->id);
    
    return 0;
}
EXPORT_SYMBOL(add_container_measurement);

/**
 * add_host_measurement - Add a measurement to the host measurement list
 * @event_name: Event name/description
 * @event_data: Additional event data
 * @digest: SHA-256 digest of the measurement
 *
 * Adds a measurement to the host-level measurement list.
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
EXPORT_SYMBOL(add_host_measurement);

/*
 * SecurityFS implementation for exposing measurement list
 */

/* Iterator for seq_file operations on measurement list */

/*
 * measurements_seq_start - Start iterator for measurement list seq_file operations
 * @s: seq_file structure for output formatting
 * @pos: Position in the measurement list to start from
 *
 * Acquires the measurement list spinlock and returns the list element at the
 * specified position. This function is called at the beginning of each read
 * operation on the measurements securityfs file.
 *
 * The spinlock is held until measurements_seq_stop() is called to ensure
 * consistent traversal of the measurement list.
 *
 * Returns: Pointer to list element at position @pos, or NULL if position is beyond list end
 */
static void *measurements_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&measurement_list_lock);
    return seq_list_start(&bpf_measurement_list, *pos);
}

/*
 * measurements_seq_next - Get next element in measurement list iteration
 * @s: seq_file structure for output formatting
 * @v: Current list element pointer
 * @pos: Current position in the list (updated by this function)
 *
 * Advances to the next element in the measurement list during seq_file iteration.
 * This function is called repeatedly during a single read operation to traverse
 * the entire measurement list.
 *
 * Returns: Pointer to next list element, or NULL if end of list is reached
 */
static void *measurements_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &bpf_measurement_list, pos);
}

/*
 * measurements_seq_stop - End measurement list iteration and release lock
 * @s: seq_file structure for output formatting
 * @v: Current list element pointer (may be NULL)
 *
 * Releases the measurement list spinlock that was acquired in measurements_seq_start().
 * This function is called at the end of each read operation, regardless of whether
 * the iteration completed successfully or was interrupted.
 *
 * Critical for preventing deadlocks - ensures the spinlock is always released.
 */
static void measurements_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&measurement_list_lock);
}

/*
 * measurements_seq_show - Format and output a single measurement entry
 * @s: seq_file structure for output formatting
 * @v: Pointer to current bpf_ima_template_entry
 *
 * Formats a single measurement entry for display in the securityfs measurements file.
 * Output format is space-separated on a single line:
 * "event_name event_data digest_hash\n"
 *
 * This format allows easy parsing by userspace tools while remaining human-readable.
 * The digest is output as a continuous hexadecimal string without spaces.
 *
 * Returns: 0 on success
 */
static int measurements_seq_show(struct seq_file *s, void *v)
{
    struct bpf_ima_template_entry *entry;
    int i;
    
    entry = list_entry(v, struct bpf_ima_template_entry, list);
    
    for (i = 0; i < IMA_DIGEST_SIZE; i++) {
        seq_printf(s, "%02x", entry->digest[i]);
    }

    seq_printf(s, " %s %s", entry->event_name, entry->event_data);
    seq_printf(s, "\n");
    
    return 0;
}

static const struct seq_operations measurements_seq_ops = {
    .start = measurements_seq_start,
    .next = measurements_seq_next,
    .stop = measurements_seq_stop,
    .show = measurements_seq_show,
};

/*
 * measurements_open - Open handler for measurements securityfs file
 * @inode: inode of the measurements file
 * @file: file structure being opened
 *
 * Initializes seq_file operations for the measurements file. This function
 * is called when userspace opens /sys/kernel/security/bpfima/measurements.
 *
 * Associates the file with the measurements_seq_ops to enable sequential
 * reading of the measurement list.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int measurements_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &measurements_seq_ops);
}

static const struct file_operations measurements_fops = {
    .owner = THIS_MODULE,
    .open = measurements_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

/*
 * status_show - Display module status information
 * @s: seq_file structure for output formatting
 * @unused: Unused parameter (required by single_open interface)
 *
 * Outputs current module status and configuration in key=value format:
 * - module: Module name (bpfima)
 * - measurement_count: Current number of recorded measurements
 * - pcr_index: TPM PCR index used for measurements
 * - tpm_available: Whether TPM hardware is available (yes/no)
 * - digest_algorithm: Hash algorithm used (sha256)
 *
 * This information helps userspace tools understand the current state
 * and capabilities of the BPF-IMA measurement system.
 *
 * Returns: 0 on success
 */
static int status_show(struct seq_file *s, void *unused)
{
    struct tpm_chip *chip;
    bool tpm_available = false;
    
    chip = tpm_default_chip();
    if (chip) {
        tpm_available = true;
        tpm_put_ops(chip);
    }
    
    seq_printf(s, "module=bpfima\n");
    seq_printf(s, "measurement_count=%d\n", atomic_read(&measurement_count));
    seq_printf(s, "pcr_index=%d\n", TPM_PCR_INDEX);
    seq_printf(s, "tpm_available=%s\n", tpm_available ? "yes" : "no");
    seq_printf(s, "digest_algorithm=sha256\n");
    
    return 0;
}

/*
 * status_open - Open handler for status securityfs file
 * @inode: inode of the status file
 * @file: file structure being opened
 *
 * Initializes single-show seq_file operations for the status file.
 * This function is called when userspace opens /sys/kernel/security/bpfima/status.
 *
 * Uses single_open() since the status file contains a single block of information
 * rather than a list that needs iteration.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int status_open(struct inode *inode, struct file *file)
{
    return single_open(file, status_show, NULL);
}

static const struct file_operations status_fops = {
    .owner = THIS_MODULE,
    .open = status_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/*
 * Container tracking and Merkle tree SecurityFS operations
 */

/*
 * host_measurements_show - Display host measurement list
 * @s: seq_file structure for output
 * @v: Current position in the list
 *
 * Shows all measurements from the host measurement list in the format:
 * digest event_name event_data
 */
static int host_measurements_seq_show(struct seq_file *s, void *v)
{
    struct measurement_entry *entry = list_entry(v, struct measurement_entry, list);
    int i;
    
    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", entry->digest[i]);
    
    seq_printf(s, " %s", entry->event_name);
    
    if (entry->event_data[0] != '\0')
        seq_printf(s, " %s", entry->event_data);
    
    seq_printf(s, "\n");
    return 0;
}

static void *host_measurements_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&host_measurement_lock);
    return seq_list_start(&host_measurement_list, *pos);
}

static void *host_measurements_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &host_measurement_list, pos);
}

static void host_measurements_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&host_measurement_lock);
}

static const struct seq_operations host_measurements_seq_ops = {
    .start = host_measurements_seq_start,
    .next = host_measurements_seq_next,
    .stop = host_measurements_seq_stop,
    .show = host_measurements_seq_show,
};

static int host_measurements_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &host_measurements_seq_ops);
}

static const struct file_operations host_measurements_fops = {
    .owner = THIS_MODULE,
    .open = host_measurements_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

/*
 * merkle_root_show - Display current Merkle root hash (virtual PCR)
 */
static int merkle_root_show(struct seq_file *s, void *unused)
{
    int i;
    unsigned long flags;
    
    spin_lock_irqsave(&system_merkle_root.lock, flags);
    
    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", system_merkle_root.root_hash[i]);
    
    seq_printf(s, " leaf_count=%u\n", system_merkle_root.leaf_count);
    
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);
    
    return 0;
}

static int merkle_root_open(struct inode *inode, struct file *file)
{
    return single_open(file, merkle_root_show, NULL);
}

static const struct file_operations merkle_root_fops = {
    .owner = THIS_MODULE,
    .open = merkle_root_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/*
 * merkle_root_history_show - Display history of values extended into Merkle root
 */
static int merkle_root_history_seq_show(struct seq_file *s, void *v)
{
    struct merkle_root_entry *entry = list_entry(v, struct merkle_root_entry, list);
    int i;
    
    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", entry->value[i]);
    
    if (entry->source_container_id[0] != '\0')
        seq_printf(s, " container=%s", entry->source_container_id);
    else
        seq_printf(s, " source=host");
    
    seq_printf(s, "\n");
    return 0;
}

static void *merkle_root_history_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&merkle_root_history_lock);
    return seq_list_start(&merkle_root_history, *pos);
}

static void *merkle_root_history_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &merkle_root_history, pos);
}

static void merkle_root_history_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&merkle_root_history_lock);
}

static const struct seq_operations merkle_root_history_seq_ops = {
    .start = merkle_root_history_seq_start,
    .next = merkle_root_history_seq_next,
    .stop = merkle_root_history_seq_stop,
    .show = merkle_root_history_seq_show,
};

static int merkle_root_history_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &merkle_root_history_seq_ops);
}

static const struct file_operations merkle_root_history_fops = {
    .owner = THIS_MODULE,
    .open = merkle_root_history_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

/*
 * container_list_show - Display list of all containers
 */
static int container_list_seq_show(struct seq_file *s, void *v)
{
    struct container_node *container = list_entry(v, struct container_node, list);
    int i;
    
    seq_printf(s, "%s leaf_hash=", container->id);
    
    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", container->leaf_hash[i]);
    
    seq_printf(s, " measurements=%d\n", atomic_read(&container->measurement_count));
    
    return 0;
}

static void *container_list_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&container_list_lock);
    return seq_list_start(&container_list, *pos);
}

static void *container_list_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &container_list, pos);
}

static void container_list_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&container_list_lock);
}

static const struct seq_operations container_list_seq_ops = {
    .start = container_list_seq_start,
    .next = container_list_seq_next,
    .stop = container_list_seq_stop,
    .show = container_list_seq_show,
};

static int container_list_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &container_list_seq_ops);
}

static const struct file_operations container_list_fops = {
    .owner = THIS_MODULE,
    .open = container_list_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

/*
 * container_measurements_show - Display measurements for a specific container
 * Uses inode->i_private to get the container_node pointer
 */
static int container_measurements_seq_show(struct seq_file *s, void *v)
{
    struct measurement_entry *entry = list_entry(v, struct measurement_entry, list);
    int i;
    
    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", entry->digest[i]);
    
    seq_printf(s, " %s", entry->event_name);
    
    if (entry->event_data[0] != '\0')
        seq_printf(s, " %s", entry->event_data);
    
    seq_printf(s, "\n");
    return 0;
}

static void *container_measurements_seq_start(struct seq_file *s, loff_t *pos)
{
    struct container_node *container = s->private;
    spin_lock(&container->measurement_lock);
    return seq_list_start(&container->measurement_list, *pos);
}

static void *container_measurements_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    struct container_node *container = s->private;
    return seq_list_next(v, &container->measurement_list, pos);
}

static void container_measurements_seq_stop(struct seq_file *s, void *v)
{
    struct container_node *container = s->private;
    spin_unlock(&container->measurement_lock);
}

static const struct seq_operations container_measurements_seq_ops = {
    .start = container_measurements_seq_start,
    .next = container_measurements_seq_next,
    .stop = container_measurements_seq_stop,
    .show = container_measurements_seq_show,
};

static int container_measurements_open(struct inode *inode, struct file *file)
{
    /* Get container_node from inode->i_private set during file creation */
    struct container_node *container = inode->i_private;
    int ret = seq_open(file, &container_measurements_seq_ops);
    if (ret == 0) {
        struct seq_file *sf = file->private_data;
        sf->private = container;
    }
    return ret;
}

static const struct file_operations container_measurements_fops = {
    .owner = THIS_MODULE,
    .open = container_measurements_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

/*
 * create_container_securityfs - Create securityfs directory for a new container
 * @container: Container node to create directory for
 *
 * Creates a subdirectory under /sys/kernel/security/bpfima/containers/<container_id>/
 * and a measurements file within it.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int create_container_securityfs(struct container_node *container)
{
    if (!containers_dir) {
        pr_err("bpfima: containers_dir not initialized\n");
        return -EINVAL;
    }
    
    /* Create container subdirectory */
    container->securityfs_dir = securityfs_create_dir(container->id, containers_dir);
    if (IS_ERR(container->securityfs_dir)) {
        pr_err("bpfima: Failed to create securityfs dir for container %s: %ld\n",
               container->id, PTR_ERR(container->securityfs_dir));
        return PTR_ERR(container->securityfs_dir);
    }
    
    /* Create measurements file with container pointer as private data */
    container->securityfs_measurements_file = 
        securityfs_create_file("measurements", 0444, container->securityfs_dir,
                              container, &container_measurements_fops);
    if (IS_ERR(container->securityfs_measurements_file)) {
        pr_err("bpfima: Failed to create measurements file for container %s: %ld\n",
               container->id, PTR_ERR(container->securityfs_measurements_file));
        securityfs_remove(container->securityfs_dir);
        container->securityfs_dir = NULL;
        return PTR_ERR(container->securityfs_measurements_file);
    }
    
    pr_info("bpfima: Created securityfs for container %s\n", container->id);
    return 0;
}

/*
 * remove_container_securityfs - Remove securityfs directory for a container
 * @container: Container node to remove directory for
 *
 * Removes the securityfs directory and files for a container.
 * Uses securityfs_remove() which handles NULL and IS_ERR pointers safely.
 */
static void remove_container_securityfs(struct container_node *container)
{
    if (container->securityfs_measurements_file && !IS_ERR(container->securityfs_measurements_file)) {
        securityfs_remove(container->securityfs_measurements_file);
        container->securityfs_measurements_file = NULL;
    }
    
    if (container->securityfs_dir && !IS_ERR(container->securityfs_dir)) {
        securityfs_remove(container->securityfs_dir);
        container->securityfs_dir = NULL;
    }
}

/*
 * bpfima_securityfs_init - Initialize SecurityFS interface for BPF-IMA
 *
 * Creates the SecurityFS directory and files to expose BPF-IMA measurement
 * data to userspace. The interface provides:
 *
 * /sys/kernel/security/bpfima/measurements - List of all measurements
 * /sys/kernel/security/bpfima/status - Module status and configuration
 *
 * If the "bpfima" directory already exists (from previous module load),
 * creates a unique directory name using the current process PID to avoid
 * conflicts: "bpfima_<pid>"
 *
 * Files are created with read-only permissions (0444) for security.
 * Proper cleanup on failure ensures no partial state is left behind.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int bpfima_securityfs_init(void)
{
    bpfima_dir = securityfs_create_dir("bpfima", NULL);
    if (IS_ERR(bpfima_dir)) {
        long err = PTR_ERR(bpfima_dir);
        if (err == -EEXIST) {
            snprintf(bpfima_dir_name, sizeof(bpfima_dir_name), "bpfima_%d", current->pid);
            pr_info("bpfima: Directory exists, using unique name: %s\n", bpfima_dir_name);
            bpfima_dir = securityfs_create_dir(bpfima_dir_name, NULL);
            if (IS_ERR(bpfima_dir)) {
                pr_err("bpfima: Failed to create unique securityfs directory: %ld\n", PTR_ERR(bpfima_dir));
                return PTR_ERR(bpfima_dir);
            }
        } else {
            pr_err("bpfima: Failed to create securityfs directory: %ld\n", err);
            return err;
        }
    }
    
    measurements_file = securityfs_create_file("measurements", 0444,
                                              bpfima_dir, NULL, &measurements_fops);
    if (IS_ERR(measurements_file)) {
        pr_err("bpfima: Failed to create measurements file: %ld\n", PTR_ERR(measurements_file));
        securityfs_remove(bpfima_dir);
        bpfima_dir = NULL;
        return PTR_ERR(measurements_file);
    }
    
    status_file = securityfs_create_file("status", 0444,
                                        bpfima_dir, NULL, &status_fops);
    if (IS_ERR(status_file)) {
        pr_err("bpfima: Failed to create status file: %ld\n", PTR_ERR(status_file));
        securityfs_remove(measurements_file);
        securityfs_remove(bpfima_dir);
        measurements_file = NULL;
        bpfima_dir = NULL;
        return PTR_ERR(status_file);
    }
    
    /* Create containers directory for container tracking */
    containers_dir = securityfs_create_dir("containers", bpfima_dir);
    if (IS_ERR(containers_dir)) {
        pr_err("bpfima: Failed to create containers directory: %ld\n", PTR_ERR(containers_dir));
        securityfs_remove(status_file);
        securityfs_remove(measurements_file);
        securityfs_remove(bpfima_dir);
        status_file = NULL;
        measurements_file = NULL;
        bpfima_dir = NULL;
        return PTR_ERR(containers_dir);
    }
    
    /* Create host measurements file */
    host_measurements_file = securityfs_create_file("host_measurements", 0444,
                                                   containers_dir, NULL, &host_measurements_fops);
    if (IS_ERR(host_measurements_file)) {
        pr_err("bpfima: Failed to create host_measurements file: %ld\n", PTR_ERR(host_measurements_file));
        goto cleanup_containers;
    }
    
    /* Create Merkle root file */
    merkle_root_file = securityfs_create_file("merkle_root", 0444,
                                             containers_dir, NULL, &merkle_root_fops);
    if (IS_ERR(merkle_root_file)) {
        pr_err("bpfima: Failed to create merkle_root file: %ld\n", PTR_ERR(merkle_root_file));
        goto cleanup_containers;
    }
    
    /* Create Merkle root history file */
    merkle_root_history_file = securityfs_create_file("merkle_root_history", 0444,
                                                     containers_dir, NULL, &merkle_root_history_fops);
    if (IS_ERR(merkle_root_history_file)) {
        pr_err("bpfima: Failed to create merkle_root_history file: %ld\n", PTR_ERR(merkle_root_history_file));
        goto cleanup_containers;
    }
    
    /* Create container list file */
    container_list_file = securityfs_create_file("container_list", 0444,
                                                containers_dir, NULL, &container_list_fops);
    if (IS_ERR(container_list_file)) {
        pr_err("bpfima: Failed to create container_list file: %ld\n", PTR_ERR(container_list_file));
        goto cleanup_containers;
    }
    
    pr_info("bpfima: SecurityFS interface created at /sys/kernel/security/%s/\n", bpfima_dir_name);
    pr_info("bpfima: Container tracking enabled at /sys/kernel/security/%s/containers/\n", bpfima_dir_name);
    return 0;

cleanup_containers:
    /* Recursive remove will clean up all files under containers_dir */
    if (containers_dir && !IS_ERR(containers_dir))
        securityfs_recursive_remove(containers_dir);
    securityfs_remove(status_file);
    securityfs_remove(measurements_file);
    securityfs_remove(bpfima_dir);
    containers_dir = NULL;
    host_measurements_file = NULL;
    merkle_root_file = NULL;
    merkle_root_history_file = NULL;
    container_list_file = NULL;
    status_file = NULL;
    measurements_file = NULL;
    bpfima_dir = NULL;
    return PTR_ERR(containers_dir);
}

/*
 * bpfima_securityfs_cleanup - Clean up SecurityFS interface
 *
 * Removes all SecurityFS files and directories created by bpfima_securityfs_init().
 * This function is called during module unload to ensure proper cleanup.
 *
 * Removal order is critical:
 * 1. Remove individual files first
 * 2. Remove child directories (containers_dir recursively)
 * 3. Remove parent directory (bpfima_dir recursively)
 *
 * Using securityfs_recursive_remove() ensures complete cleanup of directory trees.
 * All global pointers are reset to NULL to prevent double-cleanup attempts.
 *
 * Safe to call multiple times or with partially initialized state.
 */
static void bpfima_securityfs_cleanup(void)
{
    /* Remove individual files under bpfima_dir first */
    if (container_list_file) {
        securityfs_remove(container_list_file);
        container_list_file = NULL;
    }
    if (merkle_root_history_file) {
        securityfs_remove(merkle_root_history_file);
        merkle_root_history_file = NULL;
    }
    if (merkle_root_file) {
        securityfs_remove(merkle_root_file);
        merkle_root_file = NULL;
    }
    if (host_measurements_file) {
        securityfs_remove(host_measurements_file);
        host_measurements_file = NULL;
    }
    if (status_file) {
        securityfs_remove(status_file);
        status_file = NULL;
    }
    if (measurements_file) {
        securityfs_remove(measurements_file);
        measurements_file = NULL;
    }
    
    /* Recursively remove containers directory and all per-container subdirectories */
    if (containers_dir && !IS_ERR(containers_dir)) {
        securityfs_recursive_remove(containers_dir);
        containers_dir = NULL;
    }
    
    /* Finally, recursively remove the main bpfima directory */
    if (bpfima_dir && !IS_ERR(bpfima_dir)) {
        securityfs_recursive_remove(bpfima_dir);
        bpfima_dir = NULL;
    }
    
    pr_info("bpfima: SecurityFS interface removed\n");
}

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_ima_extend_measurement)
BTF_ID_FLAGS(func, bpf_ima_get_measurement_count)
BTF_ID_FLAGS(func, bpf_ima_get_pcr_value)
BTF_ID_FLAGS(func, bpf_tpm_is_available)
BTF_ID_FLAGS(func, bpf_ima_print_measurement_list)
BTF_ID_FLAGS(func, bpf_ima_file_hash_custom)
BTF_ID_FLAGS(func, bpf_container_create_or_get)
BTF_ID_FLAGS(func, bpf_container_add_measurement)
BTF_ID_FLAGS(func, bpf_host_add_measurement)
BTF_ID_FLAGS(func, bpf_get_merkle_root)
/* Task 6: Enhanced query kfuncs for bidirectional communication */
BTF_ID_FLAGS(func, bpf_container_get_count)
BTF_ID_FLAGS(func, bpf_container_get_measurement_count)
BTF_ID_FLAGS(func, bpf_container_exists)
BTF_ID_FLAGS(func, bpf_get_container_leaf_hash)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/*
 * bpfima_init - Module initialization function
 *
 * Registers BPF kfunc sets for both kprobe and tracepoint program types.
 * This allows BPF programs of these types to call the measurement functions.
 * The registration process creates BTF metadata that enables BPF verifier
 * to understand and validate calls to our kfuncs.
 *
 * Supported BPF program types:
 * - BPF_PROG_TYPE_KPROBE: For kernel probe programs
 * - BPF_PROG_TYPE_TRACEPOINT: For tracepoint programs
 *
 * Returns: 0 on success, negative error code on registration failure
 */
static int __init bpfima_init(void)
{
    int ret;

    printk(KERN_INFO "BPF-IMA module initializing...\n");
    
    /* Initialize Merkle tree root */
    memset(&system_merkle_root, 0, sizeof(system_merkle_root));
    spin_lock_init(&system_merkle_root.lock);
    pr_info("bpfima: Merkle tree root initialized\n");
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpfima: Failed to register BTF kfunc ID set for kprobe\n");
        return ret;
    }
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpfima: Failed to register BTF kfunc ID set for tracepoint\n");
        return ret;
    }
    
    ret = bpfima_securityfs_init();
    if (ret) {
        pr_err("bpfima: Failed to initialize SecurityFS interface\n");
        return ret;
    }
    
    printk(KERN_INFO "bpfima: Module loaded successfully\n");
    return 0;
}

/* Container and Merkle tree cleanup functions */

/**
 * cleanup_container_measurements - Free all measurements in a container
 * @container: Container to clean up
 *
 * Frees all measurement entries in the container's measurement list.
 * Must be called with container->measurement_lock held or when
 * no other threads can access the container.
 */
void cleanup_container_measurements(struct container_node *container)
{
    struct measurement_entry *entry, *tmp;
    
    list_for_each_entry_safe(entry, tmp, &container->measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}
EXPORT_SYMBOL(cleanup_container_measurements);

/**
 * cleanup_all_containers - Remove and free all container nodes
 *
 * Removes all containers from the list and frees their resources.
 * This includes securityfs entries and all measurement data.
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
EXPORT_SYMBOL(cleanup_all_containers);

/**
 * cleanup_host_measurements - Free all host measurement entries
 */
static void cleanup_host_measurements(void)
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
static void cleanup_merkle_root_history(void)
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

/*
 * bpfima_exit - Module cleanup function
 *
 * Performs complete cleanup when the module is unloaded:
 * 1. Prints final measurement list for audit purposes
 * 2. Safely deallocates all measurement entries from the list
 * 3. Uses proper locking to prevent race conditions during cleanup
 *
 * The function ensures all allocated memory is freed and provides
 * a final summary of measurement activity before module removal.
 * No explicit BTF kfunc unregistration needed as the kernel handles
 * this automatically when the module is unloaded.
 */
static void __exit bpfima_exit(void)
{
    struct bpf_ima_template_entry *entry, *tmp;

    printk(KERN_INFO "BPF-IMA module unloading...\n");
    
    /* Clean up container tracking structures FIRST (includes per-container securityfs) */
    cleanup_all_containers();
    cleanup_host_measurements();
    cleanup_merkle_root_history();
    
    /* Now clean up main securityfs interface (after containers are gone) */
    bpfima_securityfs_cleanup();
    
    /* Clean up original BPF measurement list */
    bpf_ima_print_measurement_list();

    spin_lock(&measurement_list_lock);
    list_for_each_entry_safe(entry, tmp, &bpf_measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&measurement_list_lock);

    cleanup_hash_table();

    printk(KERN_INFO "IMA measurements cleaned up. Total measurements: %d\n", 
           atomic_read(&measurement_count));
    printk(KERN_INFO "Container tracking: %d containers tracked\n",
           atomic_read(&container_count));
    printk(KERN_INFO "BPF-IMA module unloaded.\n");
}

module_init(bpfima_init);
module_exit(bpfima_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TORSEC");
MODULE_DESCRIPTION("BPF-IMA: eBPF-enhanced Integrity Measurement Architecture with TPM integration");
MODULE_VERSION("1.0");
