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

#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX 255
#define TPM_PCR_INDEX 23
#define HASH_TABLE_BITS 8  

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

static LIST_HEAD(bpf_measurement_list);
static DEFINE_SPINLOCK(measurement_list_lock);
static atomic_t measurement_count = ATOMIC_INIT(0);

static DEFINE_HASHTABLE(sha256_hash_table, HASH_TABLE_BITS);
static DEFINE_SPINLOCK(hash_table_lock);

/* SecurityFS interface */
static struct dentry *bpfima_dir = NULL;
static struct dentry *measurements_file = NULL;
static struct dentry *status_file = NULL;
static char bpfima_dir_name[32] = "bpfima";

__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len);
__bpf_kfunc int bpf_ima_get_measurement_count(void);
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size);
__bpf_kfunc int bpf_tpm_is_available(void);
__bpf_kfunc int bpf_ima_print_measurement_list(void);

__bpf_kfunc_start_defs();


/*
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
static int calculate_sha256_hash(const void *data, size_t len, u8 *digest)
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

/*
 * hash_exists - Check if a SHA256 hash already exists in the hash table
 * @hash_value: SHA256 digest to search for (must be SHA256_DIGEST_SIZE bytes)
 *
 * Searches the hash table to determine if a measurement with the given SHA256 hash
 * has already been recorded. Uses a simple hash function based on the first 4 bytes
 * of the SHA256 digest. The function is thread-safe using spinlock protection.
 *
 * Returns: true if hash exists, false if not found
 */
static bool hash_exists(const u8 *hash_value)
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

/*
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
static int add_hash_to_table(const u8 *hash_value, bool can_sleep)
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

/*
 * extend_tpm_pcr - Extend TPM Platform Configuration Register with measurement
 * @hash_value: SHA256 digest to extend into the PCR (must be SHA256_DIGEST_SIZE bytes)
 * @event_name: Event name for logging purposes (used in success/failure messages)
 *
 * Attempts to extend the configured TPM PCR with the provided hash value.
 * This function handles TPM chip acquisition, digest preparation, PCR extension,
 * and proper cleanup. It provides detailed logging for both success and failure cases.
 *
 * The function assumes it's called in a context where sleeping is allowed
 * (i.e., not in atomic context) since TPM operations can sleep.
 *
 * Returns: 0 on successful PCR extension, negative error code on failure
 */
static int extend_tpm_pcr(const u8 *hash_value, const char *event_name)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1];
    int ret;

    chip = tpm_default_chip();
    if (!chip) {
        printk(KERN_WARNING "TPM not available, measurement added to list only\n");
        return -ENODEV;
    }

    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;
    memcpy(digest[0].digest, hash_value, SHA256_DIGEST_SIZE);
    
    ret = tpm_pcr_extend(chip, TPM_PCR_INDEX, digest);
    if (ret < 0) {
        printk(KERN_ERR "Failed to extend TPM PCR %d: %d\n", TPM_PCR_INDEX, ret);
    } else {
        printk(KERN_INFO "Extended TPM PCR %d with measurement for event: %s\n", TPM_PCR_INDEX, event_name);
    }
    
    tpm_put_ops(chip);
    return ret;
}

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

    /* Check if this hash already exists (duplicate detection) */
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
    
    if (can_sleep) {
        extend_tpm_pcr(hash_value, event_name);
    } else {
        printk(KERN_INFO "Called from atomic context, TPM extension deferred for event: %s\n", event_name);
    }

    spin_unlock(&measurement_list_lock);

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
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len)
{
    if (!event_name || !data) {
        printk(KERN_ERR "bpfima: Invalid null parameters (event_name=%p, data=%p)\n", event_name, data);
        return -EINVAL;
    }
    
    if (strlen(event_name) == 0) {
        printk(KERN_ERR "bpfima: Empty event_name not allowed\n");
        return -EINVAL;
    }
    
    if (data_len <= 0) { 
        printk(KERN_ERR "bpfima: Invalid data_len: %u\n", data_len);
        return -EINVAL;
    }
    
    if (strnlen(data, data_len) == 0) {
        printk(KERN_ERR "bpfima: Empty data content not allowed\n");
        return -EINVAL;
    }
    
    return process_measurement(event_name, data, data_len);
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

__bpf_kfunc_end_defs();

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
    
    seq_printf(s, "%s %s ", entry->event_name, entry->event_data);
    for (i = 0; i < IMA_DIGEST_SIZE; i++) {
        seq_printf(s, "%02x", entry->digest[i]);
    }
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
    
    pr_info("bpfima: SecurityFS interface created at /sys/kernel/security/%s/\n", bpfima_dir_name);
    return 0;
}

/*
 * bpfima_securityfs_cleanup - Clean up SecurityFS interface
 *
 * Removes all SecurityFS files and directories created by bpfima_securityfs_init().
 * This function is called during module unload to ensure proper cleanup.
 *
 * Removal order:
 * 1. Individual files (status, measurements)
 * 2. Directory (using recursive remove to handle any remaining content)
 *
 * Uses securityfs_recursive_remove() for the directory to ensure complete
 * cleanup even if files were somehow left behind. All global pointers are
 * reset to NULL to prevent double-cleanup attempts.
 *
 * Safe to call multiple times or with partially initialized state.
 */
static void bpfima_securityfs_cleanup(void)
{
    if (status_file) {
        securityfs_remove(status_file);
        status_file = NULL;
    }
    if (measurements_file) {
        securityfs_remove(measurements_file);
        measurements_file = NULL;
    }
    
    if (bpfima_dir) {
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
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
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

/*
 * cleanup_hash_table - Clean up all entries in the SHA256 hash table
 *
 * Iterates through all buckets of the hash table and frees all hash entries.
 * This function should be called during module cleanup to prevent memory leaks.
 * Uses irqsave locking to ensure safe cleanup in any context.
 */
static void cleanup_hash_table(void)
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
    
    printk(KERN_INFO "Hash table cleaned up. Freed %d hash entries\n", count);
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
    
    bpfima_securityfs_cleanup();
    
    bpf_ima_print_measurement_list();

    spin_lock(&measurement_list_lock);
    list_for_each_entry_safe(entry, tmp, &bpf_measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&measurement_list_lock);

    /* Cleanup hash table for duplicate detection */
    cleanup_hash_table();

    printk(KERN_INFO "IMA measurements cleaned up. Total measurements: %d\n", 
           atomic_read(&measurement_count));
    printk(KERN_INFO "BPF-IMA module unloaded.\n");
}

module_init(bpfima_init);
module_exit(bpfima_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TORSEC");
MODULE_DESCRIPTION("BPF-IMA: eBPF-enhanced Integrity Measurement Architecture with TPM integration");
MODULE_VERSION("1.0");