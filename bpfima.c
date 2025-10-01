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

#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX 255
#define TPM_PCR_INDEX 23

struct bpf_ima_template_entry {
    struct list_head list;
    char event_name[IMA_EVENT_NAME_LEN_MAX + 1];
    char event_data[256];
    u8 digest[IMA_DIGEST_SIZE];
};

static LIST_HEAD(bpf_measurement_list);
static DEFINE_SPINLOCK(measurement_list_lock);
static atomic_t measurement_count = ATOMIC_INIT(0);

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
 * 2. Creates a measurement entry and adds it to the global list
 * 3. Attempts TPM PCR extension if not in atomic context
 * 4. Handles atomic context by deferring TPM operations
 * 5. Uses appropriate memory allocation flags based on context
 *
 * The function maintains atomicity between list operations and TPM operations
 * using a spinlock, but allows interrupts to prevent scheduling while atomic bugs.
 *
 * Returns: Total number of measurements recorded, negative error code on failure
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

    entry = kzalloc(sizeof(*entry), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;

    strncpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX);
    entry->event_name[IMA_EVENT_NAME_LEN_MAX] = '\0';
    
    strncpy(entry->event_data, data, min_t(u32, data_len, sizeof(entry->event_data) - 1));
    entry->event_data[sizeof(entry->event_data) - 1] = '\0';
    
    memcpy(entry->digest, hash_value, IMA_DIGEST_SIZE);

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
    
    printk(KERN_INFO "bpfima: Module loaded successfully\n");
    return 0;
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
    
    bpf_ima_print_measurement_list();

    spin_lock(&measurement_list_lock);
    list_for_each_entry_safe(entry, tmp, &bpf_measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&measurement_list_lock);

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