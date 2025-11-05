#include "bpfima_common.h"
#include "bpfima_kfuncs.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"

/* Global measurement tracking */
LIST_HEAD(bpf_measurement_list);
DEFINE_SPINLOCK(measurement_list_lock);
atomic_t measurement_count = ATOMIC_INIT(0);

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
static int process_measurement(const char *event_name, const char *data, u32 data_len, const char *namespace_id)
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

    if (hash_exists(hash_value, namespace_id)) {
        printk(KERN_INFO "IMA_DUPLICATE: event=%s namespace=%s digest=%*ph (skipped - already accessed by this namespace)\n", 
               event_name, namespace_id ? namespace_id : "host", IMA_DIGEST_SIZE, hash_value);
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

    ret = add_hash_to_table(hash_value, namespace_id, can_sleep);
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
        extend_tpm_pcr(hash_value, event_name);
        spin_unlock(&measurement_list_lock);
    }

    printk(KERN_INFO "IMA_MEASUREMENT: event=%s count=%d digest=%*ph\n", 
           event_name, atomic_read(&measurement_count), IMA_DIGEST_SIZE, hash_value);
    
    return atomic_read(&measurement_count);
}

/*
 * bpf_ima_extend_measurement - BPF kfunc to add measurement and extend TPM PCR
 * @event_name: Name/identifier of the event being measured (must not be null or empty)
 * @namespace_id: Container/namespace identifier (NULL for host measurements)
 * @dependencies: Dependency chain information (e.g., parent process names)
 * @additional_data: Additional event data (hash, metadata, etc.)
 * @additional_data_len: Length of additional_data in bytes
 *
 * This is the main entry point for BPF programs to record integrity measurements.
 * 
 * Flow:
 * 1. Calculate hash from concatenated data (namespace_id | dependencies | additional_data)
 * 2. If namespace_id is provided:
 *    a. Find or create container node
 *    b. Add measurement to container's measurement list
 *    c. Recalculate container's leaf hash
 *    d. Add leaf hash to Merkle root history
 *    e. Recalculate global Merkle root
 *    f. Extend TPM PCR with new Merkle root
 * 3. If namespace_id is NULL, use legacy host measurement system
 *
 * Can be called from both atomic and non-atomic contexts. TPM operations will be
 * deferred if called from atomic context to prevent scheduling while atomic bugs.
 *
 * Returns: 0 on success, negative error code on failure
 */

__bpf_kfunc_start_defs();
 
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len)
{
    struct container_node *container = NULL;
    unsigned long flags;
    size_t total_len = 0;
    char *concat_data = NULL;
    size_t offset = 0;
    u8 hash_value[SHA256_DIGEST_SIZE];
    int ret = -1;
    char separator = '|';
    bool can_sleep = !in_atomic() && !irqs_disabled();

    printk(KERN_INFO "bpfima: event_name='%s' namespace_id='%s' dependencies='%s' additional_data_len=%u", 
        event_name ? event_name : "(null)", 
        namespace_id ? namespace_id : "(null)", 
        dependencies ? dependencies : "(null)", 
        additional_data_len);

    /* Parameter validation */
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
    
    total_len += 4; 

    if (total_len == 0) {
        printk(KERN_ERR "bpfima: No valid data to concatenate\n");
        return -EINVAL;
    }

    concat_data = kmalloc(total_len, can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!concat_data) {
        printk(KERN_ERR "bpfima: kmalloc failed\n");
        return -ENOMEM;
    }

    if (event_name) {
        size_t len = strlen(event_name);
        memcpy(concat_data + offset, event_name, len);
        offset += len;
        concat_data[offset++] = separator;
    }
    if (namespace_id) {
        size_t len = strlen(namespace_id);
        memcpy(concat_data + offset, namespace_id, len);
        offset += len;
        concat_data[offset++] = separator;
    }
    if (dependencies) {
        size_t len = strlen(dependencies);
        memcpy(concat_data + offset, dependencies, len);
        offset += len;
        concat_data[offset++] = separator;
    }
    if (additional_data && additional_data_len > 0) {
        memcpy(concat_data + offset, additional_data, additional_data_len);
        offset += additional_data_len;
    }

    /* Step 2: Calculate hash of the concatenated data */
    ret = calculate_sha256_hash(concat_data, offset, hash_value);
    if (ret) {
        printk(KERN_ERR "bpfima: Failed to calculate SHA256 hash: %d\n", ret);
        kfree(concat_data);
        return ret;
    }

    printk(KERN_DEBUG "bpfima: Computed template hash over all fields: %*ph\n", SHA256_DIGEST_SIZE, hash_value);

    /* Step 3: Check if this is a container measurement */
    if (namespace_id && namespace_id[0] != '\0') {
        /* Container/namespace measurement flow */
        printk(KERN_INFO "bpfima: Processing container measurement for namespace: %s\n", namespace_id);

        /* Find or create container */
        spin_lock_irqsave(&container_list_lock, flags);
        container = find_container_by_id(namespace_id);
        spin_unlock_irqrestore(&container_list_lock, flags);

        if (!container) {
            printk(KERN_INFO "bpfima: Container %s not found, creating new one\n", namespace_id);
            container = create_container_node(namespace_id);
            if (IS_ERR(container)) {
                printk(KERN_ERR "bpfima: Failed to create container %s: %ld\n",
                       namespace_id, PTR_ERR(container));
                kfree(concat_data);
                return PTR_ERR(container);
            }
        }

        /* Step 5: Add measurement directly to namespace/container list */
        ret = add_container_measurement(container, event_name, concat_data, hash_value);
        if (ret < 0) {
            printk(KERN_ERR "bpfima: Failed to add measurement to container %s: %d\n",
                   namespace_id, ret);
            kfree(concat_data);
            return ret;
        } else if (ret == 1) {
            printk(KERN_INFO "bpfima:  File already accessed by namespace %s, skipped\n", namespace_id);
            kfree(concat_data);
            return 0;
        }

        printk(KERN_INFO "bpfima:  Successfully added measurement to container %s\n", namespace_id);
        printk(KERN_INFO "bpfima:  Leaf hash updated and added to history\n");
        printk(KERN_INFO "bpfima:  Merkle root recalculated and TPM extended\n");

    } else {
        printk(KERN_INFO "bpfima: Processing host-level measurement\n");
        ret = process_measurement(event_name ? event_name : "", concat_data, offset, NULL);
        if (ret < 0) {
            printk(KERN_ERR "bpfima: Failed to process host measurement: %d\n", ret);
            kfree(concat_data);
            return ret;
        }
    }

    kfree(concat_data);
    return 0;
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
    
    mutex_lock(&tpm_ops_mutex);

    chip = tpm_default_chip();
    if (!chip) {
        mutex_unlock(&tpm_ops_mutex);
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_INFO "TPM not available, using simulation\n");
        return 0;
    }
    
    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;
    
    ret = tpm_pcr_read(chip, TPM_PCR_INDEX, digest);
    tpm_put_ops(chip);

    mutex_unlock(&tpm_ops_mutex);
    
    if (ret < 0) {
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_WARNING "TPM PCR read failed (%d), using simulation\n", ret);
        return ret;
    }
    
    snprintf(pcr_buf, buf_size, "PCR%d_REAL:", TPM_PCR_INDEX);
    for (int i = 0; i < SHA256_DIGEST_SIZE && strlen(pcr_buf) < buf_size - 3; i++) {
        snprintf(pcr_buf + strlen(pcr_buf), buf_size - strlen(pcr_buf), 
                 "%02x", digest[0].digest[i]);
    }
    
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

    printk(KERN_DEBUG "bpfima: Simple IMA file hash called, file_scalar=%llx, size=%u\n", 
           file_scalar, digest_size);

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

    bool all_zeros = true;
    for (int i = 0; i < digest_size; i++) {
        if (digest[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    
    if (all_zeros) {
        printk(KERN_WARNING "bpfima: IMA returned all-zero hash - IMA policy may not be active or file not measured\n");
        printk(KERN_INFO "bpfima: To enable IMA: echo 'measure func=BPRM_CHECK' > /sys/kernel/security/ima/policy\n");
    } else {
        printk(KERN_INFO "bpfima: Successfully computed IMA file hash, digest=%*ph\n", 
               digest_size, digest);
    }
    
    return 0;
}

__bpf_kfunc_end_defs();
