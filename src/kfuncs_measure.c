#include "bpfima_common.h"
#include "bpfima_kfuncs.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"

/*
 * bpfima_measurement_extend - BPF kfunc to add measurement and extend TPM PCR
 * @event_name: Name/identifier of the event being measured
 * @namespace_id: Container/namespace identifier (uses "default" if NULL or empty)
 * @dependencies: Dependency chain information (e.g., parent process names)
 * @additional_data: Additional event data (hash, metadata, etc.)
 * @additional_data_len: Length of additional_data in bytes
 *
 * This is the main entry point for BPF programs to record integrity measurements.
 *
 * Flow:
 * 1. Calculate hash from concatenated data (dependencies | additional_data)
 * 2. Find or create container node for the given namespace_id
 * 3. Add measurement to container's measurement list
 * 4. Extend container's leaf hash with the new measurement
 * 5. Add leaf hash to Merkle root history
 * 6. Extend global Merkle root with updated container leaf hash
 * 7. Extend TPM PCR with new Merkle root (if not in atomic context)
 *
 * Can be called from both atomic and non-atomic contexts. TPM operations will be
 * deferred if called from atomic context to prevent scheduling while atomic bugs.
 *
 * Returns: 0 on success, negative error code on failure
 */

__bpf_kfunc_start_defs();

__bpf_kfunc int bpfima_measurement_extend(const char *event_name__nullable,
                                          const char *namespace_id__nullable, 
                                          const char *dependencies__nullable,
                                          const char *additional_data__nullable, 
                                          u32 additional_data_len)
{
    /* Alias the suffixed parameters to standard names to keep your logic clean */
    const char *event_name = event_name__nullable;
    const char *namespace_id = namespace_id__nullable;
    const char *dependencies = dependencies__nullable;
    const char *additional_data = additional_data__nullable;

    struct container_node *container = NULL;
    size_t total_len = 0;
    char *concat_data = NULL;
    size_t offset = 0;
    u8 hash_value[SHA256_DIGEST_SIZE];
    int ret = -1;
    char separator = ' ';
    bool can_sleep = !in_atomic() && !irqs_disabled();

    printk(KERN_INFO "bpfima: event_name='%s' namespace_id='%s' dependencies='%s' additional_data_len=%u\n",
           event_name ? event_name : "(null)",
           namespace_id ? namespace_id : "(null)",
           dependencies ? dependencies : "(null)",
           additional_data_len);

    if (!event_name && !namespace_id && !dependencies && !additional_data)
    {
        printk(KERN_ERR "bpfima: All parameters are null\n");
        return -EINVAL;
    }
    
    if (event_name && strlen(event_name) == 0)
    {
        printk(KERN_ERR "bpfima: Empty event_name not allowed\n");
        return -EINVAL;
    }

    if (dependencies)
    {
        total_len += strlen(dependencies) + 1;
    }
    
    if (additional_data && additional_data_len > 0)
    {
        total_len += additional_data_len + 1;
    }
    
    // separator between fields are of number n-1
    total_len -= 1;

    if (total_len == 0)
    {
        printk(KERN_ERR "bpfima: No valid data to concatenate\n");
        return -EINVAL;
    }

    concat_data = kmalloc(total_len, can_sleep ? GFP_KERNEL : GFP_ATOMIC);
    if (!concat_data)
    {
        printk(KERN_ERR "bpfima: kmalloc failed\n");
        return -ENOMEM;
    }

    if (additional_data && additional_data_len > 0)
    {
        memcpy(concat_data + offset, additional_data, additional_data_len);
        offset += additional_data_len;

        if (dependencies)
            concat_data[offset++] = separator;
    }

    if (dependencies)
    {
        size_t len = strlen(dependencies);
        memcpy(concat_data + offset, dependencies, len);
        offset += len;
    }

    ret = calculate_sha256_hash(concat_data, offset, hash_value);
    if (ret)
    {
        printk(KERN_ERR "bpfima: Failed to calculate SHA256 hash: %d\n", ret);
        kfree(concat_data);
        return ret;
    }

    printk(KERN_DEBUG "bpfima: Computed template hash over all fields: %*ph\n",
           SHA256_DIGEST_SIZE, hash_value);

    const char *effective_ns = (namespace_id && namespace_id[0] != '\0') ? namespace_id : "default";

    printk(KERN_INFO "bpfima: Processing container measurement for namespace: %s (original_ns=%s)\n",
           effective_ns, namespace_id ? namespace_id : "(null)");

    rcu_read_lock();
    container = find_container_by_id_rcu(effective_ns);
    rcu_read_unlock();

    if (!container)
    {
        printk(KERN_INFO "bpfima: Container %s not found, creating new one\n", effective_ns);
        container = create_container_node(effective_ns);
        if (IS_ERR(container))
        {
            printk(KERN_ERR "bpfima: Failed to create container %s: %ld\n",
                   effective_ns, PTR_ERR(container));
            kfree(concat_data);
            return PTR_ERR(container);
        }
    }

    ret = add_container_measurement(container, event_name,
                                    additional_data && additional_data_len > 0 ? (const char *)additional_data : "",
                                    dependencies ? dependencies : "",
                                    hash_value,
                                    can_sleep ? GFP_KERNEL : GFP_ATOMIC);

    bpfima_put_container(container);

    if (ret < 0)
    {
        printk(KERN_ERR "bpfima: Failed to add measurement to container %s: %d\n",
               effective_ns, ret);
        kfree(concat_data);
        return ret;
    }
    else if (ret == 1)
    {
        printk(KERN_INFO "bpfima:  File already accessed by namespace %s, skipped\n", effective_ns);
        kfree(concat_data);
        return 0;
    }

    printk(KERN_INFO "bpfima:  Successfully added measurement to container %s\n",
           effective_ns);
    printk(KERN_INFO "bpfima:  Leaf hash updated and added to history\n");
    printk(KERN_INFO "bpfima:  Merkle root recalculated and TPM extended\n");

    kfree(concat_data);
    return 0;
}

/*
 * bpfima_tpm_get_pcr_value - BPF kfunc to retrieve TPM PCR value or simulation
 * @pcr_buf: Output buffer to store PCR value string (minimum 80 bytes)
 * @buf_size: Size of output buffer in bytes
 * Output format:
 * - Real TPM: "PCR23_REAL:abc123def456..."
 * - Simulation: "PCR23_MEASUREMENTS_N_HASH_SIMULATION"
 * - Atomic context: "PCR23_MEASUREMENTS_N_ATOMIC_CONTEXT"
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_tpm_get_pcr_value(char *pcr_buf, u32 buf_size)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1];
    int ret;
    bool can_sleep = !in_atomic() && !irqs_disabled();

    if (!pcr_buf)
    {
        printk(KERN_ERR "bpfima: pcr_buf is null\n");
        return -EINVAL;
    }

    if (buf_size < 80)
    {
        printk(KERN_ERR "bpfima: buf_size too small: %u (minimum 80)\n",
               buf_size);
        return -EINVAL;
    }

    if (!can_sleep)
    {
        snprintf(pcr_buf, buf_size, "PCR%d_ATOMIC_CONTEXT",
                 TPM_PCR_INDEX);
        printk(KERN_INFO "Called from atomic context, using simulation\n");
        return 0;
    }

    mutex_lock(&bpfima_tpm_mutex);

    chip = tpm_default_chip();
    if (!chip)
    {
        mutex_unlock(&bpfima_tpm_mutex);
        snprintf(pcr_buf, buf_size, "PCR%d_HASH_SIMULATION",
                 TPM_PCR_INDEX);
        printk(KERN_INFO "TPM not available, using simulation\n");
        return 0;
    }

    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;

    tpm_pcr_read(chip, TPM_PCR_INDEX, digest);
    put_device(&chip->dev);

    mutex_unlock(&bpfima_tpm_mutex);

    if (ret < 0)
    {
        snprintf(pcr_buf, buf_size, "PCR%d_HASH_SIMULATION",
                 TPM_PCR_INDEX);
        printk(KERN_WARNING "TPM PCR read failed (%d), using simulation\n", ret);
        return ret;
    }

    snprintf(pcr_buf, buf_size, "PCR%d_REAL:", TPM_PCR_INDEX);
    for (int i = 0; i < SHA256_DIGEST_SIZE && strlen(pcr_buf) < buf_size - 3; i++)
    {
        snprintf(pcr_buf + strlen(pcr_buf), buf_size - strlen(pcr_buf),
                 "%02x", digest[0].digest[i]);
    }

    return 0;
}

/*
 * bpfima_tpm_is_available - BPF kfunc to check TPM hardware availability
 *
 * Attempts to acquire the default TPM chip to test if TPM hardware is available
 * and accessible. This is a lightweight check that doesn't perform any operations
 * on the TPM, just verifies that the chip can be obtained.
 *
 * Safe to call from any context as it only performs chip acquisition/release.
 *
 * Returns: 1 if TPM is available, 0 if not available
 */
__bpf_kfunc int bpfima_tpm_is_available(void)
{
    struct tpm_chip *chip;

    chip = tpm_default_chip();
    if (!chip)
        return 0;

    put_device(&chip->dev);
    return 1;
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
__bpf_kfunc int bpfima_file_hash(u64 file_scalar, u8 *digest,
                                         u32 digest_size)
{
    int ret;
    struct file *filep;
    char *filename = NULL;
    char *path_buf = NULL;
    bool can_sleep = !in_atomic() && !irqs_disabled();

    printk(KERN_DEBUG "bpfima: Simple IMA file hash called, file_scalar=%llx size=%u\n",
           file_scalar,
           digest_size);

    if (!file_scalar || !digest || digest_size != 32)
    {
        printk(KERN_ERR "bpfima: Invalid parameters for IMA file hashing\n");
        return -EINVAL;
    }

    /* Interpret the incoming scalar as a direct pointer to struct file */
    filep = (struct file *)(uintptr_t)file_scalar;

    if (IS_ERR_OR_NULL(filep))
    {
        printk(KERN_ERR "bpfima: File pointer appears invalid (filep=%p)\n",
               filep);
        return -EINVAL;
    }

    path_buf = kzalloc(PATH_MAX, can_sleep ? GFP_KERNEL : GFP_ATOMIC);

    if (path_buf)
    {
        filename = d_path(&filep->f_path, path_buf, PATH_MAX);
        if (!IS_ERR(filename))
        {
            printk(KERN_INFO "bpfima: Hashing file: %s\n", filename);
        }
        else
        {
            printk(KERN_DEBUG "bpfima: Could not get full path, error: %ld\n",
                   PTR_ERR(filename));
            if (filep->f_path.dentry && filep->f_path.dentry->d_name.name)
            {
                printk(KERN_INFO "bpfima: Hashing file (name only): %s\n",
                       filep->f_path.dentry->d_name.name);
            }
        }
        kfree(path_buf);
    }

    ret = ima_file_hash(filep, digest, digest_size);
    if (ret < 0)
    {
        printk(KERN_ERR "bpfima: IMA file hash failed: %d\n", ret);
        return ret;
    }

    bool all_zeros = true;
    for (int i = 0; i < digest_size; i++)
    {
        if (digest[i] != 0)
        {
            all_zeros = false;
            break;
        }
    }

    if (all_zeros)
    {
        printk(KERN_WARNING "bpfima: IMA returned all-zero hash - IMA policy may not be active or file not measured\n");
        printk(KERN_INFO "bpfima: To enable IMA: echo 'measure func=BPRM_CHECK' > /sys/kernel/security/ima/policy\n");
    }
    else
    {
        printk(KERN_INFO "bpfima: Successfully computed IMA file hash, digest=%*ph\n",
               digest_size,
               digest);
    }

    return 0;
}

__bpf_kfunc_end_defs();
