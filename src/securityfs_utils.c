#include "bpfima_securityfs.h"
#include "bpfima_merkle.h"

const struct seq_operations measurements_seq_ops = {
    .start = measurements_seq_start,
    .next = measurements_seq_next,
    .stop = measurements_seq_stop,
    .show = measurements_seq_show,
};

const struct file_operations measurements_fops = {
    .owner = THIS_MODULE,
    .open = measurements_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

const struct file_operations status_fops = {
    .owner = THIS_MODULE,
    .open = status_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

const struct seq_operations host_measurements_seq_ops = {
    .start = host_measurements_seq_start,
    .next = host_measurements_seq_next,
    .stop = host_measurements_seq_stop,
    .show = host_measurements_seq_show,
};

const struct file_operations host_measurements_fops = {
    .owner = THIS_MODULE,
    .open = host_measurements_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

const struct file_operations merkle_root_fops = {
    .owner = THIS_MODULE,
    .open = merkle_root_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

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
void *measurements_seq_start(struct seq_file *s, loff_t *pos)
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
void *measurements_seq_next(struct seq_file *s, void *v, loff_t *pos)
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
void measurements_seq_stop(struct seq_file *s, void *v)
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
int measurements_seq_show(struct seq_file *s, void *v)
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
int measurements_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &measurements_seq_ops);
}

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
int status_show(struct seq_file *s, void *unused)
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
int status_open(struct inode *inode, struct file *file)
{
    return single_open(file, status_show, NULL);
}

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
int host_measurements_seq_show(struct seq_file *s, void *v)
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

void *host_measurements_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&host_measurement_lock);
    return seq_list_start(&host_measurement_list, *pos);
}

void *host_measurements_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &host_measurement_list, pos);
}

void host_measurements_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&host_measurement_lock);
}

int host_measurements_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &host_measurements_seq_ops);
}

/*
 * merkle_root_show - Display current Merkle root hash (virtual PCR)
 */
int merkle_root_show(struct seq_file *s, void *unused)
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

int merkle_root_open(struct inode *inode, struct file *file)
{
    return single_open(file, merkle_root_show, NULL);
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
void bpfima_securityfs_cleanup(void)
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

