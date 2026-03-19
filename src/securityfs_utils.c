#include "bpfima_securityfs.h"
#include "bpfima_merkle.h"

const struct file_operations status_fops = {
    .owner = THIS_MODULE,
    .open = status_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

const struct seq_operations merkle_root_history_seq_ops = {
    .start = merkle_root_history_seq_start,
    .next = merkle_root_history_seq_next,
    .stop = merkle_root_history_seq_stop,
    .show = merkle_root_history_seq_show,
};

const struct file_operations merkle_root_history_fops = {
    .owner = THIS_MODULE,
    .open = merkle_root_history_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

const struct seq_operations container_measurements_seq_ops = {
    .start = container_measurements_seq_start,
    .next = container_measurements_seq_next,
    .stop = container_measurements_seq_stop,
    .show = container_measurements_seq_show,
};

const struct file_operations container_measurements_fops = {
    .owner = THIS_MODULE,
    .open = container_measurements_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

struct dentry *bpfima_dir = NULL;
struct dentry *status_file = NULL;
char bpfima_dir_name[32] = "bpfima";

struct dentry *containers_dir = NULL;
struct dentry *merkle_root_history_file = NULL;

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
    if (chip)
    {
        tpm_available = true;
        put_device(&chip->dev);
    }

    seq_printf(s, "module=bpfima\n");
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
 * Merkle root history operations
 */
int merkle_root_history_seq_show(struct seq_file *s, void *v)
{
    struct merkle_root_entry *entry = list_entry(v, struct merkle_root_entry, list);
    int i;

    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", entry->value[i]);

    if (entry->is_aggregate) {
        seq_printf(s, " [AGGREGATE:%u entries]", entry->aggregated_count);
    }

    seq_printf(s, "\n");
    return 0;
}

void *merkle_root_history_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&merkle_root_history_lock);
    return seq_list_start(&merkle_root_history, *pos);
}

void *merkle_root_history_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &merkle_root_history, pos);
}

void merkle_root_history_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&merkle_root_history_lock);
}

int merkle_root_history_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &merkle_root_history_seq_ops);
}

/*
 * Container/Namespace measurements operations
 */
int container_measurements_seq_show(struct seq_file *s, void *v)
{
    struct measurement_entry *entry = list_entry(v, struct measurement_entry, list);
    int i;

    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", entry->digest[i]);

    seq_printf(s, " %s", entry->event_name);

    if (entry->event_data[0] != '\0')
        seq_printf(s, " %s", entry->event_data);

    if (entry->dependencies[0] != '\0')
        seq_printf(s, " %s", entry->dependencies);

    seq_printf(s, "\n");
    return 0;
}

void *container_measurements_seq_start(struct seq_file *s, loff_t *pos)
{
    struct container_node *container = s->private;
    spin_lock(&container->measurement_lock);
    return seq_list_start(&container->measurement_list, *pos);
}

void *container_measurements_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    struct container_node *container = s->private;
    return seq_list_next(v, &container->measurement_list, pos);
}

void container_measurements_seq_stop(struct seq_file *s, void *v)
{
    struct container_node *container = s->private;
    spin_unlock(&container->measurement_lock);
}

int container_measurements_open(struct inode *inode, struct file *file)
{
    struct container_node *container = inode->i_private;
    int ret = seq_open(file, &container_measurements_seq_ops);
    if (ret == 0)
    {
        struct seq_file *sf = file->private_data;
        sf->private = container;
    }
    return ret;
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
    remove_global_policy_changes_securityfs();
    remove_global_policy_securityfs();

    if (merkle_root_history_file)
    {
        securityfs_remove(merkle_root_history_file);
        merkle_root_history_file = NULL;
    }
    if (status_file)
    {
        securityfs_remove(status_file);
        status_file = NULL;
    }

    // After kernel version 6.16, the behavior of securityfs_remove was fixed and securityfs_recursive_remove removed
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
    if (containers_dir && !IS_ERR(containers_dir))
    {
        securityfs_remove(containers_dir);
        containers_dir = NULL;
    }

    if (bpfima_dir && !IS_ERR(bpfima_dir))
    {
        securityfs_remove(bpfima_dir);
        bpfima_dir = NULL;
    }
    #else
        if (containers_dir && !IS_ERR(containers_dir))
    {
        securityfs_recursive_remove(containers_dir);
        containers_dir = NULL;
    }

    if (bpfima_dir && !IS_ERR(bpfima_dir))
    {
        securityfs_recursive_remove(bpfima_dir);
        bpfima_dir = NULL;
    }
    #endif

    pr_info("bpfima: SecurityFS interface removed\n");
}

/*
 * create_container_securityfs - Create securityfs directory for a new container/namespace
 * @container: Container node to create directory for
 *
 * Creates a subdirectory under /sys/kernel/security/bpfima/namespaces/<namespace_id>/
 * with measurements file and policy file within it.
 *
 * Returns: 0 on success, negative error code on failure
 */
int create_container_securityfs(struct container_node *container)
{
    if (!containers_dir)
    {
        pr_err("bpfima: containers_dir not initialized\n");
        return -EINVAL;
    }

    container->securityfs_dir = securityfs_create_dir(container->id, containers_dir);
    if (IS_ERR(container->securityfs_dir))
    {
        pr_err("bpfima: Failed to create securityfs dir for container %s: %ld\n",
               container->id, PTR_ERR(container->securityfs_dir));
        return PTR_ERR(container->securityfs_dir);
    }

    container->securityfs_measurements_file =
        securityfs_create_file("measurements", 0444, container->securityfs_dir,
                               container, &container_measurements_fops);
    if (IS_ERR(container->securityfs_measurements_file))
    {
        pr_err("bpfima: Failed to create measurements file for container %s: %ld\n",
               container->id, PTR_ERR(container->securityfs_measurements_file));
        securityfs_remove(container->securityfs_dir);
        container->securityfs_dir = NULL;
        return PTR_ERR(container->securityfs_measurements_file);
    }

    container->securityfs_policy_file =
        create_namespace_policy_securityfs(container->id, container->securityfs_dir);
    if (IS_ERR(container->securityfs_policy_file))
    {
        pr_warn("bpfima: Failed to create policy file for container %s: %ld\n",
                container->id, PTR_ERR(container->securityfs_policy_file));
        container->securityfs_policy_file = NULL;
    }

    container->securityfs_policy_changes_file =
        create_namespace_policy_changes_securityfs(container->id, container->securityfs_dir);
    if (IS_ERR(container->securityfs_policy_changes_file))
    {
        pr_warn("bpfima: Failed to create policy_changes file for container %s: %ld\n",
                container->id, PTR_ERR(container->securityfs_policy_changes_file));
        container->securityfs_policy_changes_file = NULL;
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
void remove_container_securityfs(struct container_node *container)
{
    if (container->securityfs_policy_changes_file && !IS_ERR(container->securityfs_policy_changes_file))
    {
        remove_namespace_policy_changes_securityfs(container->securityfs_policy_changes_file);
        container->securityfs_policy_changes_file = NULL;
    }

    if (container->securityfs_policy_file && !IS_ERR(container->securityfs_policy_file))
    {
        remove_namespace_policy_securityfs(container->securityfs_policy_file);
        container->securityfs_policy_file = NULL;
    }

    if (container->securityfs_measurements_file && !IS_ERR(container->securityfs_measurements_file))
    {
        securityfs_remove(container->securityfs_measurements_file);
        container->securityfs_measurements_file = NULL;
    }

    if (container->securityfs_dir && !IS_ERR(container->securityfs_dir))
    {
        securityfs_remove(container->securityfs_dir);
        container->securityfs_dir = NULL;
    }
}
