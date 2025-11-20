#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_kfuncs.h"
#include "bpfima_merkle.h"
#include "bpfima_securityfs.h"
#include "bpfima_policy.h"

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
    int ret = 0;
    bpfima_dir = securityfs_create_dir("bpfima", NULL);
    if (IS_ERR(bpfima_dir))
    {
        long err = PTR_ERR(bpfima_dir);
        if (err == -EEXIST)
        {
            snprintf(bpfima_dir_name, sizeof(bpfima_dir_name), "bpfima_%d", current->pid);
            pr_info("bpfima: Directory exists, using unique name: %s\n", bpfima_dir_name);
            bpfima_dir = securityfs_create_dir(bpfima_dir_name, NULL);
            if (IS_ERR(bpfima_dir))
            {
                pr_err("bpfima: Failed to create unique securityfs directory: %ld\n", PTR_ERR(bpfima_dir));
                return PTR_ERR(bpfima_dir);
            }
        }
        else
        {
            pr_err("bpfima: Failed to create securityfs directory: %ld\n", err);
            return err;
        }
    }

    status_file = securityfs_create_file("status", 0444,
                                         bpfima_dir, NULL, &status_fops);
    if (IS_ERR(status_file))
    {
        pr_err("bpfima: Failed to create status file: %ld\n", PTR_ERR(status_file));
        securityfs_remove(bpfima_dir);
        bpfima_dir = NULL;
        return PTR_ERR(status_file);
    }

    merkle_root_history_file = securityfs_create_file("merkle_root_history", 0444,
                                                      bpfima_dir, NULL, &merkle_root_history_fops);
    if (IS_ERR(merkle_root_history_file))
    {
        pr_err("bpfima: Failed to create merkle_root_history file: %ld\n", PTR_ERR(merkle_root_history_file));
        securityfs_remove(status_file);
        securityfs_remove(bpfima_dir);
        status_file = NULL;
        bpfima_dir = NULL;
        return PTR_ERR(merkle_root_history_file);
    }

    containers_dir = securityfs_create_dir("namespaces", bpfima_dir);
    if (IS_ERR(containers_dir))
    {
        pr_err("bpfima: Failed to create namespaces directory: %ld\n", PTR_ERR(containers_dir));
        securityfs_remove(merkle_root_history_file);
        securityfs_remove(status_file);
        securityfs_remove(bpfima_dir);
        merkle_root_history_file = NULL;
        status_file = NULL;
        bpfima_dir = NULL;
        return PTR_ERR(containers_dir);
    }

    ret = create_global_policy_securityfs(bpfima_dir);
    if (ret)
    {
        pr_err("bpfima: Failed to create global policy file: %d\n", ret);
        securityfs_remove(containers_dir);
        securityfs_remove(merkle_root_history_file);
        securityfs_remove(status_file);
        securityfs_remove(bpfima_dir);
        containers_dir = NULL;
        merkle_root_history_file = NULL;
        status_file = NULL;
        bpfima_dir = NULL;
        return ret;
    }

    ret = create_global_policy_changes_securityfs(bpfima_dir);
    if (ret)
    {
        pr_err("bpfima: Failed to create global policy_changes file: %d\n", ret);
        remove_global_policy_securityfs();
        securityfs_remove(containers_dir);
        securityfs_remove(merkle_root_history_file);
        securityfs_remove(status_file);
        securityfs_remove(bpfima_dir);
        containers_dir = NULL;
        merkle_root_history_file = NULL;
        status_file = NULL;
        bpfima_dir = NULL;
        return ret;
    }

    pr_info("bpfima: SecurityFS interface created at /sys/kernel/security/%s/\n", bpfima_dir_name);
    pr_info("bpfima: Global policy at /sys/kernel/security/%s/policy\n", bpfima_dir_name);
    pr_info("bpfima: Global policy changes at /sys/kernel/security/%s/policy_changes\n", bpfima_dir_name);
    pr_info("bpfima: Namespace tracking enabled at /sys/kernel/security/%s/namespaces/\n", bpfima_dir_name);
    return 0;
}

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpfima_measurement_extend)
BTF_ID_FLAGS(func, bpfima_tpm_get_pcr_value)
BTF_ID_FLAGS(func, bpfima_tpm_is_available)
BTF_ID_FLAGS(func, bpfima_file_hash)
BTF_ID_FLAGS(func, bpfima_container_get_or_create)
BTF_ID_FLAGS(func, bpfima_merkle_get_root)

BTF_ID_FLAGS(func, bpfima_container_get_count)
BTF_ID_FLAGS(func, bpfima_container_get_measurement_count)
BTF_ID_FLAGS(func, bpfima_container_exists)
BTF_ID_FLAGS(func, bpfima_container_get_leaf_hash)

BTF_ID_FLAGS(func, bpfima_policy_update_filter_flags)
BTF_ID_FLAGS(func, bpfima_policy_update_action_flags)
BTF_ID_FLAGS(func, bpfima_policy_update_min_file_size)
BTF_ID_FLAGS(func, bpfima_policy_update_log_level)
BTF_ID_FLAGS(func, bpfima_policy_get_changes_hash)
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

    ret = bpfima_policy_init();
    if (ret)
    {
        pr_err("bpfima: Failed to initialize policy subsystem: %d\n", ret);
        return ret;
    }

    ret = bpfima_policy_namespace_init();
    if (ret)
    {
        pr_err("bpfima: Failed to initialize namespace policy subsystem: %d\n", ret);
        bpfima_policy_cleanup();
        return ret;
    }

    memset(&system_merkle_root, 0, sizeof(system_merkle_root));
    spin_lock_init(&system_merkle_root.lock);
    pr_info("bpfima: Merkle tree root initialized\n");

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpfima: Failed to register BTF kfunc ID set for kprobe\n");
        bpfima_policy_namespace_cleanup();
        bpfima_policy_cleanup();
        return ret;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpfima: Failed to register BTF kfunc ID set for tracepoint\n");
        bpfima_policy_namespace_cleanup();
        bpfima_policy_cleanup();
        return ret;
    }

    ret = bpfima_securityfs_init();
    if (ret)
    {
        pr_err("bpfima: Failed to initialize SecurityFS interface\n");
        bpfima_policy_namespace_cleanup();
        bpfima_policy_cleanup();
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
    printk(KERN_INFO "BPF-IMA module unloading...\n");

    /* Clean up container tracking structures FIRST (includes per-container securityfs) */
    cleanup_all_containers();
    cleanup_merkle_root_history();

    /* Now clean up main securityfs interface (after containers are gone) */
    bpfima_securityfs_cleanup();

    /* Clean up policy subsystem */
    bpfima_policy_namespace_cleanup();
    bpfima_policy_cleanup();

    cleanup_hash_table();

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
