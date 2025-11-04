#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_kfuncs.h"
#include "bpfima_merkle.h"
#include "bpfima_securityfs.h"

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

    /* Create namespaces directory for container tracking */
    containers_dir = securityfs_create_dir("namespaces", bpfima_dir);
    if (IS_ERR(containers_dir)) {
        pr_err("bpfima: Failed to create namespaces directory: %ld\n", PTR_ERR(containers_dir));
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
