/*
 * BPF-IMA Core Module (Modular Version)
 * Main entry point, initialization, and module metadata
 * 
 * NOTE: This is a simplified modular version demonstrating the
 * refactored structure. For full functionality, use bpfima.c
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_securityfs.h"
#include "bpfima_kfuncs.h"

/* Legacy BPF-IMA global state */
LIST_HEAD(bpf_measurement_list);
DEFINE_SPINLOCK(measurement_list_lock);
atomic_t measurement_count = ATOMIC_INIT(0);

/* BTF kfunc ID set registration - only for container tracking kfuncs */
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_container_create_or_get)
BTF_ID_FLAGS(func, bpf_container_add_measurement)
BTF_ID_FLAGS(func, bpf_host_add_measurement)
BTF_ID_FLAGS(func, bpf_get_merkle_root)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/**
 * bpfima_init - Module initialization function
 */
static int __init bpfima_init(void)
{
    int ret;

    printk(KERN_INFO "bpfima_modular: Module initializing (demonstration version)...\n");
    
    /* Initialize Merkle tree root */
    memset(&system_merkle_root, 0, sizeof(system_merkle_root));
    spin_lock_init(&system_merkle_root.lock);
    pr_info("bpfima_modular: Merkle tree root initialized\n");
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpfima_modular: Failed to register BTF kfunc ID set for kprobe\n");
        return ret;
    }
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpfima_modular: Failed to register BTF kfunc ID set for tracepoint\n");
        return ret;
    }
    
    ret = bpfima_securityfs_init();
    if (ret) {
        pr_err("bpfima_modular: Failed to initialize SecurityFS interface\n");
        return ret;
    }
    
    printk(KERN_INFO "bpfima_modular: Module loaded successfully\n");
    printk(KERN_INFO "bpfima_modular: This is a demonstration of the modular structure.\n");
    printk(KERN_INFO "bpfima_modular: For full functionality, use bpfima.ko instead.\n");
    return 0;
}

/**
 * bpfima_exit - Module cleanup function
 */
static void __exit bpfima_exit(void)
{
    printk(KERN_INFO "bpfima_modular: Module unloading...\n");
    
    /* Clean up securityfs first */
    bpfima_securityfs_cleanup();
    
    /* Clean up container tracking structures */
    cleanup_all_containers();
    cleanup_host_measurements();
    cleanup_merkle_root_history();
    
    /* Clean up hash table */
    cleanup_hash_table();

    printk(KERN_INFO "bpfima_modular: Container tracking: %d containers tracked\n",
           atomic_read(&container_count));
    printk(KERN_INFO "bpfima_modular: Module unloaded.\n");
}

module_init(bpfima_init);
module_exit(bpfima_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TORSEC");
MODULE_DESCRIPTION("BPF-IMA: eBPF-enhanced Integrity Measurement Architecture with TPM integration");
