#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * LSM hook for monitoring file open operations
 * Uses file_open hook which has access to the file structure
 */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    char file_hash[32];
    char comm[16];
    long hash_ret;
    struct inode *inode;
    umode_t mode;
    u32 pid;
    
    if (!file) {
        return 0;
    }
    
    /* Get basic process info */
    bpf_get_current_comm(comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Check if it's a regular file */
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;
    }
    
    mode = BPF_CORE_READ(inode, i_mode);
    if ((mode & 0170000) != 0100000) { /* Not a regular file */
        return 0;
    }
    
    bpf_printk("=== LSM file_open: Regular file opened by %s (PID: %u) ===\n", comm, pid);
    
    /* Try bpf_ima_file_hash in LSM context */
    hash_ret = bpf_ima_file_hash(file, file_hash, sizeof(file_hash));
    
    if (hash_ret > 0) {
        bpf_printk("SUCCESS! bpf_ima_file_hash returned %ld bytes in LSM\n", hash_ret);
        bpf_printk("Hash: %02x%02x%02x%02x%02x%02x%02x%02x...\n",
                   file_hash[0] & 0xff, file_hash[1] & 0xff, file_hash[2] & 0xff, file_hash[3] & 0xff,
                   file_hash[4] & 0xff, file_hash[5] & 0xff, file_hash[6] & 0xff, file_hash[7] & 0xff);
        
        bpf_printk("✓ IMA file hash successfully obtained in LSM!\n");
        
    } else {
        bpf_printk("⚠ bpf_ima_file_hash failed in LSM: %ld\n", hash_ret);
    }
    
    return 0;
}