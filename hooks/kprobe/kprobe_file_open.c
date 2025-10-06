#include "../../utils/headers_bpf.h"

char LICENSE[] SEC("license") = "GPL";


extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;

/*
 * Simple kretprobe on do_filp_open - called when file open returns
 * Focus on demonstrating bpf_ima_file_hash functionality
 */
SEC("kretprobe/do_filp_open") 
int kretprobe_file_open(struct pt_regs *ctx) {
    struct file *file;
    struct inode *inode;
    char file_hash[32];
    char comm[16];
    long hash_ret;
    umode_t mode;
    u32 pid;
    
    /* Get the file pointer from return value */
    file = (struct file *)PT_REGS_RC(ctx);
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
    
    bpf_printk("=== KRETPROBE: Regular file opened by %s (PID: %u) ===\n", comm, pid);
    
    /* The key fubpf_ima_file_hashnctionality - use bpf_ima_file_hash in sleepable kretprobe! */
    hash_ret = (file, file_hash, sizeof(file_hash));
    
    if (hash_ret > 0) {
        bpf_printk("SUCCESS! bpf_ima_file_hash returned %ld bytes\n", hash_ret);
        bpf_printk("Hash: %02x%02x%02x%02x%02x%02x%02x%02x...\n",
                   file_hash[0] & 0xff, file_hash[1] & 0xff, file_hash[2] & 0xff, file_hash[3] & 0xff,
                   file_hash[4] & 0xff, file_hash[5] & 0xff, file_hash[6] & 0xff, file_hash[7] & 0xff);
        
        bpf_printk("✓ IMA file hash successfully obtained!\n");
        
    } else {
        bpf_printk("⚠ bpf_ima_file_hash failed: %ld\n", hash_ret);
    }
    
    return 0;
}