#include "../../utils/headers_bpf.h"

extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;
extern int bpf_tpm_is_available(void) __ksym;

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/mmap_file")
int bpf_mmap_file(struct file *file) {
    struct inode *inode = NULL;
    struct address_space *mapping;
    struct path file_path;
    struct dentry *dentry;
    umode_t mode;
    fmode_t f_mode;
    
    bpf_printk("=== MMAP FILE VIA LSM ===\n");

    if (!file) {
        bpf_printk("File pointer is NULL\n");
        return 0;
    }
    
    inode = BPF_CORE_READ(file, f_inode);
    
    if (!inode) {
        bpf_printk("f_inode is NULL, trying f_mapping->host\n");
        mapping = BPF_CORE_READ(file, f_mapping);
        if (mapping) {
            inode = BPF_CORE_READ(mapping, host);
            if (inode) {
                bpf_printk("Got inode via f_mapping->host\n");
            }
        }
    }
    
    if (!inode) {
        bpf_printk("f_mapping->host is NULL, trying f_path.dentry\n");
        file_path = BPF_CORE_READ(file, f_path);
        dentry = BPF_CORE_READ(&file_path, dentry);
        if (dentry) {
            inode = BPF_CORE_READ(dentry, d_inode);
            if (inode) {
                bpf_printk("Got inode via f_path.dentry->d_inode\n");
            }
        }
    }
    
    if (!inode) {
        bpf_printk("All inode methods failed, checking f_mode\n");
        f_mode = BPF_CORE_READ(file, f_mode);
        
        // Check if it's a regular file based on f_mode flags
        // FMODE_READ (0x1) and FMODE_WRITE (0x2) typically indicate regular files
        // if (!(f_mode & 0x1) && !(f_mode & 0x2)) {
        //     bpf_printk("Not a readable/writable file, skipping\n");
        //     return 0;
        // }
        
        bpf_printk("File appears to be regular based on f_mode: 0x%x\n", f_mode);
        
        // Proceed without inode check since we can't get it
        char event_name[] = "mmap_lsm_no_inode";
        char random_data[] = "mmap_data_no_inode_42";
        int ret = bpf_ima_extend_measurement(event_name, random_data, sizeof(random_data));
        bpf_printk("IMA measurement result (no inode): %d\n", ret);
        return 0;
    }

    // If we have an inode, check the file mode properly
    mode = BPF_CORE_READ(inode, i_mode);
    
    // Only process regular files (not sockets, pipes, etc.)
    if ((mode & 0170000) != 0100000) { // Not S_IFREG
        bpf_printk("Not a regular file (mode: 0x%x), skipping\n", mode);
        return 0;
    }
    
    bpf_printk("Regular file mmap detected (mode: 0x%x)\n", mode);
    
    // Call bpfima function for regular file mmap operations
    char event_name[] = "mmap_lsm";
    char random_data[] = "mmap_data_42";
    int ret = bpf_ima_extend_measurement(event_name, random_data, sizeof(random_data));
    bpf_printk("IMA measurement result: %d\n", ret);

    return 0;
}