#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;
extern int bpf_tpm_is_available(void) __ksym;

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/mmap_file")
int bpf_file_open(struct file *file) {
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

/* Helper function to append string to buffer */
static __always_inline int append_string_to_buffer(char *buf, int *len, int max_len, const char *str, int str_max_len)
{
    for (int i = 0; i < str_max_len && str[i] != 0; i++) {
        if (*len >= max_len - 1) return -1;
        buf[(*len)++] = str[i];
    }
    return 0;
}

/* Helper function to append separator to buffer */
static __always_inline int append_separator(char *buf, int *len, int max_len)
{
    if (*len >= max_len - 1) return -1;
    buf[(*len)++] = '_';
    return 0;
}

/* Build measurement data string: "comm_pid_uid_full_path_filehash" */
static __always_inline int build_measurement_data(char *measurement_data, int max_len, 
                                                  const char *comm, pid_t pid, u32 uid)
{
    int len = 0;
    
    /* Add process name */
    if (append_string_to_buffer(measurement_data, &len, max_len, comm, 16) < 0)
        return -1;
    
    /* Add separator and PID */
    if (append_separator(measurement_data, &len, max_len) < 0)
        return -1;
    if (append_u32_to_buffer(measurement_data, &len, max_len, pid) < 0)
        return -1;
    
    /* Add separator and UID */
    if (append_separator(measurement_data, &len, max_len) < 0)
        return -1;
    if (append_u32_to_buffer(measurement_data, &len, max_len, uid) < 0)
        return -1;
    
    /* Null terminate */
    if (len < max_len) {
        measurement_data[len] = '\0';
    } else {
        return -1;
    }
    
    return len;
}

/* Monitor file open operations */
SEC("lsm/file_open")
int handle_lsm_file_post_open_tpm(struct file *file, int mask) {

    //struct path f_path;
    //bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);

    /*
    char full_path[PATH_MAX];
    long read = bpf_d_path(&f_path, full_path, sizeof(full_path));  
    if (read < 0) {
        bpf_printk("Failed to resolve file full path\n");
        return 0;
    } */

    // If we have an inode, check the file mode properly
    mode = BPF_CORE_READ(inode, i_mode);
    
    // Only process regular files (not sockets, pipes, etc.)
    if ((mode & 0170000) != 0100000) { // Not S_IFREG
        bpf_printk("Not a regular file (mode: 0x%x), skipping\n", mode);
    bpf_printk("=== TPM FILE OPEN DETECTED ===\n");
    bpf_printk("Process: pid=%d uid=%d gid=%d comm=%s\n", pid, uid, gid, comm);
    bpf_printk("Timestamp: %llu ns\n", ts);

    char measurement_data[256] = {0};
    int data_len = build_measurement_data(measurement_data, sizeof(measurement_data), comm, pid, uid);
    
    if (data_len < 0) {
        bpf_printk("Failed to build measurement data\n");
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
