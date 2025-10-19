#include "../../utils/headers_bpf.h"

#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#endif

/* External kfunc declarations for IMA operations */
extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;
extern int bpf_tpm_is_available(void) __ksym;
extern int bpf_ima_custom_file_hash_scalar(struct file *file, u8 *digest, u32 digest_size) __ksym;
extern int bpf_ima_hash_by_inode(u64 inode_number, u32 dev_id, u8 *digest, u32 digest_size) __ksym;
extern int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size) __ksym;

char LICENSE[] SEC("license") = "GPL";

/*
 * LSM hook for monitoring file post-open operations
 * This hook is called after a file has been successfully opened
 * 
 * Parameters:
 *   - struct file *file: The file structure of the opened file
 *   - int mask: The file access mask/permissions used to open the file
 * 
 * The mask parameter contains flags like:
 *   - MAY_READ (0x00000001)
 *   - MAY_WRITE (0x00000002)
 *   - MAY_EXEC (0x00000004)
 *   - MAY_APPEND (0x00000008)
 */
SEC("lsm/file_post_open")
int BPF_PROG(lsm_file_post_open, struct file *file, int mask)
{
    u8 digest[32] = {0};
    char comm[16] = {0};
    char filepath[256] = {0};
    u64 file_scalar;
    u32 pid;
    u64 pid_tgid;
    int hash_ret;
    char event_name[] = "file_post_open";
    
    /* Get process information */
    bpf_get_current_comm(comm, sizeof(comm));
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    if (!(mask & 0x00000004)) {
        return 0;  // Skip no exec accesses for this example
    }

    /* Print mask information */

    /* Decode mask flags */
/*     if (mask & 0x00000001) {
        bpf_printk("  - MAY_READ\n");
    }
    if (mask & 0x00000002) {
        bpf_printk("  - MAY_WRITE\n");
    }
    if (mask & 0x00000004) {
        bpf_printk("  - MAY_EXEC\n");
    }
    if (mask & 0x00000008) {
        bpf_printk("  - MAY_APPEND\n");
    }
     */
    /* Check if file pointer is valid */
    if (!file) {
        return 0;
    }
    
    /* Get full file path */
    long ret = bpf_d_path(&file->f_path, filepath, sizeof(filepath));
    if (ret < 0) {
        /* Fallback to just filename if full path fails */
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
            if (name_ptr) {
                bpf_probe_read_kernel_str(filepath, sizeof(filepath), name_ptr);
            }
            else {
                return 0;
            }
        }
        else {
            return 0;
        }
    }
    
    /* Only process files in /home/lo directory */
    if (filepath[0] != '/' || filepath[1] != 'h' || filepath[2] != 'o' || 
        filepath[3] != 'm' || filepath[4] != 'e' || filepath[5] != '/' ||
        filepath[6] != 'l' || filepath[7] != 'o' || filepath[8] != '/') {
        return 0;
    }
    
    /* Get inode information */
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;
    }
    
    /* Read inode details */
    unsigned long i_ino = BPF_CORE_READ(inode, i_ino);
    umode_t i_mode = BPF_CORE_READ(inode, i_mode);
    uid_t i_uid_val = BPF_CORE_READ(inode, i_uid.val);
    gid_t i_gid_val = BPF_CORE_READ(inode, i_gid.val);
    loff_t i_size = BPF_CORE_READ(inode, i_size);

    /* Check file type */
   /*  if (S_ISREG(i_mode)) {
        bpf_printk("File type: Regular file\n");
    } else if ((i_mode & 0170000) == 0040000) {
        bpf_printk("File type: Directory\n");
    } else if ((i_mode & 0170000) == 0120000) {
        bpf_printk("File type: Symbolic link\n");
    } else if ((i_mode & 0170000) == 0060000) {
        bpf_printk("File type: Block device\n");
    } else if ((i_mode & 0170000) == 0020000) {
        bpf_printk("File type: Character device\n");
    } else if ((i_mode & 0170000) == 0010000) {
        bpf_printk("File type: FIFO/pipe\n");
    } else if ((i_mode & 0170000) == 0140000) {
        bpf_printk("File type: Socket\n");
    } else {
        bpf_printk("File type: Unknown (0%o)\n", i_mode & 0170000);
    }
     */
    /* Get device information */
 /*    dev_t i_sb_s_dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u32 dev_major = i_sb_s_dev >> 20;
    u32 dev_minor = i_sb_s_dev & 0xfffff;
    bpf_printk("Device: %u:%u\n", dev_major, dev_minor);
    */ 
    /* Get file flags */
    // unsigned int f_flags = BPF_CORE_READ(file, f_flags);
/*     
    if (!(f_flags & 0x0200)) {
        return 0;
    }
 */
    /* Decode common file flags */
/*     bpf_printk("f_flags: 0x%x\n", f_flags);
    if (f_flags & 0x0001) bpf_printk("  O_RDONLY/WRONLY\n");
    if (f_flags & 0x0002) bpf_printk("  O_RDWR\n");
    if (f_flags & 0x0100) bpf_printk("  O_CREAT\n");
    if (f_flags & 0x0200) bpf_printk("  O_EXCL\n");
    if (f_flags & 0x0400) bpf_printk("  O_TRUNC\n");
    if (f_flags & 0x0800) bpf_printk("  O_APPEND\n");
    if (f_flags & 0x4000) bpf_printk("  O_DIRECT\n");
    if (f_flags & 0x8000) bpf_printk("  O_LARGEFILE\n");
  */
    /* Get file mode */
    fmode_t f_mode = BPF_CORE_READ(file, f_mode);
    // bpf_printk("File mode: 0x%x\n", f_mode);
    
    /* Only try to hash regular files */
    if (!S_ISREG(i_mode)) {
        return 0;
    }
    
    /* Filter by file mode - skip if not readable */
    if (!(f_mode & 0x00000001)) {  // FMODE_READ
        return 0;
    }
    
    /* Skip if file was opened for writing (likely being modified) */
    if (f_mode & 0x00000002) {  // FMODE_WRITE
        return 0;
    }
    
    /* Skip very small files (likely empty or config files) */
    if (i_size < 4096) {
        return 0;
    }
    
    /* Skip very large files (avoid expensive hashing) */
    if (i_size > 10485) { 
        return 0;
    }
    
    /* Get file scalar value for hashing by reading the pointer value into a u64.
     * This produces a plain scalar register for the verifier (trusted_ptr_file
     * cannot be passed directly). */
    if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) != 0) {
        return 0;
    }
    if (file_scalar == 0) {
        return 0;
    }
     
    bpf_printk("Process: %s (PID: %u, TID: %u)\n", comm, pid, tid);
    bpf_printk("File: %s\n", filepath);
    bpf_printk("File ptr: %p, inode: %lu\n", file, i_ino);
    bpf_printk("Owner UID: %u, GID: %u, Size: %lld bytes\n", i_uid_val, i_gid_val, i_size);
    bpf_printk("File scalar value: %llu (0x%llx)\n", file_scalar, file_scalar);
    
    /* Attempt hash computation using custom file hash function */
    hash_ret = bpf_ima_file_hash_custom(file_scalar, digest, sizeof(digest));
    // 
    if (hash_ret == 0) {
        /* Compact single-line SHA256 hex output using %*ph (length + pointer) */
        bpf_printk("  Hash computation SUCCESS! SHA256: %*ph\n", 32, digest);
    }
    else {
        bpf_printk("  Hash computation FAILED (ret=%d)\n", hash_ret);
        return 0;
    }
    
    int extend_ret = bpf_ima_extend_measurement(event_name, (const char *)digest, sizeof(digest));

    if (extend_ret >= 0) {
        bpf_printk("  IMA measurement extension SUCCESS for event: %s\n", event_name);
    } else {
        bpf_printk("  IMA measurement extension FAILED for event: %s (ret=%d)\n", event_name, extend_ret);
    }
    return 0;
}
