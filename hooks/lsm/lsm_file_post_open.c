#include "../hook_utils.h"
#include "../../utils/bpf_kfunc_defs.h"

#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#endif

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
    if (!(mask & 0x00000004))
        return 0;
    if (!file)
        return 0;

    char filepath[256] = {0};
    long ret = bpf_d_path((struct path *)&file->f_path, filepath, sizeof(filepath));
    if (ret < 0) {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (!dentry)
            return 0;
        const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
        if (!name_ptr)
            return 0;
        bpf_probe_read_kernel_str(filepath, sizeof(filepath), name_ptr);
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    umode_t i_mode = BPF_CORE_READ(inode, i_mode);
    if (!S_ISREG(i_mode))
        return 0;

    fmode_t f_mode = BPF_CORE_READ(file, f_mode);
    if (!(f_mode & 0x00000001)) // FMODE_READ
        return 0;
    if (f_mode & 0x00000002) // FMODE_WRITE
        return 0;

    loff_t i_size = BPF_CORE_READ(inode, i_size);
    if (i_size < 4096 || i_size > 10485)
        return 0;

    u64 file_scalar = 0;
    if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) != 0 || file_scalar == 0)
        return 0;

    u8 digest[32] = {0};
    char comm[16] = {0};
    bpf_get_current_comm(comm, sizeof(comm));
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    unsigned long i_ino = BPF_CORE_READ(inode, i_ino);
    uid_t i_uid_val = BPF_CORE_READ(inode, i_uid.val);
    gid_t i_gid_val = BPF_CORE_READ(inode, i_gid.val);

    bpf_printk("Process: %s (PID: %u, TID: %u)\n", comm, pid, tid);
    bpf_printk("File: %s\n", filepath);
    bpf_printk("File ptr: %p, inode: %lu\n", file, i_ino);
    bpf_printk("Owner UID: %u, GID: %u, Size: %lld bytes\n", i_uid_val, i_gid_val, i_size);
    bpf_printk("File scalar value: %llu (0x%llx)\n", file_scalar, file_scalar);

    int hash_ret = bpfima_file_hash(file_scalar, digest, sizeof(digest));
    if (hash_ret != 0) {
        bpf_printk("  Hash computation FAILED (ret=%d)\n", hash_ret);
        return 0;
    }

    u32 scratch_key = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);
    if (!scratch)
        return 0;

    char *digest_hex = scratch->digest_hex;
    if (bytes_to_hex_str(digest, 32, digest_hex, sizeof(scratch->digest_hex)) < 0)
        return 0;

    char event_name[] = "file_post_open";
    int extend_ret = bpfima_measurement_extend(event_name, NULL, NULL, digest_hex, 64);
    if (extend_ret >= 0) {
        bpf_printk("  IMA measurement extension SUCCESS for event: %s\n", event_name);
    } else {
        bpf_printk("  IMA measurement extension FAILED for event: %s (ret=%d)\n", event_name, extend_ret);
    }

    return 0;
}
