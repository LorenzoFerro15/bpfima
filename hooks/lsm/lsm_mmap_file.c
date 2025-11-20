#include "../../utils/headers_bpf.h"
#include "../../utils/bpf_kfunc_defs.h"

#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#endif

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/mmap_file")
int bpf_mmap_file(struct file *file)
{
    u8 digest[32] = {0};
    u64 file_scalar;
    int ret_extension = 0;

    bpf_printk("=== MMAP FILE VIA LSM ===\n");

    if (!file)
    {
        bpf_printk("File pointer is NULL - anonymous mapping\n");
        return 0;
    }

    bpf_printk("File pointer: %p\n", file);

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    bpf_printk("Inode pointer: %p\n", inode);

    if (!inode)
    {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        bpf_printk("Dentry pointer: %p\n", dentry);

        if (dentry)
        {
            char name[16] = {0};
            bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(dentry, d_name.name));
            bpf_printk("File name: %s\n", name);
        }

        bpf_printk("File has NULL inode, trying hash anyway...\n");

        /* Read the file pointer into a u64 scalar so the verifier sees a plain
         * scalar value (trusted_ptr_file can't be passed directly to kfuncs). */
        if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) != 0)
        {
            bpf_printk("Failed to read file pointer\n");
            return 0;
        }

        if (file_scalar == 0)
        {
            bpf_printk("Invalid file scalar (0), skipping\n");
            return 0;
        }

        bpf_printk("File scalar: %llu\n", file_scalar);

        int hash_ret = bpfima_file_hash(file_scalar, digest, sizeof(digest));
        if (hash_ret == 0)
        {
            bpf_printk("SUCCESS! Hash: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                       digest[0], digest[1], digest[2], digest[3],
                       digest[4], digest[5], digest[6], digest[7]);
        }
        else
        {
            bpf_printk("Hash computation failed: %d\n", hash_ret);
        }

        return 0;
    }

    umode_t i_mode = BPF_CORE_READ(inode, i_mode);

    if (!S_ISREG(i_mode))
    {
        bpf_printk("Not a regular file (mode: %o), skipping\n", i_mode);
        return 0;
    }

    unsigned long i_ino = BPF_CORE_READ(inode, i_ino);
    bpf_printk("Valid regular file - inode: %lu, mode: %o\n", i_ino, i_mode);

    bpf_printk("File: %p\n", file);
    bpf_printk("Processing file mapping\n");

    /* Read the file pointer into a u64 scalar so the verifier sees a plain
     * scalar value (trusted_ptr_file can't be passed directly to kfuncs). */
    if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) != 0)
    {
        bpf_printk("Failed to read file pointer\n");
        return 0;
    }

    if (file_scalar == 0)
    {
        bpf_printk("Invalid file scalar (0), skipping\n");
        return 0;
    }

    bpf_printk("File scalar: %llu\n", file_scalar);

    int hash_ret = bpfima_file_hash(file_scalar, digest, sizeof(digest));
    if (hash_ret == 0)
    {
        bpf_printk("Hash: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                   digest[0], digest[1], digest[2], digest[3],
                   digest[4], digest[5], digest[6], digest[7]);

        char event_name[] = "mmap_file";
        ret_extension = bpfima_measurement_extend(event_name, NULL, NULL,
                                                   (const char *)digest, sizeof(digest));
        if (ret_extension >= 0)
        {
            bpf_printk("  IMA measurement extended\n");
        }
        else
        {
            bpf_printk("   IMA measurement extension failed: %d\n", ret_extension);
        }
    }
    else
    {
        bpf_printk("FAILED! Hash computation failed: %d\n", hash_ret);
    }

    return 0;
}