#include "../hook_utils.h"
#include "../../utils/bpf_kfunc_defs.h"

#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#endif

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/mmap_file")
int BPF_PROG(bpf_mmap_file, struct file *file)
{
    if (!file)
        return 0;

    u64 file_scalar = 0;
    if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) != 0 || file_scalar == 0)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
        umode_t i_mode = BPF_CORE_READ(inode, i_mode);
        if (!S_ISREG(i_mode))
            return 0;
    }

    u8 digest[32] = {0};
    int hash_ret = bpfima_file_hash(file_scalar, digest, sizeof(digest));
    if (hash_ret != 0) {
        bpf_printk("FAILED! Hash computation failed: %d\n", hash_ret);
        return 0;
    }

    u32 scratch_key = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);
    if (!scratch)
        return 0;

    char *digest_hex = scratch->digest_hex;
    if (bytes_to_hex_str(digest, 32, digest_hex, sizeof(scratch->digest_hex)) < 0)
        return 0;

    char event_name[] = "mmap_file";
    int ret_extension = bpfima_measurement_extend(event_name, NULL, NULL, digest_hex, 64);
    if (ret_extension >= 0) {
        bpf_printk("  IMA measurement extended\n");
    } else {
        bpf_printk("   IMA measurement extension failed: %d\n", ret_extension);
    }

    return 0;
}