#include "../hook_utils.h"
#include "../../utils/bpf_kfunc_defs.h"

#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#endif

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/mmap_file")
int BPF_PROG(bpf_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int previous_ret)
{
    if (previous_ret != 0)
        return previous_ret;

    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
        umode_t i_mode = BPF_CORE_READ(inode, i_mode);
        if (!S_ISREG(i_mode))
            return 0;
    }

    u8 digest[32] = {0};
    long hash_algo = bpf_ima_file_hash(file, digest, sizeof(digest));
    if (hash_algo != HASH_ALGO_SHA256) {
        bpf_printk("IMA hash failed or is not SHA-256: %ld\n", hash_algo);
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
    struct measurement_ctx measurement = {
        .event_name = event_name,
        .additional_data = digest_hex,
        .additional_data_len = 64,
    };
    int ret_extension = bpfima_submit_measurement(&measurement);
    if (ret_extension >= 0) {
        bpf_printk("  IMA measurement extended\n");
    } else {
        bpf_printk("   IMA measurement extension failed: %d\n", ret_extension);
    }

    return 0;
}
