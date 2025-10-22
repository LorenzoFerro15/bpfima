#include "../../utils/headers_bpf.h"
#include "../../utils/utils.h"

/* External kfunc declarations used by hooks */
extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size) __ksym;

char LICENSE[] SEC("license") = "GPL";

/*
 * LSM hook: bprm_check_security
 * Collects available fields from struct linux_binprm and attempts to
 * compute a SHA256-like 32-byte blob to pass to bpf_ima_extend_measurement.
 * This demonstrates the data available in linux_binprm to callers.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm)
{
    char comm[16] = {0};
    u64 pid_tgid;
    u32 pid;
    u8 digest[32] = {0};
    int ret;

    if (!bprm) {
        return 0;
    }

    bpf_get_current_comm(comm, sizeof(comm));
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    bpf_printk("LSM bprm_check_security: %s PID=%u\n", comm, pid);

    const char *fname = BPF_CORE_READ(bprm, filename);
    char fname_buf[64] = {0};
    if (fname) {
        bpf_probe_read_kernel_str(fname_buf, sizeof(fname_buf), fname);
        bpf_printk(" filename: %s\n", fname_buf);
    }
/* 
    const char *interp = BPF_CORE_READ(bprm, interp);
    char interp_buf[64] = {0};
    if (interp) {
        bpf_probe_read_kernel_str(interp_buf, sizeof(interp_buf), interp);
        bpf_printk(" interp: %s\n", interp_buf);
    } */

    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        u64 file_scalar = 0;
        if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) == 0 && file_scalar != 0) {
            // bpf_printk(" file ptr: %p (scalar=0x%llx)\n", file, file_scalar);
            ret = bpf_ima_file_hash_custom(file_scalar, digest, sizeof(digest));
            if (ret == 0) {
                print_hex_digest(digest, 32);

                char event_name[] = "bprm_file_exec";
                bpf_ima_extend_measurement(event_name, (const char *)digest, sizeof(digest));
                return 0;
            }
            else {
                bpf_printk(" failed hashing failed extending found data about it");
            }
        }
    }

    // in case hash fails record the data about the triggerer 

    int argc = BPF_CORE_READ(bprm, argc);
    kuid_t uid = BPF_CORE_READ(bprm, cred->uid);
    kgid_t gid = BPF_CORE_READ(bprm, cred->gid);

    digest[0] = (u8)(pid & 0xff);
    digest[1] = (u8)((pid >> 8) & 0xff);
    digest[2] = (u8)((pid >> 16) & 0xff);
    digest[3] = (u8)((pid >> 24) & 0xff);

    for (int i = 0; i < 16; i++) {
        if (i < 16)
            digest[4 + i] = comm[i];
        else
            digest[4 + i] = 0;
    }

    digest[20] = (u8)(argc & 0xff);
    digest[21] = (u8)((argc >> 8) & 0xff);
    digest[22] = (u8)((argc >> 16) & 0xff);
    digest[23] = (u8)((argc >> 24) & 0xff);

    digest[24] = (u8)(uid.val & 0xff);
    digest[25] = (u8)((uid.val >> 8) & 0xff);
    digest[26] = (u8)((uid.val >> 16) & 0xff);
    digest[27] = (u8)((uid.val >> 24) & 0xff);

    digest[28] = (u8)(gid.val & 0xff);
    digest[29] = (u8)((gid.val >> 8) & 0xff);
    digest[30] = (u8)((gid.val >> 16) & 0xff);
    digest[31] = (u8)((gid.val >> 24) & 0xff);

    char event_name2[] = "bprm_derived";
    bpf_ima_extend_measurement(event_name2, (const char *)digest, sizeof(digest));

    return 0;
}
