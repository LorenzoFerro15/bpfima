#include "../../utils/headers_bpf.h"
#include "../../utils/utils.h"

/* External kfunc declarations used by hooks */
extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size) __ksym;

char LICENSE[] SEC("license") = "GPL";

/* Per-CPU scratch buffer to avoid large stack allocations and heavy inlining
 * which can blow up the verifier. Value contains a small buffer and a length.
 */
/* Use a larger buffer and keep layout simple (no trailing metadata) so the
 * verifier can reason about map value bounds when we write fixed-size slots.
 */
struct scratch_t {
    /* 10 slots * 17 bytes each (16 char comm + separator) = 170; round up to 192 */
    char buf[192];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_t);
} scratch_buf_map SEC(".maps");

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
    int cgroup_id;
    u32 scratch_key = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);
    /* Fallback to small stack buffer if map lookup fails (shouldn't normally) */
    char stack_dependencies_buf[16] = {0};
    char *deps = stack_dependencies_buf;
    int deps_actual =  0;
    int deps_max = sizeof(stack_dependencies_buf);
    if (scratch) {
        deps = scratch->buf;
        deps_max = sizeof(scratch->buf);
    }
    if (!bprm) {
        return 0;
    }

    bpf_get_current_comm(comm, sizeof(comm));
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    cgroup_id = bpf_get_current_cgroup_id();
    bpf_printk("LSM bprm_check_security: %s PID=%u  cgroup_id=%d\n", comm, pid, cgroup_id);

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    struct task_struct *ancestor = NULL;

    if (cur) {
        ancestor = BPF_CORE_READ(cur, real_parent);
    }

#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (!ancestor)
            break;

        struct task_struct *next = BPF_CORE_READ(ancestor, real_parent);
        if (deps_actual < deps_max) {
            /* compute how many bytes are available and bound the probe-read
             * so the verifier can reason about the map value bounds.
             * We prefer reading up to 16 bytes (comm size) but ensure that
             * when we choose the larger fixed size the sum (deps_actual +
             * want) is <= deps_max. Otherwise fall back to the remaining
             * space (deps_max - deps_actual).
             */
            int avail = deps_max - deps_actual;
            if (avail > 0) {
                const int want = 16; /* max comm we expect to read */
                if (deps_actual <= deps_max - want)
                    avail = want;
                else
                    avail = deps_max - deps_actual;
                int r = bpf_probe_read_kernel_str(&deps[deps_actual], avail, BPF_CORE_READ(ancestor, comm));
                if (r > 0) {
                    int consumed = r - 1;
                    if (consumed < 0)
                        consumed = 0;
                    deps_actual += consumed;
                    if (deps_actual < deps_max) {
                        deps[deps_actual] = ':';
                        deps_actual++;
                    } else {
                        deps[deps_max - 1] = '\0';
                    }
                }
            }
        }

        if (!next || next == ancestor)
            break;

        ancestor = next;
    }

    const char *fname = BPF_CORE_READ(bprm, filename);
    char fname_buf[64] = {0};
    if (fname) {
        bpf_probe_read_kernel_str(fname_buf, sizeof(fname_buf), fname);
        bpf_printk(" filename: %s\n", fname_buf);
    }
    
    deps[deps_actual > 0 ? deps_actual - 1 : 0] = '\0'; 
    
    bpf_printk(" dependencies: %s\n", deps);

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
