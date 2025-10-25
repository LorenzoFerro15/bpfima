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
    char event_name[] = "bprm_file_exec";
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

    struct css_set *cgroups = BPF_CORE_READ(cur, cgroups);
    if (cgroups) {
        struct cgroup *dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
        if (dfl) {
            struct kernfs_node *kn = BPF_CORE_READ(dfl, kn);
            if (kn) {
                char cgroup_name[64] = {0};
                bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), BPF_CORE_READ(kn, name));
                bpf_printk(" cgroup_name: %s\n", cgroup_name);
            }
        }
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
                const int want = 16;
                if (deps_actual <= deps_max - want)
                    avail = want;
                else
                    avail = deps_max - deps_actual;
                ret = bpf_probe_read_kernel_str(&deps[deps_actual], avail, BPF_CORE_READ(ancestor, comm));
                if (ret > 0) {
                    int consumed = ret - 1;
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
    
 
    
    bpf_printk(" dependencies: %s\n", deps);

    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        u64 file_scalar = 0;
        if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) == 0 && file_scalar != 0) {
            ret = bpf_ima_file_hash_custom(file_scalar, digest, sizeof(digest));
            if (ret == 0) {
                print_hex_digest(digest, 32);
                
                bpf_printk(" deps_actual=%d deps_max=%d\n", deps_actual, deps_max);

                if (deps_actual <= deps_max - 65) {
                    int written = bytes_to_hex_str(digest, 32, deps + deps_actual, deps_max - deps_actual);
                    if (written > 0) {
                        deps_actual += written;
                    }
                }
                if (deps_actual < deps_max) {
                    deps[deps_actual] = '\0';
                } else {
                    deps[deps_max - 1] = '\0';
                }
                bpf_ima_extend_measurement(event_name, deps, deps_actual);
            }
            else {
                bpf_printk(" failed hashing failed extending found data about it");
            }
        }
    }
    return 0;
}
