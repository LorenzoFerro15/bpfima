#include "../../utils/headers_bpf.h"
#include "../../utils/utils.h"

/* External kfunc declarations used by hooks */
extern int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len) __ksym;
extern int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size) __ksym;

/* Container tracking kfuncs - Task 5: eBPF Container Event Hook Integration */
extern int bpf_container_create_or_get(const char *container_id) __ksym;
extern int bpf_container_add_measurement(const char *container_id, const char *event_name, const char *event_data, const u8 *digest, u32 digest_size) __ksym;

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
 * 
 * Container Lifecycle Tracking (Task 5):
 * This hook serves as the primary container event detector. It:
 * 1. Extracts cgroup information to identify container context
 * 2. Creates or retrieves container nodes in the kernel module
 * 3. Computes file hash of the executable being launched
 * 4. Adds measurements to the appropriate container's list
 * 5. Triggers Merkle root recalculation and TPM PCR extension
 * 
 * When a process executes within a container (identified by cgroup_name),
 * this hook ensures the container is tracked and all measurements are
 * properly recorded in the container-specific measurement list.
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
    char cgroup_name[64] = {0};
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
                bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), BPF_CORE_READ(kn, name));
                bpf_printk(" cgroup_name: %s\n", cgroup_name);
            }
        }
    }

    /* ===== Task 5: Container Event Tracking =====
     * If we detected a valid cgroup name (potential container identifier),
     * ensure that a container node exists in the kernel tracking system.
     * This acts as a "container start" event detector.
     */
    bool is_container_context = false;
    if (cgroup_name[0] != '\0') {
        /* Filter out common system cgroups to focus on actual containers
         * Containers typically have IDs like:
         * - docker-<hash>
         * - cri-containerd-<hash>
         * - kubepods-<...>
         * - Or custom container runtime identifiers
         */
        const char *ignore_patterns[] = {"/", "init.scope", "system.slice", "user.slice"};
        bool should_track = true;
        
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (__builtin_strcmp(cgroup_name, ignore_patterns[i]) == 0) {
                should_track = false;
                break;
            }
        }
        
        if (should_track) {
            is_container_context = true;
            ret = bpf_container_create_or_get(cgroup_name);
            if (ret == 0) {
                bpf_printk("✓ Container tracking: %s (created or exists)\n", cgroup_name);
            } else {
                bpf_printk("⚠ Failed to track container %s: %d\n", cgroup_name, ret);
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
                char digest_hex[65] = {0};
                
                bpf_printk(" deps_actual=%d deps_max=%d\n", deps_actual, deps_max);

                int written = bytes_to_hex_str(digest, 32, digest_hex, sizeof(digest_hex));
                if (written < 0) {
                    bpf_printk(" failed converting digest to hex string\n");
                }
                if (deps_actual < deps_max) {
                    deps[deps_actual] = '\0';
                } else {
                    deps[deps_max - 1] = '\0';
                }
                digest_hex[64] = '\0';
                
                /* ===== Task 5: Container Measurement Integration =====
                 * Route measurements to the appropriate tracking system:
                 * - If in container context: Add to container-specific list
                 * - Otherwise: Use legacy host-level measurement system
                 * 
                 * This ensures proper Merkle tree leaf updates and TPM PCR extension.
                 */
                if (is_container_context && cgroup_name[0] != '\0') {
                    /* Container-aware measurement using new kfunc */
                    ret = bpf_container_add_measurement(cgroup_name, event_name, deps, digest, sizeof(digest));
                    if (ret == 0) {
                        bpf_printk("✓ Added measurement to container %s: %s\n", cgroup_name, event_name);
                    } else {
                        bpf_printk("⚠ Failed to add container measurement: %d\n", ret);
                        /* Fallback to legacy system */
                        bpf_ima_extend_measurement(event_name, cgroup_name, deps, digest_hex, 64);
                    }
                } else {
                    /* Host-level measurement (legacy system) */
                    bpf_ima_extend_measurement(event_name, cgroup_name, deps, digest_hex, 64);
                }
            }
            else {
                bpf_printk(" failed hashing failed extending found data about it");
            }
        }
    }
    return 0;
}
