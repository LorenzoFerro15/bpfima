#include "../hook_utils.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * LSM hook: bprm_check_security
 * 
 * Container Lifecycle Tracking with Streamlined Measurement Flow:
 * This hook serves as the primary container event detector with the following flow:
 * 
 * 1. Detection: Extract cgroup information to identify container context
 * 2. Hash Calculation: Compute file hash of the executable via kfunc
 * 3. Dependencies: Build dependency chain from parent processes
 * 4. Measurement Extension: Call bpf_ima_extend_measurement which:
 *    - If namespace_id provided:
 *      5. Directly extends in the namespace/container measurement list
 *      6. Updates the leaf value (container-specific hash)
 *      7. Inserts new leaf value in the Merkle history file
 *      8. Updates the Merkle root value
 *      9. Extends TPM PCR with the new root value
 *    - If namespace_id is NULL:
 *      Uses legacy host-level measurement system
 * 
 * All Merkle tree operations and TPM extension are handled automatically
 * by the bpf_ima_extend_measurement kfunc, simplifying the BPF hook logic.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm)
{
    char comm[16] = {0};
    u64 pid_tgid;
    u32 pid;
    int ret;
    int cgroup_id;
    u32 scratch_key = 0;
    char event_name[64] = {0}; 
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);

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
    bool is_container_context = false;
    if (cgroup_name[0] != '\0') {
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
            bpf_printk("Container context detected: %s\n", cgroup_name);
        }
    }

    const char *fname = BPF_CORE_READ(bprm, filename);
    
    /* Build dependency chain using the modular utility function */
    deps_actual = build_dependencies(deps, deps_max, fname, cur);
    
    __builtin_memcpy(event_name, "bprm_check_security", 20);
    
    bpf_printk(" dependencies: %s\n", deps);

    struct file *file = BPF_CORE_READ(bprm, file);
    ret = measure_accessed_file(file, 
                                  event_name, 
                                  cgroup_name, 
                                  is_container_context,
                                  deps,
                                  deps_actual,
                                  deps_max);
    if (ret < 0) {
        bpf_printk("The file measurement failed: %d\n", ret);
        return ret;
    }
    
    return 0;
}
