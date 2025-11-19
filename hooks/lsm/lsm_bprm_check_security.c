#include "../hook_utils.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * LSM hook: bprm_check_security
 * 
 * Container Lifecycle Tracking with Streamlined Measurement Flow and Policy Enforcement:
 * This hook serves as the primary container event detector with the following flow:
 * 
 * 1. Policy Check: Verify if hook is enabled and should process
 * 2. Detection: Extract cgroup information to identify container context
 * 3. Policy Filter: Check if cgroup/path should be ignored based on policy
 * 4. Hash Calculation: Compute file hash of the executable via kfunc
 * 5. Dependencies: Build dependency chain from parent processes (if enabled in policy)
 * 6. Measurement Extension: Call bpf_ima_extend_measurement which:
 *    - If namespace_id provided:
 *      7. Directly extends in the namespace/container measurement list
 *      8. Updates the leaf value (container-specific hash)
 *      9. Inserts new leaf value in the Merkle history file
 *      10. Updates the Merkle root value
 *      11. Extends TPM PCR with the new root value (if policy allows)
 *    - If namespace_id is NULL:
 *      Uses legacy host-level measurement system
 * 
 * All Merkle tree operations and TPM extension are handled automatically
 * by the bpf_ima_extend_measurement kfunc, with behavior controlled by policy.
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
    
    if (!bprm) {
        return 0;
    }

    if (!bpfima_should_process(HOOK_LSM_BPRM_CHECK_SECURITY)) {
        return 0; 
    }

    struct bpfima_policy_config *policy = bpfima_get_policy();
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(HOOK_LSM_BPRM_CHECK_SECURITY);
    
    if (!policy || !hook_cfg) {
        bpf_printk("Policy not loaded, using default behavior\n");
    }

    if (scratch) {
        deps = scratch->buf;
        deps_max = sizeof(scratch->buf);
    }

    bpf_get_current_comm(comm, sizeof(comm));
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    cgroup_id = bpf_get_current_cgroup_id();
    
    if (!policy || policy->log_level >= 2) {
        bpf_printk("LSM bprm_check_security: %s PID=%u  cgroup_id=%d\n", comm, pid, cgroup_id);
    }

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();

    struct css_set *cgroups = BPF_CORE_READ(cur, cgroups);
    if (cgroups) {
        struct cgroup *dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
        if (dfl) {
            struct kernfs_node *kn = BPF_CORE_READ(dfl, kn);
            if (kn) {
                bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), BPF_CORE_READ(kn, name));
                if (!policy || policy->log_level >= 2) {
                    bpf_printk(" cgroup_name: %s\n", cgroup_name);
                }
            }
        }
    }
    
    bool is_container_context = false;
    if (cgroup_name[0] != '\0') {
        /* Check if this cgroup should be ignored based on policy */
        if (bpfima_should_ignore_cgroup(cgroup_name, policy)) {
            if (!policy || policy->log_level >= 3) {
                bpf_printk("Ignoring cgroup by policy: %s\n", cgroup_name);
            }
            return 0;
        }
        
        /* Check if this is actually a container, not just any cgroup */
        if (!hook_cfg || (hook_cfg->flags & HOOK_FLAG_TRACK_CONTAINERS)) {
            if (bpfima_is_container_cgroup(cgroup_name)) {
                is_container_context = true;
                if (!policy || policy->log_level >= 2) {
                    bpf_printk("Container context detected: %s\n", cgroup_name);
                }
            } else {
                if (!policy || policy->log_level >= 3) {
                    bpf_printk("Non-container cgroup (using host measurement): %s\n", cgroup_name);
                }
            }
        }
    }

    const char *fname = BPF_CORE_READ(bprm, filename);
    
    if (!policy || (policy->action_flags & POLICY_ACTION_BUILD_DEPS)) {
        deps_actual = build_dependencies(deps, deps_max, fname, cur);
        
        if (!policy || policy->log_level >= 2) {
            bpf_printk(" dependencies: %s\n", deps);
        }
    }
    
    __builtin_memcpy(event_name, "bprm_check_security", 20);

    struct file *file = BPF_CORE_READ(bprm, file);
    ret = measure_accessed_file(file, 
                                  event_name, 
                                  cgroup_name, 
                                  is_container_context,
                                  deps,
                                  deps_actual,
                                  deps_max);
    if (ret < 0) {
        if (!policy || policy->log_level >= 1) {
            bpf_printk("The file measurement failed: %d\n", ret);
        }
        return ret;
    }
    
    return 0;
}
