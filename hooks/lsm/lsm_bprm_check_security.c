#include "../hook_utils.h"
#include "../../include/bpfima_event.h"



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
 * 6. Measurement Extension: Call bpfima_measurement_extend which:
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
 * by the bpfima_measurement_extend kfunc, with behavior controlled by policy.
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

    u64 start_time_total = 0, end_time_total = 0;
    u64 start_time_deps = 0, end_time_deps = 0;

    u64 start_time_measure = 0, end_time_measure = 0;
    u64 hash_time = 0, extend_time = 0;

    start_time_total = bpf_ktime_get_ns();

    char stack_dependencies_buf[16] = {0};
    char *deps = stack_dependencies_buf;
    int deps_actual =  0;
    int deps_max = sizeof(stack_dependencies_buf);
    char cgroup_name[64] = {0};
    
    struct css_set *cgroups;
    struct cgroup *dfl;
    struct kernfs_node *kn;

    if (!bprm) {
        return 0;
    }

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    

    /* Initialize scratch buffers early for debug */
    bpf_get_current_comm(comm, sizeof(comm));
    u32 pid_val = bpf_get_current_pid_tgid() >> 32;
    char filename_debug[64] = {0};
    bpf_probe_read_kernel_str(filename_debug, sizeof(filename_debug), bprm->filename);
    
    /* UNCONDITIONAL DEBUG */
    bpf_printk("Check: PID=%u comm=%s file=%s\n", pid_val, comm, filename_debug);

    if (!bpfima_should_process(HOOK_LSM_BPRM_CHECK_SECURITY)) {
        return 0; 
    }


    
    /* Get cgroup name first to determine policy context */
    cgroups = BPF_CORE_READ(cur, cgroups);
    if (cgroups) {
        dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
        if (dfl) {
            kn = BPF_CORE_READ(dfl, kn);
            if (kn) {
                bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), BPF_CORE_READ(kn, name));
            }
        }
    }

    struct bpfima_policy_config *policy = NULL;
    struct bpfima_policy_config ns_policy = {0}; /* Stack allocation for namespace policy */
    
    /* Try to get namespace-specific policy first */
    if (cgroup_name[0] != '\0') {
        if (bpfima_policy_namespace_get_config(cgroup_name, &ns_policy) == 0) {
            policy = &ns_policy;
            /* Debug print if needed implies policy was found */
        }
    }

    /* Fallback to global policy if no namespace policy found */
    if (!policy) {
        policy = bpfima_get_policy();
    }

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
        if (cgroup_name[0] != '\0') {
            bpf_printk(" cgroup_name: %s\n", cgroup_name);
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
        start_time_deps = bpf_ktime_get_ns();
        deps_actual = build_dependencies(deps, deps_max, fname, cur);
        end_time_deps = bpf_ktime_get_ns();
        
        if (!policy || policy->log_level >= 2) {
            bpf_printk(" dependencies: %s\n", deps);
        }
    }
    
    __builtin_memcpy(event_name, "bprm_check_security", 20);

    struct file *file = BPF_CORE_READ(bprm, file);
    u8 hash[32] = {0};
    
    start_time_measure = bpf_ktime_get_ns();
    ret = measure_accessed_file(file, 
                                  event_name, 
                                  cgroup_name, 
                                  is_container_context,
                                  deps,
                                  deps_actual,
                                  deps_max,
                                  hash,
                                  &hash_time,
                                  &extend_time);
    end_time_measure = bpf_ktime_get_ns();
    if (ret < 0) {
        if (!policy || policy->log_level >= 1) {
            bpf_printk("The file measurement failed: %d\n", ret);
        }
        return ret;
    }
    


    end_time_total = bpf_ktime_get_ns();

    u32 stats_key = TIMING_BPRM;
    struct hook_timing *timing = bpf_map_lookup_elem(&bpf_timing_stats, &stats_key);
    if (timing) {
        __sync_fetch_and_add(&timing->count, 1);
        __sync_fetch_and_add(&timing->total_time, end_time_total - start_time_total);
        if (end_time_deps > start_time_deps)
            __sync_fetch_and_add(&timing->deps_time, end_time_deps - start_time_deps);
        if (end_time_measure > start_time_measure)
            __sync_fetch_and_add(&timing->measure_time, end_time_measure - start_time_measure);
        __sync_fetch_and_add(&timing->hash_time, hash_time);
        __sync_fetch_and_add(&timing->extend_time, extend_time);
    }

    bpf_printk("BPRM: total=%llu deps=%llu measure=%llu hash=%llu extend=%llu\n", 
               end_time_total - start_time_total,
               (end_time_deps > start_time_deps) ? (end_time_deps - start_time_deps) : 0,
               (end_time_measure > start_time_measure) ? (end_time_measure - start_time_measure) : 0,
               hash_time, extend_time);

    return 0;
}
