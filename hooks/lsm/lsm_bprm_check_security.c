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
SEC("lsm.s/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int previous_ret)
{
    if (previous_ret != 0)
        return previous_ret;

    if (!bprm)
        return 0;

    u64 total_time = 0, deps_time = 0;
    u64 get_config_time = 0, filtering_time = 0, measure_time = 0;
    u64 hash_time = 0, extend_time = 0;

    total_time = bpf_ktime_get_ns();

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    char comm[16] = {0};
    bpf_get_current_comm(comm, sizeof(comm));

    const char *debug_fname = BPF_CORE_READ(bprm, filename);

    get_config_time = bpf_ktime_get_ns();
    struct file *policy_file = bprm->file;
    if (!policy_file)
        return 0;
    struct inode *policy_inode = BPF_CORE_READ(policy_file, f_inode);
    u64 size = policy_inode ? BPF_CORE_READ(policy_inode, i_size) : 0;
    int decision = bpfima_policy_for_hook(HOOK_LSM_BPRM_CHECK_SECURITY, debug_fname, size,
                                         BPFIMA_POLICY_FILE | BPFIMA_POLICY_READONLY | BPFIMA_POLICY_EXECUTABLE);
    if (decision)
        return decision < 0 ? decision : 0;
    struct bpfima_policy_config *policy = bpfima_get_policy();
    const char *cgroup_name = bpfima_current_namespace();
    bool is_container_context = true;
    get_config_time = bpf_ktime_get_ns() - get_config_time;

    /* The path of bprm->file, the measured file: the hook runs again for the
     * interpreter of a script, with the same filename but the interpreter as
     * file and interp. interp is the filename for the executable itself. */
    const char *fname = BPF_CORE_READ(bprm, interp);
    char event_name[32] = "bprm_check_security";
    u8 hash[32] = {0};

    /* Keep the verifier-tracked file pointer at the sleepable LSM call site. */
    struct file *file = bprm->file;
    if (!file)
        return 0;

    u64 hash_start = bpf_ktime_get_ns();
    long hash_algo = bpf_ima_file_hash(file, hash, sizeof(hash));
    hash_time = bpf_ktime_get_ns() - hash_start;
    if (hash_algo != HASH_ALGO_SHA256) {
        bpf_printk("IMA file hash failed or is not SHA-256: %ld\n", hash_algo);
        return 0;
    }

    struct file_measure_ctx mctx = {
        .digest = hash,
        .event_name = event_name,
        .cgroup_name = cgroup_name,
        .is_container_context = is_container_context,
        .fname = fname,
        .cur = cur,
        .policy = policy,
        .extend_duration = &extend_time,
        .deps_duration = &deps_time,
    };

    measure_time = bpf_ktime_get_ns();
    int ret = measure_accessed_file(&mctx);
    measure_time = bpf_ktime_get_ns() - measure_time;

    if (ret < 0) {
        if (!policy || policy->log_level >= 1) {
            bpf_printk("The file measurement failed: %d\n", ret);
        }
        return ret;
    }

    total_time = bpf_ktime_get_ns() - total_time;

    u32 stats_key = TIMING_BPRM;
    u64 *count = bpf_map_lookup_elem(&bpf_timing_stats_count, &stats_key);
    if (count) {
        u64 current_index =__sync_fetch_and_add(count, 1);
        if (current_index < TIMING_MAX_ENTRIES) {
            u32 index_key = (u32)current_index;
            struct hook_timing *timing = bpf_map_lookup_elem(&bpf_timing_stats_bprm, &index_key);
            if (timing) {
                __sync_fetch_and_add(&timing->total_time, total_time);
                if (deps_time > 0)
                    __sync_fetch_and_add(&timing->deps_time, deps_time);
                if (measure_time > 0)
                    __sync_fetch_and_add(&timing->measure_time, measure_time);
                __sync_fetch_and_add(&timing->hash_time, hash_time);
                __sync_fetch_and_add(&timing->extend_time, extend_time);
                __sync_fetch_and_add(&timing->get_config_time, get_config_time);
                __sync_fetch_and_add(&timing->filtering_time, filtering_time);
                bpf_probe_read_kernel_str(timing->binary_name, TIMING_MAX_BUF, bprm->filename);
                // Ensure null termination if the string was cut
                timing->binary_name[TIMING_MAX_BUF - 1] = '\0';
            }
        }
    }

    bpf_printk("BPRM: total=%llu deps=%llu measure=%llu hash=%llu extend=%llu get_config=%llu filtering_cgroups=%llu\n",
               total_time,
               (deps_time > 0) ? (deps_time) : 0,
               (measure_time > 0) ? (measure_time) : 0,
               hash_time, extend_time, get_config_time, filtering_time
            );

    return 0;
}
