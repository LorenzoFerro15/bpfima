#include "../hook_utils.h"
#include "../../utils/utils.h"

char LICENSE[] SEC("license") = "GPL";

/* Helper for byte order conversion */
#define bpf_ntohs(x) __builtin_bswap16(x)

/*
 * LSM hook: socket_connect
 * 
 * Socket Connection Monitoring with IMA Measurement Flow
 * 
 * @param sock: Pointer to the socket structure
 * @param address: Pointer to the sockaddr structure containing remote address
 * @param addrlen: Length of the address structure
 */
SEC("lsm/socket_connect")
int BPF_PROG(bpf_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    char comm[16] = {0};
    u32 scratch_key = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);
    if (!scratch) {
        bpf_printk("bpf_socket_connect: Failed to get scratch buffer.\n");
        return 0;
    }

    u64 total_time = 0, deps_time = 0;
    u64 get_config_time = 0, filtering_time = 0, measure_time = 0;
    u64 extend_time = 0;

    total_time = bpf_ktime_get_ns();

    char *deps = scratch->buf;
    char cgroup_name[64] = {0};
    int deps_max = sizeof(scratch->buf), deps_actual = 0;

    if (!address) {
        bpf_printk("bpf_socket_connect: No address provided.\n");
        return 0;
    }

    if (address->sa_family != AF_INET && address->sa_family != AF_UNIX) {
        return 0;
    }

    if (!bpfima_should_process(HOOK_LSM_SOCKET_CONNECT)) {
        bpf_printk("bpf_socket_connect: Hook processing disabled by policy.\n");
        return 0;
    }

    get_config_time =  bpf_ktime_get_ns();
    struct bpfima_policy_config *policy = bpfima_get_policy();
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(HOOK_LSM_SOCKET_CONNECT);
    get_config_time =  bpf_ktime_get_ns() - get_config_time;

    if (!policy || !hook_cfg) {
        bpf_printk("Policy not loaded, using default behavior\n");
    }

    bpf_get_current_comm(comm, sizeof(comm));

    if (!policy || policy->log_level >= 2) {
        bpf_printk("\n=== SOCKET CONNECT (LSM) ===");
        bpf_printk("Process: %s\n", comm);
    }

    /* --------- Address Gathering --------- */

    /* Get Source Info
     * The source info lives in the 'sk' struct.
     * Note: saddr and sport might be 0 if the socket was not
     * bound before calling connect().
     */
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        bpf_printk("bpf_socket_connect: No struct sock found.\n");
        return 0;
    }

    // Get source info
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // Get destination info
    struct sockaddr_in *address_in = (struct sockaddr_in *)address;
    u32 daddr = BPF_CORE_READ(address_in, sin_addr.s_addr);
    u16 dport = BPF_CORE_READ(address_in, sin_port);

    /*
     * Local stack buffer for the additional data string. 
     * Max IPv4 format length is 15 chars, so 64 is safe.
     */
    char additional_data[MAX_DATA_BUF_SIZE] = {0};
    long len = build_socket_additional_data(additional_data, MAX_DATA_BUF_SIZE,
                                            saddr, sport,
                                            daddr, bpf_ntohs(dport));

    int buffer_len = 0;
    if (len > 0) {
        /* Ensure we clamp to buffer size just in case */
        if (len >= MAX_DATA_BUF_SIZE) {
            buffer_len = MAX_DATA_BUF_SIZE - 1;
        } else {
            buffer_len = len;
        }
        /* Ensure null termination */
        additional_data[buffer_len] = '\0'; 
    }

    /* Log the connection for debugging */
    if (!policy || policy->log_level >= 2) {
        bpf_printk("  Additional data (%ld chars): %s\n", buffer_len, additional_data);
    }

    /* --------- Getting dependencies info --------- */
    char socket_path[MAX_PATH_LEN] = {0};    // For UNIX socket path the max is 108 chars

    if (address->sa_family == AF_INET) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        if (!task) {
            bpf_printk("bpf_socket_connect: Failed to get current task.\n");
            return 0;
        }

        // 
        struct file *exe_file = bpf_get_task_exe_file(task);
        if (!exe_file) return 0;

        len = bpf_d_path((struct path *)&exe_file->f_path, socket_path, sizeof(socket_path));
        if (!policy || policy->log_level >= 2) {
            bpf_printk("INET Connect Target: %s\n", socket_path);
        }

        bpf_put_file(exe_file);
    } else if (address->sa_family == AF_UNIX) { // AF_UNIX
        struct sockaddr_un *un_addr = (struct sockaddr_un *)address;

        /* Read the path from the address structure */
        /* Note:
         *    - first 2 bytes are the address family ID (sun_family field, type: unsigned short)
         *    - 0x7F mask to get an upper bound on path length, so the verifier does not complain
         */
        int path_len = (addrlen - sizeof(unsigned short)) & PATH_LEN_MASK;
        if (path_len > 0 && path_len < sizeof(socket_path)) {
            bpf_probe_read_kernel(socket_path, path_len, un_addr->sun_path);
            socket_path[path_len] = '\0';
            
            if (!policy || policy->log_level >= 2) {
                bpf_printk("UNIX Connect Target: %s\n", socket_path);
            }
        }
    } else {
        bpf_printk("bpf_socket_connect: Unsupported address family: %d\n", address->sa_family);
        return 0;
    }

    /* Get container context */
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
    } else {
        if (!policy || policy->log_level >= 2) {
            bpf_printk(" No cgroups found for current task.\n");
        }
    }

    bool is_container_context = false;
    if (cgroup_name[0] != '\0') {
        /* Check if this cgroup should be ignored based on policy */
        filtering_time = bpf_ktime_get_ns();
        if (bpfima_should_ignore_cgroup(cgroup_name, policy)) {
            if (!policy || policy->log_level >= 3) {
                bpf_printk("Ignoring cgroup by policy: %s\n", cgroup_name);
            }
            return 0;
        }
        filtering_time = bpf_ktime_get_ns() - filtering_time;

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

    /* Build dependencies if enabled in policy */
    if (!policy || (policy->action_flags & POLICY_ACTION_BUILD_DEPS)) {
        deps_time = bpf_ktime_get_ns();
        deps_actual = build_dependencies(deps, deps_max, socket_path, cur);
        deps_time = bpf_ktime_get_ns() - deps_time;

        if (!policy || policy->log_level >= 2) {
            bpf_printk(" dependencies -> %s\n", deps);
        }
    }

    /* Measure the executable file making the connection */
    char event_name[] = "socket_connect";
    measure_time = bpf_ktime_get_ns();
    int ret = measure_socket_data(event_name,
                                 cgroup_name,
                                 is_container_context,
                                 deps,
                                 deps_actual,
                                 deps_max,
                                 additional_data,
                                 buffer_len,
                                 &extend_time);
    measure_time = bpf_ktime_get_ns() - measure_time;

    if (ret < 0) {
        if (!policy || policy->log_level >= 1) {
            bpf_printk("Socket connection measurement failed: %d\n", ret);
        }
        return ret;
    }


    total_time = bpf_ktime_get_ns() - total_time;

    u32 stats_key = TIMING_SOCKET;
    u64 *count = bpf_map_lookup_elem(&bpf_timing_stats_count, &stats_key);
    if (count) {
        u64 current_index =__sync_fetch_and_add(count, 1);
        if (current_index < TIMING_MAX_ENTRIES) {
            u32 index_key = (u32)current_index;
            struct hook_timing *timing = bpf_map_lookup_elem(&bpf_timing_stats_socket, &index_key);
            if (timing) {
            __sync_fetch_and_add(&timing->total_time, total_time);
            if (deps_time > 0)
                __sync_fetch_and_add(&timing->deps_time, deps_time);
            if (measure_time > 0)
                __sync_fetch_and_add(&timing->measure_time, measure_time);
            __sync_fetch_and_add(&timing->extend_time, extend_time);
            __sync_fetch_and_add(&timing->get_config_time, get_config_time);
            __sync_fetch_and_add(&timing->filtering_time, filtering_time);

            if (address->sa_family == AF_INET) {
                __builtin_memcpy(timing->binary_name, additional_data, TIMING_MAX_BUF);
            } else if (address->sa_family == AF_UNIX) {
                __builtin_memcpy(timing->binary_name, socket_path, TIMING_MAX_BUF);
            }
            // Ensure null termination if the string was cut
            timing->binary_name[TIMING_MAX_BUF - 1] = '\0';
            }
        }
    }

    bpf_printk("SOCKET: total=%llu deps=%llu measure=%llu extend=%llu get_config=%llu filtering_cgroups=%llu\n",
               total_time,
               (deps_time > 0) ? (deps_time) : 0,
               (measure_time > 0) ? (measure_time) : 0,
               extend_time, get_config_time, filtering_time
            );

    return 0;
}
