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
    if (!address)
        return 0;
    if (address->sa_family != AF_INET && address->sa_family != AF_UNIX)
        return 0;
    if (!bpfima_should_process(HOOK_LSM_SOCKET_CONNECT))
        return 0;

    u32 scratch_key = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);
    if (!scratch)
        return 0;

    u64 total_time = 0, deps_time = 0;
    u64 get_config_time = 0, filtering_time = 0, measure_time = 0;
    u64 extend_time = 0;

    total_time = bpf_ktime_get_ns();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    get_config_time =  bpf_ktime_get_ns();
    struct bpfima_policy_config *policy = bpfima_get_policy();
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(HOOK_LSM_SOCKET_CONNECT);
    get_config_time = bpf_ktime_get_ns() - get_config_time;

    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct sockaddr_in *address_in = (struct sockaddr_in *)address;
    u32 daddr = BPF_CORE_READ(address_in, sin_addr.s_addr);
    u16 dport = BPF_CORE_READ(address_in, sin_port);

    char additional_data[MAX_DATA_BUF_SIZE] = {0};
    struct socket_addr_info addr_info = {
        .additional_data = additional_data,
        .buf_size = MAX_DATA_BUF_SIZE,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = bpf_ntohs(dport),
    };
    long len = build_socket_additional_data(&addr_info);

    int buffer_len = 0;
    if (len > 0) {
        buffer_len = (len >= MAX_DATA_BUF_SIZE) ? (MAX_DATA_BUF_SIZE - 1) : len;
        additional_data[buffer_len] = '\0';
    }

    char socket_path[MAX_PATH_LEN] = {0};
    if (address->sa_family == AF_INET) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        if (!task)
            return 0;
        struct file *exe_file = bpf_get_task_exe_file(task);
        if (!exe_file)
            return 0;
        bpf_d_path((struct path *)&exe_file->f_path, socket_path, sizeof(socket_path));
        bpf_put_file(exe_file);
    } else if (address->sa_family == AF_UNIX) {
        struct sockaddr_un *un_addr = (struct sockaddr_un *)address;
        int path_len = (addrlen - sizeof(unsigned short)) & PATH_LEN_MASK;
        if (path_len > 0 && path_len < sizeof(socket_path)) {
            bpf_probe_read_kernel(socket_path, path_len, un_addr->sun_path);
            socket_path[path_len] = '\0';
        }
    }

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    char cgroup_name[64] = {0};
    fetch_cgroup_name(cur, cgroup_name, sizeof(cgroup_name));

    bool is_container_context = false;
    if (cgroup_name[0] != '\0') {
        /* Check if this cgroup should be ignored based on policy */
        filtering_time = bpf_ktime_get_ns();
        if (bpfima_should_ignore_cgroup(cgroup_name, policy))
            return 0;
        filtering_time = bpf_ktime_get_ns() - filtering_time;

        /* Check if this is actually a container, not just any cgroup */
        if (!hook_cfg || (hook_cfg->flags & HOOK_FLAG_TRACK_CONTAINERS)) {
            if (bpfima_is_container_cgroup(cgroup_name)) {
                is_container_context = true;
            }
        }
    }

    char *deps = scratch->buf;
    int deps_max = sizeof(scratch->buf);
    int deps_actual = 0;

    if (!policy || (policy->action_flags & POLICY_ACTION_BUILD_DEPS)) {
        deps_time = bpf_ktime_get_ns();
        deps_actual = build_dependencies(deps, deps_max, socket_path, cur);
        deps_time = bpf_ktime_get_ns() - deps_time;
    }

    char event_name[] = "socket_connect";
    struct socket_measure_ctx smctx = {
        .event_name = event_name,
        .cgroup_name = cgroup_name,
        .is_container_context = is_container_context,
        .deps = deps,
        .deps_actual = deps_actual,
        .deps_max = deps_max,
        .additional_data = additional_data,
        .additional_data_len = buffer_len,
        .extend_duration = &extend_time,
    };

    measure_time = bpf_ktime_get_ns();
    int ret = measure_socket_data(&smctx);
    measure_time = bpf_ktime_get_ns() - measure_time;

    if (ret < 0)
        return ret;


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

    return 0;
}
