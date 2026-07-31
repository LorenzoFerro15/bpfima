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

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    struct bpfima_policy_config *policy = bpfima_get_policy();
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(HOOK_LSM_SOCKET_CONNECT);

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
        if (bpfima_should_ignore_cgroup(cgroup_name, policy))
            return 0;
        if (!hook_cfg || (hook_cfg->flags & HOOK_FLAG_TRACK_CONTAINERS)) {
            if (bpfima_is_container_cgroup(cgroup_name)) {
                is_container_context = true;
            }
        }
    }

    char *deps = scratch->buf;
    int deps_max = sizeof(scratch->buf);
    int deps_actual = 0;

    u64 start_time_total = bpf_ktime_get_ns();
    u64 start_time_deps = 0, end_time_deps = 0;
    u64 start_time_measure = 0, end_time_measure = 0;
    u64 extend_time = 0;

    if (!policy || (policy->action_flags & POLICY_ACTION_BUILD_DEPS)) {
        start_time_deps = bpf_ktime_get_ns();
        deps_actual = build_dependencies(deps, deps_max, socket_path, cur);
        end_time_deps = bpf_ktime_get_ns();
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

    start_time_measure = bpf_ktime_get_ns();
    int ret = measure_socket_data(&smctx);
    end_time_measure = bpf_ktime_get_ns();

    if (ret < 0)
        return ret;

    u64 end_time_total = bpf_ktime_get_ns();
    u32 stats_key = TIMING_SOCKET;
    struct hook_timing *timing = bpf_map_lookup_elem(&bpf_timing_stats, &stats_key);
    if (timing) {
        __sync_fetch_and_add(&timing->count, 1);
        __sync_fetch_and_add(&timing->total_time, end_time_total - start_time_total);
        if (end_time_deps > start_time_deps)
            __sync_fetch_and_add(&timing->deps_time, end_time_deps - start_time_deps);
        if (end_time_measure > start_time_measure)
            __sync_fetch_and_add(&timing->measure_time, end_time_measure - start_time_measure);
        __sync_fetch_and_add(&timing->extend_time, extend_time);
    }

    return 0;
}
