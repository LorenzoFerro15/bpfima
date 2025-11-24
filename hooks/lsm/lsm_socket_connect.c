#include "../hook_utils.h"
#include "../../utils/utils.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define MAX_DATA_BUF_SIZE 64

/* Helper for byte order conversion */
#define bpf_ntohs(x) __builtin_bswap16(x)

/*
 * LSM hook: socket_connect
 * 
 * Socket Connection Monitoring with IMA Measurement Flow:
 * This hook tracks socket connection attempts with the following flow:
 * 
 * 1. Policy Check: Verify if hook is enabled and should process
 * 2. Detection: Extract socket and address information
 * 3. Container Context: Identify container context from cgroup
 * 4. Policy Filter: Check if cgroup should be ignored based on policy
 * 5. Dependencies: Build dependency chain from parent processes (if enabled in policy)
 * 6. Hash Calculation: Compute hash of connection data (source/dest addresses)
 * 7. Measurement Extension: Call bpfima_measurement_extend with connection info
 * 
 * Params:
 * - sock: Pointer to the socket structure
 * - address: Pointer to the sockaddr structure containing remote address
 * - addrlen: Length of the address structure
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

    /* Use first half of scratch buffer for additional data, second half for deps */
    char *deps = scratch->buf;
    int deps_max = 0, deps_actual = 0;
    char cgroup_name[64] = {0};

    if (!address) {
        bpf_printk("bpf_socket_connect: No address provided.\n");
        return 0;
    }

    if (address->sa_family != AF_INET) {
        return 0; /* Not AF_INET (for now, then add IPv6)*/
    }

    if (!bpfima_should_process(HOOK_LSM_SOCKET_CONNECT)) {
        bpf_printk("bpf_socket_connect: Hook processing disabled by policy.\n");
        return 0;
    }

    struct bpfima_policy_config *policy = bpfima_get_policy();
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(HOOK_LSM_SOCKET_CONNECT);
        
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
    struct sock_common sk_common = BPF_CORE_READ(sk, __sk_common);
    u32 saddr = sk_common.skc_rcv_saddr;
    u16 sport = sk_common.skc_num;

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

    /* Build dependencies if enabled in policy */
    if (!policy || (policy->action_flags & POLICY_ACTION_BUILD_DEPS)) {
        deps_actual = build_dependencies(deps, deps_max, comm, cur);
        
        if (!policy || policy->log_level >= 2) {
            bpf_printk(" dependencies: %s\n", deps);
        }
    }

    /* Measure the executable file making the connection */
    char event_name[] = "socket_connect";
    int ret = measure_socket_data(event_name,
                                 cgroup_name,
                                 is_container_context,
                                 deps,
                                 deps_actual,
                                 deps_max,
                                 additional_data,
                                 buffer_len);
    
    if (ret < 0) {
        if (!policy || policy->log_level >= 1) {
            bpf_printk("Socket connection measurement failed: %d\n", ret);
        }
        return ret;
    }

    return 0;
}
