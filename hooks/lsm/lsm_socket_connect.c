#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;
extern int bpf_tpm_is_available(void) __ksym;

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/socket_connect")
int bpf_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct sock *sk = NULL;
    int state;
    int proto;
    int family;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u64 pid_tgid;
    u32 pid;
    u64 uid_gid;
    u32 uid;
    char comm[16];

    bpf_printk("=== SOCKET CONNECT VIA LSM ===\n");

    if (!sock)
    {
        bpf_printk("Socket pointer is NULL\n");
        return 0;
    }

    /* try to read socket->sk (protocol core struct) */
    sk = BPF_CORE_READ(sock, sk);
    state = BPF_CORE_READ(sock, state); /* some kernels store socket state here */
    bpf_printk("socket->state (raw): %d\n", state);

    if (!sk)
    {
        bpf_printk("sk is NULL\n");
        /* still emit an IMA measurement if you want */
        char event_name[] = "socket_connect_lsm_no_socket";
        char random_data[] = "socket_connect_no_socket_42";
        int ret = bpf_ima_extend_measurement(event_name, random_data, sizeof(random_data));
        bpf_printk("IMA measurement result (no socket): %d\n", ret);
        return 0;
    }

    /* Basic socket/core fields */
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    proto = BPF_CORE_READ(sk, sk_protocol); /* protocol number, e.g. IPPROTO_TCP */
    state = BPF_CORE_READ(sk, __sk_common.skc_state);

    /* IPv4 addresses & ports (most common case) */
    if (family == AF_INET)
    {
        /* local port */
        sport = (u16)BPF_CORE_READ(sk, __sk_common.skc_num);
        /* remote port is stored in network order -> convert to host order */
        dport = (u16)BPF_CORE_READ(sk, __sk_common.skc_dport);
        dport = bpf_ntohs(dport);

        /* addresses are stored as 32-bit integers */
        saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        pid_tgid = bpf_get_current_pid_tgid();
        pid = (u32)(pid_tgid >> 32);
        uid_gid = bpf_get_current_uid_gid();
        uid = (u32)(uid_gid & 0xFFFFFFFF);

        bpf_get_current_comm(comm, sizeof(comm));

        bpf_printk("conn pid=%d uid=%d proto=%d state=%d\n", pid, uid, proto, state);
        bpf_printk("local %pI4:%d -> remote %pI4:%d\n", &saddr, sport, &daddr, dport);
        bpf_printk("comm=%s\n", comm);
    }
    else
    {
        /* IPv6 or other families: log family/proto/state and skip detailed addr extraction */
        pid_tgid = bpf_get_current_pid_tgid();
        pid = (u32)(pid_tgid >> 32);
        uid_gid = bpf_get_current_uid_gid();
        uid = (u32)(uid_gid & 0xFFFFFFFF);
        bpf_get_current_comm(comm, sizeof(comm));

        bpf_printk("conn (non-IPv4) pid=%d uid=%d family=%d proto=%d state=%d comm=%s\n",
                   pid, uid, family, proto, state, comm);

        /* OPTIONAL: attempt IPv6 extraction (careful with verifier / field names per kernel)
           Example (may need tuning per kernel's vmlinux.h):
           unsigned int v6_0 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
           ...
         */
    }

    {
        char event_name[] = "socket_connect_lsm_event";
        char random_data[] = "socket_connect_seen_42";
        int ret = bpf_ima_extend_measurement(event_name, random_data, sizeof(random_data));
        bpf_printk("IMA measurement result: %d\n", ret);
    }

    return 0;
}
