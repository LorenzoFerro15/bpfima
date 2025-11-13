#include "../hook_utils.h"

#define AF_INET 2

/* Helper for byte order conversion */
#define bpf_ntohs(x) __builtin_bswap16(x)

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/socket_connect")
int BPF_PROG(bpf_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    int proto, state;
    u64 pid_tgid, uid_gid;
    u32 pid, uid;
    char comm[16];

    if (!address) {
        bpf_printk("bpf_socket_connect: No address provided.\n");
        return 0;
    }

    if (address->sa_family != AF_INET) {
        return 0; /* Not AF_INET (for now, then add IPv6)*/
    }

    /* Cast to the IPv4-specific struct */
    struct sockaddr_in *address_in = (struct sockaddr_in *)address;

    /* 3. Get the kernel's internal sock struct */
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        bpf_printk("bpf_socket_connect: No sock struct found.\n");
        return 0;
    }

    /* try to read socket->sk */
    state = BPF_CORE_READ(sock, state); /* some kernels store socket state here */
    proto = BPF_CORE_READ(sk, sk_protocol);

    pid_tgid = bpf_get_current_pid_tgid();
    pid = (u32)(pid_tgid >> 32);
    uid_gid = bpf_get_current_uid_gid();
    uid = (u32)(uid_gid & 0xFFFFFFFF);

    bpf_get_current_comm(comm, sizeof(comm));

    /* --- Address Gathering --- */

    /* Get Source Info
     * The source info lives in the 'sk' struct.
     * Note: saddr and sport might be 0 if the socket was not
     * explicitly bound before calling connect().
     */
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    /* Get Destination Info */
    u32 daddr = BPF_CORE_READ(address_in, sin_addr.s_addr);
    u16 dport = BPF_CORE_READ(address_in, sin_port);
    
    /* --- Print the Addresses --- */    
    bpf_printk("\n=== SOCKET CONNECT (LSM) ===");
    bpf_printk("  conn pid=%d uid=%d proto=%d state=%d comm=%s", pid, uid, proto, state, comm);
    
    bpf_printk("  SRC: %d.%d.%d.%d:%u",
                (saddr >> 0) & 0xff,
                (saddr >> 8) & 0xff,
                (saddr >> 16) & 0xff,
                (saddr >> 24) & 0xff,
                sport
            );

    bpf_printk("  DST: %d.%d.%d.%d:%u\n",
                (daddr >> 0) & 0xff,
                (daddr >> 8) & 0xff,
                (daddr >> 16) & 0xff,
                (daddr >> 24) & 0xff,
                bpf_ntohs(dport) /* Convert network to host order for printing */
            );

    return 0;
}
