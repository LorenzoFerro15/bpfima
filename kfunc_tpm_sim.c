/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* TPM simulation counters using BPF maps */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10);
} tpm_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, char[64]);
    __uint(max_entries, 1);
} tpm_pcr_value SEC(".maps");

/* Monitor file unlink operations with TPM simulation */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat_tpm_sim(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    u32 gid = uid_gid >> 32;
    char comm[16];
    u64 ts = bpf_ktime_get_ns();
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("=== TPM SIM FILE UNLINK DETECTED ===\n");
    bpf_printk("Process: pid=%d uid=%d gid=%d comm=%s\n", pid, uid, gid, comm);
    bpf_printk("Timestamp: %llu ns\n", ts);
    
    /* Check TPM availability (simulation) */
    u32 tpm_key = 0;
    u64 *tpm_counter = bpf_map_lookup_elem(&tpm_counters, &tpm_key);
    if (!tpm_counter) {
        bpf_printk("TPM Available: NO (simulation mode)\n");
        u64 initial_count = 0;
        bpf_map_update_elem(&tpm_counters, &tpm_key, &initial_count, BPF_ANY);
        tpm_counter = &initial_count;
    } else {
        bpf_printk("TPM Available: YES (simulated)\n");
    }
    
    /* Build measurement data */
    char measurement_data[128] = {0};
    char *ptr = measurement_data;
    int len = 0;
    
    /* Add process information to measurement */
    for (int i = 0; i < 16 && comm[i] != 0 && len < 100; i++) {
        *ptr++ = comm[i];
        len++;
    }
    
    if (len < 120) {
        *ptr++ = '_';
        len++;
        
        /* Add PID (simplified) */
        u32 temp_pid = pid % 10000;  // Keep it small for simplicity
        if (temp_pid < 10) {
            *ptr++ = '0' + temp_pid;
            len++;
        } else if (temp_pid < 100) {
            *ptr++ = '0' + (temp_pid / 10);
            *ptr++ = '0' + (temp_pid % 10);
            len += 2;
        } else if (temp_pid < 1000) {
            *ptr++ = '0' + (temp_pid / 100);
            *ptr++ = '0' + ((temp_pid / 10) % 10);
            *ptr++ = '0' + (temp_pid % 10);
            len += 3;
        }
    }
    
    *ptr = '\0';
    
    bpf_printk("TPM Measurement data: %s (len=%d)\n", measurement_data, len);
    
    /* Simulate TPM PCR extend */
    if (tpm_counter) {
        u64 new_count = *tpm_counter + 1;
        bpf_map_update_elem(&tpm_counters, &tpm_key, &new_count, BPF_ANY);
        bpf_printk("TPM PCR extend simulation: count=%llu\n", new_count);
        
        /* Simulate PCR value update */
        char pcr_sim[64];
        __builtin_memset(pcr_sim, 0, sizeof(pcr_sim));
        
        /* Create a simple hash-like representation */
        pcr_sim[0] = 'P'; pcr_sim[1] = 'C'; pcr_sim[2] = 'R'; pcr_sim[3] = '1'; pcr_sim[4] = '0';
        pcr_sim[5] = '_'; pcr_sim[6] = 'C'; pcr_sim[7] = 'N'; pcr_sim[8] = 'T'; pcr_sim[9] = '_';
        
        /* Add count in hex-like format */
        u64 count_val = new_count;
        for (int i = 10; i < 20 && i < 63; i++) {
            u32 digit = count_val % 16;
            pcr_sim[i] = (digit < 10) ? ('0' + digit) : ('A' + digit - 10);
            count_val /= 16;
        }
        
        u32 pcr_key = 0;
        bpf_map_update_elem(&tpm_pcr_value, &pcr_key, pcr_sim, BPF_ANY);
        
        bpf_printk("TPM PCR Value: %s\n", pcr_sim);
    }
    
    bpf_printk("TPM-simulated measurement completed\n");
    
    return 0;
}

/* VFS layer monitoring with TPM simulation */
SEC("kprobe/vfs_unlink")
int handle_vfs_unlink_tpm_sim(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("VFS_UNLINK_TPM_SIM: pid=%d comm=%s\n", pid, comm);
    
    /* Quick TPM simulation status */
    u32 tpm_key = 0;
    u64 *tpm_counter = bpf_map_lookup_elem(&tpm_counters, &tpm_key);
    if (tpm_counter) {
        bpf_printk("TPM Status: READY (count=%llu)\n", *tpm_counter);
    } else {
        bpf_printk("TPM Status: INITIALIZING\n");
    }
    
    return 0;
}