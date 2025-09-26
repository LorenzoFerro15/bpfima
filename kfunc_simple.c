/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;
typedef long long s64;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Monitor file unlink operations and collect contextual information */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    u32 gid = uid_gid >> 32;
    char comm[16];
    u64 ts = bpf_ktime_get_ns();
    u64 cgroup = bpf_get_current_cgroup_id();
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("=== FILE UNLINK DETECTED ===\n");
    bpf_printk("Process: pid=%d uid=%d gid=%d comm=%s\n", pid, uid, gid, comm);
    bpf_printk("Timestamp: %llu ns\n", ts);
    
    char measurement_data[256] = {0};
    int len = 0;
    
    // Build measurement string: comm_pid_uid_timestamp
    char *ptr = measurement_data;
    
    // Add comm
    for (int i = 0; i < 16 && comm[i] != 0 && len < 200; i++) {
        *ptr++ = comm[i];
        len++;
    }
    
    if (len < 250) {
        *ptr++ = '_';
        len++;
        
        u32 temp_pid = pid;
        char pid_digits[16];
        int pid_len = 0;
        
        if (temp_pid == 0) {
            pid_digits[pid_len++] = '0';
        } else {
            char temp_str[16];
            int temp_len = 0;
            while (temp_pid > 0 && temp_len < 15) {
                temp_str[temp_len++] = '0' + (temp_pid % 10);
                temp_pid /= 10;
            }
            for (int i = temp_len - 1; i >= 0 && pid_len < 15; i--) {
                pid_digits[pid_len++] = temp_str[i];
            }
        }
        
        for (int i = 0; i < pid_len && len < 245; i++) {
            *ptr++ = pid_digits[i];
            len++;
        }
        
        if (len < 240) {
            *ptr++ = '_';
            len++;
            
            u32 temp_uid = uid;
            char uid_digits[16];
            int uid_len = 0;
            
            if (temp_uid == 0) {
                uid_digits[uid_len++] = '0';
            } else {
                char temp_str[16];
                int temp_len = 0;
                while (temp_uid > 0 && temp_len < 15) {
                    temp_str[temp_len++] = '0' + (temp_uid % 10);
                    temp_uid /= 10;
                }
                for (int i = temp_len - 1; i >= 0 && uid_len < 15; i--) {
                    uid_digits[uid_len++] = temp_str[i];
                }
            }
            
            for (int i = 0; i < uid_len && len < 235; i++) {
                *ptr++ = uid_digits[i];
                len++;
            }
        }
    }
    
    *ptr = '\0';
    
    bpf_printk("Measurement data: %s (len=%d)\n", measurement_data, len);
    bpf_printk("Event logged for IMA-style measurement\n");
    
    return 0;
}

/* Monitor file operations via VFS layer */
SEC("kprobe/vfs_unlink")
int handle_vfs_unlink(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    u64 ts = bpf_ktime_get_ns();
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("VFS_UNLINK: pid=%d comm=%s ts=%llu\n", pid, comm, ts);
    bpf_printk("File operation intercepted at VFS layer\n");
    
    return 0;
}