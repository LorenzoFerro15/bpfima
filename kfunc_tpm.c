/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* External kfuncs for TPM operations */
extern int bpf_tpm_is_available(void) __ksym;
extern int bpf_tpm_extend_pcr(const char *data, u32 data_len) __ksym;
extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size) __ksym;

/* Helper function to convert u32 to string and append to buffer */
static __always_inline int append_u32_to_buffer(char *buf, int *len, int max_len, u32 value)
{
    char temp[16];
    int temp_len = 0;
    
    /* Handle zero case */
    if (value == 0) {
        if (*len >= max_len - 1) return -1;
        buf[(*len)++] = '0';
        return 0;
    }
    
    /* Convert to string (digits in reverse order) */
    u32 temp_val = value;
    while (temp_val > 0 && temp_len < 15) {
        temp[temp_len++] = '0' + (temp_val % 10);
        temp_val /= 10;
    }
    
    /* Check if we have space */
    if (*len + temp_len >= max_len) return -1;
    
    /* Reverse and copy to buffer */
    for (int i = temp_len - 1; i >= 0; i--) {
        buf[(*len)++] = temp[i];
    }
    
    return 0;
}

/* Helper function to append string to buffer */
static __always_inline int append_string_to_buffer(char *buf, int *len, int max_len, const char *str, int str_max_len)
{
    for (int i = 0; i < str_max_len && str[i] != 0; i++) {
        if (*len >= max_len - 1) return -1;
        buf[(*len)++] = str[i];
    }
    return 0;
}

/* Helper function to append separator to buffer */
static __always_inline int append_separator(char *buf, int *len, int max_len)
{
    if (*len >= max_len - 1) return -1;
    buf[(*len)++] = '_';
    return 0;
}

/* Build measurement data string: "comm_pid_uid" */
static __always_inline int build_measurement_data(char *measurement_data, int max_len, 
                                                  const char *comm, pid_t pid, u32 uid)
{
    int len = 0;
    
    /* Add process name */
    if (append_string_to_buffer(measurement_data, &len, max_len, comm, 16) < 0)
        return -1;
    
    /* Add separator and PID */
    if (append_separator(measurement_data, &len, max_len) < 0)
        return -1;
    if (append_u32_to_buffer(measurement_data, &len, max_len, pid) < 0)
        return -1;
    
    /* Add separator and UID */
    if (append_separator(measurement_data, &len, max_len) < 0)
        return -1;
    if (append_u32_to_buffer(measurement_data, &len, max_len, uid) < 0)
        return -1;
    
    /* Null terminate */
    if (len < max_len) {
        measurement_data[len] = '\0';
    } else {
        return -1;
    }
    
    return len;
}

/* Monitor file unlink operations with TPM integration */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat_tpm(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    u32 gid = uid_gid >> 32;
    char comm[16];
    char pcr_buf[128];
    u64 ts = bpf_ktime_get_ns();
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("=== TPM FILE UNLINK DETECTED ===\n");
    bpf_printk("Process: pid=%d uid=%d gid=%d comm=%s\n", pid, uid, gid, comm);
    bpf_printk("Timestamp: %llu ns\n", ts);
    
    /* Check if TPM is available */
    int tpm_available = bpf_tpm_is_available();
    bpf_printk("TPM Available: %s\n", tpm_available ? "YES" : "NO");
    
    /* Build measurement data using helper function */
    char measurement_data[256] = {0};
    int data_len = build_measurement_data(measurement_data, sizeof(measurement_data), comm, pid, uid);
    
    if (data_len < 0) {
        bpf_printk("Failed to build measurement data\n");
        return 0;
    }
    
    bpf_printk("Measurement data: %s (len=%d)\n", measurement_data, data_len);
    
    /* Extend IMA measurement list */
    char event_name[] = "file_unlink";
    int ima_ret = bpf_ima_extend_measurement(event_name, measurement_data, data_len);
    bpf_printk("IMA measurement result: %d\n", ima_ret);
    
    /* TPM operations if available */
    if (tpm_available) {
        int tpm_ret = bpf_tpm_extend_pcr(measurement_data, data_len);
        bpf_printk("TPM PCR extend result: %d\n", tpm_ret);
        
        /* Get updated PCR value */
        int pcr_ret = bpf_ima_get_pcr_value(pcr_buf, sizeof(pcr_buf));
        if (pcr_ret == 0) {
            bpf_printk("PCR Value: %s\n", pcr_buf);
        } else {
            bpf_printk("Failed to read PCR: %d\n", pcr_ret);
        }
    } else {
        bpf_printk("TPM not available - using simulation only\n");
        
        int pcr_ret = bpf_ima_get_pcr_value(pcr_buf, sizeof(pcr_buf));
        if (pcr_ret == 0) {
            bpf_printk("Simulated PCR: %s\n", pcr_buf);
        }
    }
    
    bpf_printk("TPM-enhanced measurement completed\n");
    
    return 0;
}

/* VFS layer monitoring with TPM logging */
SEC("kprobe/vfs_unlink")
int handle_vfs_unlink_tpm(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("VFS_UNLINK_TPM: pid=%d comm=%s\n", pid, comm);
    
    /* Quick TPM availability check */
    int tpm_available = bpf_tpm_is_available();
    bpf_printk("TPM Status: %s\n", tpm_available ? "READY" : "UNAVAILABLE");
    
    return 0;
}