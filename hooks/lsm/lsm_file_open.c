/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

#define IMA_MAX_DIGEST_SIZE 64
#define PATH_MAX 64

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* External kfuncs for TPM operations */
extern int bpf_tpm_is_available(void) __ksym;
extern int bpf_tpm_extend_pcr(const char *data, u32 data_len) __ksym;
extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size) __ksym;

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

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

/* Build measurement data string: "comm_pid_uid_full_path_filehash" */
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

/* Monitor file open operations */
SEC("lsm/file_open")
int handle_lsm_file_post_open_tpm(struct file *file, int mask) {

    struct path f_path;
    //bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);

    /*
    char full_path[PATH_MAX];
    long read = bpf_d_path(&f_path, full_path, sizeof(full_path));  
    if (read < 0) {
        bpf_printk("Failed to resolve file full path\n");
        return 0;
    } */

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    u32 gid = uid_gid >> 32;
    char comm[16];
    u64 ts = bpf_ktime_get_ns();

    bpf_get_current_comm(comm, sizeof(comm));
    
    bpf_printk("=== TPM FILE OPEN DETECTED ===\n");
    bpf_printk("Process: pid=%d uid=%d gid=%d comm=%s\n", pid, uid, gid, comm);
    bpf_printk("Timestamp: %llu ns\n", ts);

    char measurement_data[256] = {0};
    int data_len = build_measurement_data(measurement_data, sizeof(measurement_data), comm, pid, uid);
    
    if (data_len < 0) {
        bpf_printk("Failed to build measurement data\n");
        return 0;
    }

    /* Check if TPM is available */
    int tpm_available = bpf_tpm_is_available();
    bpf_printk("TPM Available: %s\n", tpm_available ? "YES" : "NO");

    char event_name[] = "file_open";
    int ima_ret = bpf_ima_extend_measurement(event_name, measurement_data, data_len);
    bpf_printk("IMA measurement result: %d\n", ima_ret);

    return 0;
}