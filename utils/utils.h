#ifndef UTILS_H
#define UTILS_H

#define BPF_NO_GLOBAL_DATA

#include <bpf/bpf_helpers.h>

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

#endif /* UTILS_H */

/*
 * Convert a byte vector to a hex string (lowercase), up to 32 bytes.
 * Returns the number of characters written (excluding NUL) or -1 on error.
 * The output buffer must be at least (len*2 + 1) bytes long; a safe size is 65.
 */
static __always_inline int bytes_to_hex_str(const u8 *bytes, int len, char *out, int out_len)
{
    int pos = 0;
    int max = len;
    if (max > 32)
        max = 32;

    /* hex characters table */
    const char *hex = "0123456789abcdef";

#pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= max)
            break;
        if (pos + 2 >= out_len)
            return -1;
        u8 b = bytes[i];
        u8 hi = (b >> 4) & 0xf;
        u8 lo = b & 0xf;
        out[pos++] = hex[hi];
        out[pos++] = hex[lo];
    }

    if (pos < out_len) {
        out[pos] = '\0';
        return pos;
    }
    return -1;
}

/* Build a small hex string and print it with bpf_printk as a C string. */
static __always_inline void print_hex_digest(const u8 *bytes, int len)
{
    char buf[65] = {0};
    int r = bytes_to_hex_str(bytes, len, buf, sizeof(buf));
    if (r > 0) {
        bpf_printk("%s\n", buf);
    }
}
