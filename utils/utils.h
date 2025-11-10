#ifndef UTILS_H
#define UTILS_H

#define BPF_NO_GLOBAL_DATA

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;
typedef unsigned char u8;

/* Per-CPU scratch buffer to avoid large stack allocations and heavy inlining
 * which can blow up the verifier. Value contains a small buffer and a length.
 */
/* Use a larger buffer and keep layout simple (no trailing metadata) so the
 * verifier can reason about map value bounds when we write fixed-size slots.
 */
struct scratch_t {
    /* 10 slots * 17 bytes each (16 char comm + separator) = 170; round up to 192 */
    char buf[192];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_t);
} scratch_buf_map SEC(".maps");

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

/*
 * Build a dependency chain by walking up to 10 ancestor processes.
 * 
 * @param deps: Output buffer for the dependency string (colon-separated)
 * @param deps_max: Maximum size of the deps buffer
 * @param initial_name: Initial name to prepend (e.g., filename), can be NULL
 * @param current_task: The current task_struct pointer
 * 
 * Returns the actual length of the dependency string (excluding null terminator).
 * 
 * The resulting string format is: "initial_name:parent1:parent2:...:parent10"
 * If initial_name is NULL, starts with "unknown:"
 */
static __always_inline int build_dependencies(char *deps, int deps_max, 
                                              const char *initial_name,
                                              struct task_struct *current_task)
{
    int deps_actual = 0;
    int ret;

    /* Add initial filename */
    if (initial_name) {
        ret = bpf_probe_read_kernel_str(deps, deps_max, initial_name);
        if (ret > 0) {
            deps_actual = ret - 1; // exclude null terminator
            if (deps_actual < deps_max) {
                deps[deps_actual] = ':';
                deps_actual++;
            }
        }
    }

    if (deps_actual == 0) {
        __builtin_memcpy(deps, "unknown:", 9);
        deps_actual = 8;
    }
    
    struct task_struct *ancestor = NULL;
    if (current_task) {
        ancestor = BPF_CORE_READ(current_task, real_parent);
    }
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (!ancestor)
            break;
        
        struct task_struct *next = BPF_CORE_READ(ancestor, real_parent);
        
        if (deps_actual < deps_max - 16) {
            ret = bpf_probe_read_kernel_str(&deps[deps_actual], 16, BPF_CORE_READ(ancestor, comm));
            if (ret > 0) {
                int consumed = ret - 1;
                if (consumed < 0)
                    consumed = 0;
                deps_actual += consumed;
                if (deps_actual < deps_max) {
                    deps[deps_actual] = ':';
                    deps_actual++;
                }
            }
        }
        
        if (!next || next == ancestor)
            break;
        
        ancestor = next;
    }
    
    /* Null-terminate the dependencies string after removing the last separator */
    if (deps_actual > 0 && deps_actual <= deps_max) {
        deps[--deps_actual] = '\0';
    }
    
    return deps_actual;
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