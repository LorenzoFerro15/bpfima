#ifndef UTILS_H
#define UTILS_H

#define BPF_NO_GLOBAL_DATA

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;
typedef unsigned char u8;

#define ATTR_MODE (1 << 0)
#define ATTR_UID (1 << 1)
#define ATTR_GID (1 << 2)
#define ATTR_SIZE (1 << 3)
#define ATTR_ATIME (1 << 4)
#define ATTR_MTIME (1 << 5)
#define ATTR_CTIME (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE (1 << 9) /* Not a change, but a change it */
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_OPEN (1 << 15) /* Truncating from open(O_TRUNC) */
#define ATTR_TIMES_SET (1 << 16)
#define ATTR_TOUCH (1 << 17)
#define ATTR_DELEG (1 << 18)

#define AF_UNIX 1
#define AF_INET 2
#define MAX_DATA_BUF_SIZE 64
#define MAX_PATH_DEPTH 16
#define MAX_PATH_LEN 108
#define PATH_LEN_MASK 0x7F

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
 * @returns the actual length of the dependency string (excluding null terminator).
 * 
 * The resulting string format is: "initial_name:parent1:parent2:...:parent10"
 * If initial_name is NULL, starts with "unknown:"
 */
static __always_inline int build_dependencies(char *deps, int deps_max,
                                              const char *initial_name,
                                              struct task_struct *current_task)
{
    bool read_from_kernel = false;
    int deps_actual = 0;
    int ret;

    /* Add initial filename */
    if (initial_name) {
        ret = bpf_probe_read_kernel_str(deps, deps_max, initial_name);
        if (ret > 1) {  // Successfully read from kernel memory (ret includes '\0' in the length)
            deps_actual = ret - 1; // exclude null terminator
            if (deps_actual < deps_max) {
                deps[deps_actual] = ':';
                deps_actual++;
            }
            read_from_kernel = true;
        }
    }

    if (!read_from_kernel) {
        // Failed to read initial name or it was empty
        bpf_printk("Using default 'unknown:' prefix\n");
        const char unknown[] = "unknown:";
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            deps[i] = unknown[i];
        }
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


/*
 * Build socket connection additional data string" 
 * Format: "192.168.1.1:8080-10.0.0.1:80"
 *         "<saddr>:<sport>-<daddr>:<dport>"
 * 
 * @param additional_data: Output buffer for the additional data string
 * @param buf_size: Size of the additional_data buffer
 * @param saddr: Source IPv4 address
 * @param sport: Source port
 * @param daddr: Destination IPv4 address
 * @param dport: Destination port
 * 
 * @returns The number of written characters.
 */
static __always_inline long build_socket_additional_data(char *additional_data, int buf_size,
                                                  u32 saddr, u16 sport,
                                                  u32 daddr, u16 dport)
{
    u64 params[10] = {
        (u64)(saddr & 0xFF),
        (u64)((saddr >> 8) & 0xFF), 
        (u64)((saddr >> 16) & 0xFF),
        (u64)((saddr >> 24) & 0xFF), 
        (u64)sport,
        (u64)(daddr & 0xFF),
        (u64)((daddr >> 8) & 0xFF), 
        (u64)((daddr >> 16) & 0xFF),
        (u64)((daddr >> 24) & 0xFF), 
        (u64)dport
    };

    return bpf_snprintf(additional_data, buf_size,
                        "%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                        params, sizeof(params));
}

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


static __always_inline void append_attr(char *buf, int buf_max,
                                        int *off, const char *fmt, __u64 val)
{
    if (!buf || !off || *off >= buf_max)
        return;

    __u64 args[1];
    args[0] = val;   // wrap the scalar in an array

    int n = bpf_snprintf(buf + *off,
                         buf_max - *off,
                         fmt,
                         args,   // pointer to array of __u64
                         1);     // number of arguments

    if (n > 0)
        *off += n;
}


static __always_inline int build_attributes(char *attrs, int attrs_max, struct iattr *attr)
{
    int off = 0;

    if (!attr || !attrs || attrs_max <= 0)
        return 0;

    if (attr->ia_valid & ATTR_MODE)
        append_attr(attrs, 64, &off, "mode=%llu,", (__u64)attr->ia_mode);

    if (attr->ia_valid & ATTR_UID)
        append_attr(attrs, 64, &off, "uid=%llu,", (__u64)attr->ia_uid.val);

    if (attr->ia_valid & ATTR_GID)
        append_attr(attrs, 64, &off, "gid=%llu,", (__u64)attr->ia_gid.val);

    if (attr->ia_valid & ATTR_SIZE)
        append_attr(attrs, 64, &off, "size=%llu,", (__u64)attr->ia_size);

    // if (attr->ia_valid & ATTR_OPEN)
    //     append_attr(attrs, 64, &off, "open=%llu,", (__u64)attr->ia_opened);

    /* KILL_PRIV */
    if (attr->ia_valid & ATTR_KILL_PRIV)
        append_attr(attrs, attrs_max, &off, "kill_priv=1,", 0);

    /* KILL_SUID */
    if (attr->ia_valid & ATTR_KILL_SUID)
        append_attr(attrs, attrs_max, &off, "kill_suid=1,", 0);

    /* KILL_SGID */
    if (attr->ia_valid & ATTR_KILL_SGID)
        append_attr(attrs, attrs_max, &off, "kill_sgid=1,", 0);

    /* Trim trailing comma */
    if (off > 0 && attrs[off - 1] == ',')
        attrs[off - 1] = '\0';
    else if (off < attrs_max)
        attrs[off] = '\0';

    return off;
}

#endif /* UTILS_H */