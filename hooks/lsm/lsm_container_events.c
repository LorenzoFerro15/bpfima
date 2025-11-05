/*
 * Task 6: Enhanced Kernel-eBPF Communication
 * 
 * This file demonstrates additional communication patterns beyond kfuncs:
 * 1. Ring buffer for asynchronous event notifications
 * 2. BPF maps for statistics and container state tracking
 * 3. Bidirectional data flow between eBPF and kernel
 * 
 * This complements the existing kfunc-based synchronous communication
 * used in lsm_bprm_check_security.c
 */

#include "../../utils/headers_bpf.h"
#include "../../utils/utils.h"

/* External kfunc declarations */
extern int bpf_container_create_or_get(const char *container_id) __ksym;
extern int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len) __ksym;
extern int bpf_get_merkle_root(u8 *root_hash, u32 hash_size) __ksym;
extern int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size) __ksym;

char LICENSE[] SEC("license") = "GPL";

/* ===== Task 6: Communication Structures ===== */

/**
 * struct container_event - Event notification structure for ring buffer
 * @timestamp: Event timestamp (nanoseconds)
 * @pid: Process ID that triggered the event
 * @event_type: Type of event (1=created, 2=measurement, 3=deleted)
 * @container_id: Container identifier
 * @event_name: Event name/description
 * @digest: SHA-256 hash of the measurement
 */
struct container_event {
    __u64 timestamp;
    __u32 pid;
    __u32 event_type;
    char container_id[128];
    char event_name[256];
    __u8 digest[32];
};

/**
 * struct container_stats - Statistics for a container
 * @measurement_count: Number of measurements
 * @last_updated: Last update timestamp
 * @process_count: Number of processes seen
 */
struct container_stats {
    __u64 measurement_count;
    __u64 last_updated;
    __u32 process_count;
    __u32 padding;
};

/* ===== Task 6: BPF Maps for Communication ===== */

/**
 * Ring buffer for asynchronous event notifications
 * User-space can consume these events to monitor container activity in real-time
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB ring buffer */
} container_events SEC(".maps");

/**
 * Hash map for per-container statistics
 * Key: container_id (string), Value: container_stats
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); /* Support up to 1024 containers */
    __type(key, char[128]);
    __type(value, struct container_stats);
} container_stats_map SEC(".maps");

/**
 * Global statistics array
 * Index 0: Total containers created
 * Index 1: Total measurements
 * Index 2: Total events
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

/**
 * LRU hash for tracking active containers
 * This allows quick lookups to check if a container is already tracked
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, char[128]);
    __type(value, __u64); /* Timestamp of last activity */
} active_containers SEC(".maps");

/* ===== Task 6: Helper Functions ===== */

/**
 * update_container_stats - Update statistics for a container
 */
static __always_inline void update_container_stats(const char *container_id)
{
    struct container_stats *stats;
    struct container_stats new_stats = {0};
    
    stats = bpf_map_lookup_elem(&container_stats_map, container_id);
    if (stats) {
        __sync_fetch_and_add(&stats->measurement_count, 1);
        __sync_fetch_and_add(&stats->process_count, 1);
        stats->last_updated = bpf_ktime_get_ns();
    } else {
        new_stats.measurement_count = 1;
        new_stats.process_count = 1;
        new_stats.last_updated = bpf_ktime_get_ns();
        bpf_map_update_elem(&container_stats_map, container_id, &new_stats, BPF_ANY);
    }
}

/**
 * update_global_stat - Update a global statistic
 */
static __always_inline void update_global_stat(__u32 index, __u64 increment)
{
    __u64 *stat = bpf_map_lookup_elem(&global_stats, &index);
    if (stat) {
        __sync_fetch_and_add(stat, increment);
    } else {
        __u64 val = increment;
        bpf_map_update_elem(&global_stats, &index, &val, BPF_ANY);
    }
}

/**
 * send_container_event - Send event notification via ring buffer
 */
static __always_inline int send_container_event(__u32 event_type,
                                                const char *container_id,
                                                const char *event_name,
                                                const __u8 *digest)
{
    struct container_event *event;
    
    event = bpf_ringbuf_reserve(&container_events, sizeof(*event), 0);
    if (!event) {
        return -1;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = event_type;
    
    if (container_id) {
        __builtin_memcpy(event->container_id, container_id, 
                        sizeof(event->container_id) < 128 ? sizeof(event->container_id) : 128);
    }
    
    if (event_name) {
        __builtin_memcpy(event->event_name, event_name,
                        sizeof(event->event_name) < 256 ? sizeof(event->event_name) : 256);
    }
    
    if (digest) {
        __builtin_memcpy(event->digest, digest, 32);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * is_container_active - Check if container is already being tracked
 */
static __always_inline bool is_container_active(const char *container_id)
{
    __u64 *timestamp = bpf_map_lookup_elem(&active_containers, container_id);
    return (timestamp != NULL);
}

/**
 * mark_container_active - Mark container as active and update timestamp
 */
static __always_inline void mark_container_active(const char *container_id)
{
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&active_containers, container_id, &now, BPF_ANY);
}

/* ===== Task 6: LSM Hook with Enhanced Communication ===== */

/**
 * LSM hook: file_post_open
 * 
 * This hook demonstrates the enhanced communication patterns:
 * - Uses kfuncs for synchronous operations (container creation, measurement)
 * - Uses ring buffer for asynchronous event notifications
 * - Updates BPF maps for statistics tracking
 * - Provides bidirectional data flow
 */
SEC("lsm/file_post_open")
int BPF_PROG(lsm_container_file_post_open, struct file *file, int mask)
{
    char comm[16] = {0};
    char cgroup_name[64] = {0};  /* Reduced from 128 to save stack space */
    __u8 digest[32] = {0};
    int ret;
    bool is_new_container = false;
    
    if (!file) {
        return 0;
    }
    
    /* Get process information */
    bpf_get_current_comm(comm, sizeof(comm));
    
    /* Extract cgroup name as container identifier */
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    if (cur) {
        struct css_set *cgroups = BPF_CORE_READ(cur, cgroups);
        if (cgroups) {
            struct cgroup *dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
            if (dfl) {
                struct kernfs_node *kn = BPF_CORE_READ(dfl, kn);
                if (kn) {
                    bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), 
                                             BPF_CORE_READ(kn, name));
                }
            }
        }
    }
    
    /* Filter out system cgroups */
    if (cgroup_name[0] == '\0' || 
        __builtin_strcmp(cgroup_name, "/") == 0 ||
        __builtin_strcmp(cgroup_name, "init.scope") == 0 ||
        __builtin_strcmp(cgroup_name, "system.slice") == 0 ||
        __builtin_strcmp(cgroup_name, "user.slice") == 0) {
        return 0;
    }
    
    /* ===== Task 6: Multi-Channel Communication ===== */
    
    /* Channel 1: Check BPF map to see if container is new */
    if (!is_container_active(cgroup_name)) {
        is_new_container = true;
        mark_container_active(cgroup_name);
        
        /* Update global stats */
        update_global_stat(0, 1); /* Index 0: Total containers */
        
        bpf_printk("Task 6: New container detected: %s\n", cgroup_name);
    }
    
    /* Channel 2: Synchronous kfunc call to kernel module */
    ret = bpf_container_create_or_get(cgroup_name);
    if (ret != 0) {
        bpf_printk("Task 6: Failed to create container %s: %d\n", cgroup_name, ret);
        return 0;
    }
    
    /* Channel 3: Send async event via ring buffer */
    if (is_new_container) {
        send_container_event(1, cgroup_name, "container_created", NULL);
    }
    
    /* Get file hash */
    u64 file_scalar = 0;
    if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) == 0 && 
        file_scalar != 0) {
        ret = bpf_ima_file_hash_custom(file_scalar, digest, sizeof(digest));
        if (ret == 0) {
            /* Convert digest to hex string for additional_data */
            char digest_hex[65] = {0};
            bytes_to_hex_str(digest, 32, digest_hex, sizeof(digest_hex));
            
            /* Streamlined measurement via bpf_ima_extend_measurement */
            char event_name[] = "file_open";
            ret = bpf_ima_extend_measurement(event_name, cgroup_name, comm, 
                                            digest_hex, 64);
            if (ret == 0) {
                /* Channel 5: Update statistics in BPF maps */
                update_container_stats(cgroup_name);
                update_global_stat(1, 1); /* Index 1: Total measurements */
                update_global_stat(2, 1); /* Index 2: Total events */
                
                /* Channel 6: Send measurement event via ring buffer */
                send_container_event(2, cgroup_name, event_name, digest);
                
                bpf_printk("Task 6: ✓ Multi-channel comm: container=%s, file_open\n", 
                          cgroup_name);
            }
        }
    }
    
    return 0;
}

/**
 * LSM hook: bprm_check_security (Enhanced version for Task 6)
 * 
 * This demonstrates the same container tracking as the main hook,
 * but with additional communication channels for statistics and events.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_container_exec_enhanced, struct linux_binprm *bprm)
{
    char comm[16] = {0};
    char cgroup_name[64] = {0};  /* Reduced from 128 to save stack space */
    __u8 digest[32] = {0};
    int ret;
    bool is_new_container = false;
    
    if (!bprm) {
        return 0;
    }
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    /* Extract cgroup information */
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    if (cur) {
        struct css_set *cgroups = BPF_CORE_READ(cur, cgroups);
        if (cgroups) {
            struct cgroup *dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
            if (dfl) {
                struct kernfs_node *kn = BPF_CORE_READ(dfl, kn);
                if (kn) {
                    bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name),
                                             BPF_CORE_READ(kn, name));
                }
            }
        }
    }
    
    /* Filter system cgroups */
    if (cgroup_name[0] == '\0' ||
        __builtin_strcmp(cgroup_name, "/") == 0 ||
        __builtin_strcmp(cgroup_name, "init.scope") == 0 ||
        __builtin_strcmp(cgroup_name, "system.slice") == 0 ||
        __builtin_strcmp(cgroup_name, "user.slice") == 0) {
        return 0;
    }
    
    /* Check if this is a new container */
    if (!is_container_active(cgroup_name)) {
        is_new_container = true;
        mark_container_active(cgroup_name);
        update_global_stat(0, 1);
    }
    
    /* Create container via kfunc */
    ret = bpf_container_create_or_get(cgroup_name);
    if (ret != 0) {
        return 0;
    }
    
    /* Send container creation event */
    if (is_new_container) {
        send_container_event(1, cgroup_name, "container_exec_start", NULL);
    }
    
    /* Hash the executable */
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        u64 file_scalar = 0;
        if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) == 0 &&
            file_scalar != 0) {
            ret = bpf_ima_file_hash_custom(file_scalar, digest, sizeof(digest));
            if (ret == 0) {
                /* Convert digest to hex string for additional_data */
                char digest_hex[65] = {0};
                bytes_to_hex_str(digest, 32, digest_hex, sizeof(digest_hex));
                
                /* Streamlined measurement via bpf_ima_extend_measurement */
                char event_name[] = "exec";
                ret = bpf_ima_extend_measurement(event_name, cgroup_name, comm,
                                                digest_hex, 64);
                if (ret == 0) {
                    update_container_stats(cgroup_name);
                    update_global_stat(1, 1);
                    update_global_stat(2, 1);
                    send_container_event(2, cgroup_name, event_name, digest);
                    
                    bpf_printk("Task 6: ✓ Exec tracked: %s in %s\n", comm, cgroup_name);
                }
            }
        }
    }
    
    return 0;
}
