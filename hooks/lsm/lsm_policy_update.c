/**
 * lsm_policy_update.c - Example LSM hook that dynamically updates policies
 *
 * This example demonstrates how eBPF programs can dynamically update
 * policy configurations for specific namespaces using the policy kfuncs.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* External kfunc declarations for policy management */
extern int bpf_policy_update_filter_flags(const char *namespace_id, u32 new_flags) __ksym;
extern int bpf_policy_update_action_flags(const char *namespace_id, u32 new_flags) __ksym;
extern int bpf_policy_update_min_file_size(const char *namespace_id, u32 new_size) __ksym;
extern int bpf_policy_update_log_level(const char *namespace_id, u32 new_level) __ksym;
extern int bpf_policy_get_changes_hash(const char *namespace_id, u8 *hash_out, u32 hash_size) __ksym;

/* External kfunc declarations for container tracking */
extern int bpf_container_create_or_get(const char *container_id) __ksym;
extern int bpf_container_exists(const char *container_id) __ksym;

/* Policy flag definitions (from bpfima_policy.h) */
#define POLICY_FILTER_SYSTEM_CGROUPS    (1 << 0)
#define POLICY_FILTER_PROC_SYS          (1 << 1)
#define POLICY_FILTER_DEV               (1 << 2)
#define POLICY_FILTER_READONLY_FILES    (1 << 3)
#define POLICY_FILTER_SMALL_FILES       (1 << 4)
#define POLICY_FILTER_NON_EXECUTABLE    (1 << 5)
#define POLICY_FILTER_LIBRARIES         (1 << 6)
#define POLICY_FILTER_TMP_FILES         (1 << 7)

#define POLICY_ACTION_EXTEND_TPM        (1 << 0)
#define POLICY_ACTION_LOG_SECURITYFS    (1 << 1)
#define POLICY_ACTION_LOG_KERNEL        (1 << 2)
#define POLICY_ACTION_ALERT_SUSPICIOUS  (1 << 3)
#define POLICY_ACTION_BLOCK             (1 << 4)
#define POLICY_ACTION_TRACK_CONTAINER   (1 << 5)
#define POLICY_ACTION_BUILD_DEPS        (1 << 6)

#define MERKLE_HASH_SIZE 32

char LICENSE[] SEC("license") = "GPL";

/**
 * Example 1: Update policy when a specific container starts
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(policy_update_on_exec, struct linux_binprm *bprm, int ret)
{
    char container_id[128] = {0};
    u32 new_filter_flags;
    u32 new_action_flags;
    int result;

    /* Get the container ID from cgroup (simplified example) */
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    /* Example: Detect if we're in a specific namespace/container
     * In real scenario, you'd extract this from cgroup path or namespace ID
     */
    __builtin_memcpy(container_id, "prod-container-123", 18);

    /* Check if container exists, create if needed */
    result = bpf_container_create_or_get(container_id);
    if (result < 0) {
        bpf_printk("Failed to create/get container: %d\n", result);
        return 0;
    }

    /* Update filter flags for this container - disable some filters for production */
    new_filter_flags = POLICY_FILTER_SYSTEM_CGROUPS | 
                       POLICY_FILTER_PROC_SYS |
                       POLICY_FILTER_DEV;
    
    result = bpf_policy_update_filter_flags(container_id, new_filter_flags);
    if (result < 0) {
        bpf_printk("Failed to update filter flags: %d\n", result);
        return 0;
    }

    /* Update action flags - enable all logging for production containers */
    new_action_flags = POLICY_ACTION_EXTEND_TPM |
                       POLICY_ACTION_LOG_SECURITYFS |
                       POLICY_ACTION_LOG_KERNEL |
                       POLICY_ACTION_TRACK_CONTAINER |
                       POLICY_ACTION_BUILD_DEPS;
    
    result = bpf_policy_update_action_flags(container_id, new_action_flags);
    if (result < 0) {
        bpf_printk("Failed to update action flags: %d\n", result);
        return 0;
    }

    bpf_printk("Policy updated for container: %s\n", container_id);

    return 0;
}

/**
 * Example 2: Adjust policy based on file characteristics
 */
SEC("lsm/file_open")
int BPF_PROG(policy_adjust_on_file_open, struct file *file, int ret)
{
    char namespace_id[128] = {0};
    u32 min_file_size;
    int result;

    /* Get namespace ID from current task */
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    /* Example: Extract namespace from cgroup or use a hardcoded value for demo */
    __builtin_memcpy(namespace_id, "dev-namespace", 13);

    /* If opening a large file, increase minimum file size threshold */
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    loff_t size = BPF_CORE_READ(inode, i_size);
    
    /* If accessing large files, adjust policy to focus on large files only */
    if (size > 10 * 1024 * 1024) {  /* 10 MB */
        min_file_size = 5 * 1024 * 1024;  /* 5 MB threshold */
        
        result = bpf_policy_update_min_file_size(namespace_id, min_file_size);
        if (result < 0) {
            bpf_printk("Failed to update min_file_size: %d\n", result);
        } else {
            bpf_printk("Updated min_file_size for %s to %u\n", namespace_id, min_file_size);
        }
    }

    return 0;
}

/**
 * Example 3: Get hash of all policy changes for a namespace
 */
SEC("lsm/mmap_file")
int BPF_PROG(policy_get_changes_hash, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    char namespace_id[128] = {0};
    u8 policy_hash[MERKLE_HASH_SIZE] = {0};
    int result;

    /* Get namespace ID */
    __builtin_memcpy(namespace_id, "monitoring-ns", 13);

    /* Ensure namespace exists */
    if (bpf_container_exists(namespace_id) <= 0)
        return 0;

    /* Retrieve the hash of all policy changes for this namespace */
    result = bpf_policy_get_changes_hash(namespace_id, policy_hash, MERKLE_HASH_SIZE);
    if (result < 0) {
        bpf_printk("Failed to get policy changes hash: %d\n", result);
        return 0;
    }

    /* Log first 4 bytes of hash for verification */
    bpf_printk("Policy hash for %s: %02x%02x%02x%02x...\n",
               namespace_id,
               policy_hash[0], policy_hash[1], 
               policy_hash[2], policy_hash[3]);

    return 0;
}

/**
 * Example 4: Dynamically adjust log level based on activity
 */
SEC("lsm/socket_connect")
int BPF_PROG(policy_adjust_log_level, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    char namespace_id[128] = {0};
    u32 new_log_level;
    int result;

    /* Get namespace ID */
    __builtin_memcpy(namespace_id, "backend-service", 15);

    /* Create namespace if it doesn't exist */
    result = bpf_container_create_or_get(namespace_id);
    if (result < 0)
        return 0;

    /* Increase log level for debugging network issues */
    new_log_level = 3;  /* Debug level */
    
    result = bpf_policy_update_log_level(namespace_id, new_log_level);
    if (result < 0) {
        bpf_printk("Failed to update log level: %d\n", result);
    } else {
        bpf_printk("Increased log level to %u for %s\n", new_log_level, namespace_id);
    }

    return 0;
}
