/*
 * BPF Kernel Functions (kfuncs) for Container Tracking
 * 
 * These functions can be called from eBPF programs to interact
 * with the container tracking and Merkle tree system.
 */

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_kfuncs.h"

/**
 * bpf_container_create_or_get - Create a new container or get existing one
 * @container_id: Unique container identifier
 *
 * Creates a new container node if it doesn't exist, or returns success
 * if the container already exists.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_container_create_or_get(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;
    
    if (!container_id || container_id[0] == '\0')
        return -EINVAL;
    
    /* Check if container already exists */
    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    if (container) {
        pr_debug("bpfima: Container %s already exists\n", container_id);
        return 0;
    }
    
    /* Create new container */
    container = create_container_node(container_id);
    if (IS_ERR(container)) {
        pr_err("bpfima: Failed to create container %s: %ld\n",
               container_id, PTR_ERR(container));
        return PTR_ERR(container);
    }
    
    pr_info("bpfima: Created new container: %s\n", container_id);
    return 0;
}

/**
 * bpf_container_add_measurement - Add a measurement to a container
 */
__bpf_kfunc int bpf_container_add_measurement(const char *container_id,
                                               const char *event_name,
                                               const char *event_data,
                                               const u8 *digest,
                                               u32 digest_size)
{
    struct container_node *container;
    unsigned long flags;
    int ret;
    
    if (!container_id || !event_name || !digest)
        return -EINVAL;
    
    if (digest_size != MERKLE_HASH_SIZE)
        return -EINVAL;
    
    /* Find the container */
    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    spin_unlock_irqrestore(&container_list_lock, flags);
    
    if (!container) {
        pr_err("bpfima: Container %s not found\n", container_id);
        return -ENOENT;
    }
    
    /* Add measurement to container */
    ret = add_container_measurement(container, event_name, event_data, digest);
    if (ret < 0) {
        pr_err("bpfima: Failed to add measurement to container %s: %d\n",
               container_id, ret);
        return ret;
    }
    
    pr_debug("bpfima: Added measurement '%s' to container %s\n",
             event_name, container_id);
    
    return 0;
}

/**
 * bpf_host_add_measurement - Add a measurement to the host measurement list
 */
__bpf_kfunc int bpf_host_add_measurement(const char *event_name,
                                          const char *event_data,
                                          const u8 *digest,
                                          u32 digest_size)
{
    int ret;
    
    if (!event_name || !digest)
        return -EINVAL;
    
    if (digest_size != MERKLE_HASH_SIZE)
        return -EINVAL;
    
    ret = add_host_measurement(event_name, event_data, digest);
    if (ret < 0) {
        pr_err("bpfima: Failed to add host measurement: %d\n", ret);
        return ret;
    }
    
    pr_debug("bpfima: Added host measurement: %s\n", event_name);
    
    return 0;
}

/**
 * bpf_get_merkle_root - Get the current Merkle root hash
 */
__bpf_kfunc int bpf_get_merkle_root(u8 *root_hash, u32 hash_size)
{
    unsigned long flags;
    
    if (!root_hash)
        return -EINVAL;
    
    if (hash_size != MERKLE_HASH_SIZE)
        return -EINVAL;
    
    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(root_hash, system_merkle_root.root_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);
    
    return 0;
}
