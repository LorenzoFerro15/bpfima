#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_kfuncs.h"

__bpf_kfunc_start_defs();

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

    if (container)
    {
        pr_debug("bpfima: Container %s already exists\n", container_id);
        return 0;
    }

    /* Create new container */
    container = create_container_node(container_id);
    if (IS_ERR(container))
    {
        pr_err("bpfima: Failed to create container %s: %ld\n",
               container_id, PTR_ERR(container));
        return PTR_ERR(container);
    }

    pr_info("bpfima: Created new container: %s\n", container_id);
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

    ret = add_host_measurement(event_name, event_data ? event_data : "", "", digest);
    if (ret < 0)
    {
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

/**
 * bpf_container_get_count - Get the total number of tracked containers
 *
 * Returns: Number of containers currently being tracked
 */
__bpf_kfunc int bpf_container_get_count(void)
{
    return atomic_read(&container_count);
}

/**
 * bpf_container_get_measurement_count - Get measurement count for a container
 * @container_id: Container identifier
 *
 * Returns: Number of measurements in the container, or negative error code
 */
__bpf_kfunc int bpf_container_get_measurement_count(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;
    int count;

    if (!container_id || container_id[0] == '\0')
        return -EINVAL;

    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    if (!container)
    {
        spin_unlock_irqrestore(&container_list_lock, flags);
        return -ENOENT;
    }
    count = atomic_read(&container->measurement_count);
    spin_unlock_irqrestore(&container_list_lock, flags);

    return count;
}

/**
 * bpf_container_exists - Check if a container is being tracked
 * @container_id: Container identifier
 *
 * Returns: 1 if container exists, 0 if not, negative error code on failure
 */
__bpf_kfunc int bpf_container_exists(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;

    if (!container_id || container_id[0] == '\0')
        return -EINVAL;

    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    spin_unlock_irqrestore(&container_list_lock, flags);

    return container ? 1 : 0;
}

/**
 * bpf_get_container_leaf_hash - Get the Merkle leaf hash for a container
 * @container_id: Container identifier
 * @leaf_hash: Buffer to store the leaf hash (must be MERKLE_HASH_SIZE bytes)
 * @hash_size: Size of the buffer (must be MERKLE_HASH_SIZE)
 *
 * Retrieves the current leaf hash for the specified container.
 * The leaf hash represents the current state of all measurements in the container.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_get_container_leaf_hash(const char *container_id, u8 *leaf_hash, u32 hash_size)
{
    struct container_node *container;
    unsigned long flags;

    if (!container_id || !leaf_hash)
        return -EINVAL;

    if (hash_size != MERKLE_HASH_SIZE)
        return -EINVAL;

    spin_lock_irqsave(&container_list_lock, flags);
    container = find_container_by_id(container_id);
    if (!container)
    {
        spin_unlock_irqrestore(&container_list_lock, flags);
        return -ENOENT;
    }

    memcpy(leaf_hash, container->leaf_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&container_list_lock, flags);

    return 0;
}

__bpf_kfunc_end_defs();