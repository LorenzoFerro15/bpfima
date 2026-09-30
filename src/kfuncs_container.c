#include "bpfima_common.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_kfuncs.h"
#include "bpfima_kfunc_buffer.h"

__bpf_kfunc_start_defs();

/**
 * bpfima_container_get_or_create - Create a new container or get existing one
 * @container_id: Unique container identifier
 *
 * Creates a new container node if it doesn't exist, or returns success
 * if the container already exists.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_container_get_or_create(const char *container_id, u32 container_id__sz)
{
    struct container_node *container;
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), container_id, container_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    rcu_read_lock();
    container = find_container_by_id_rcu(id);
    rcu_read_unlock();

    if (container)
    {
        bpfima_put_container(container);
        pr_debug("bpfima: Container %s already exists\n", id);
        return 0;
    }

    container = create_container_node(id);
    if (IS_ERR(container))
    {
        pr_err("bpfima: Failed to create container %s: %ld\n", id, PTR_ERR(container));
        return PTR_ERR(container);
    }

    bpfima_put_container(container);
    pr_info("bpfima: Created new container: %s\n", id);
    return 0;
}

/**
 * bpfima_merkle_get_root - Get the current Merkle root hash
 */
__bpf_kfunc int bpfima_merkle_get_root(u8 *root_hash, u32 root_hash__sz)
{
    unsigned long flags;

    if (!root_hash)
        return -EINVAL;

    if (root_hash__sz != MERKLE_HASH_SIZE)
        return -EINVAL;

    spin_lock_irqsave(&system_merkle_root.lock, flags);
    memcpy(root_hash, system_merkle_root.root_hash, MERKLE_HASH_SIZE);
    spin_unlock_irqrestore(&system_merkle_root.lock, flags);

    return 0;
}

/**
 * bpfima_container_get_count - Get the total number of tracked containers
 *
 * Returns: Number of containers currently being tracked
 */
__bpf_kfunc int bpfima_container_get_count(void)
{
    return atomic_read(&container_count);
}

/**
 * bpfima_container_get_measurement_count - Get measurement count for a container
 * @container_id: Container identifier
 *
 * Returns: Number of measurements in the container, or negative error code
 */
__bpf_kfunc int bpfima_container_get_measurement_count(const char *container_id, u32 container_id__sz)
{
    struct container_node *container;
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;
    int count;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), container_id, container_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    rcu_read_lock();
    container = find_container_by_id_rcu(id);
    rcu_read_unlock();

    if (!container)
        return -ENOENT;

    count = atomic_read(&container->measurement_count);
    bpfima_put_container(container);

    return count;
}

/**
 * bpfima_container_exists - Check if a container is being tracked
 * @container_id: Container identifier
 *
 * Returns: 1 if container exists, 0 if not, negative error code on failure
 */
__bpf_kfunc int bpfima_container_exists(const char *container_id, u32 container_id__sz)
{
    struct container_node *container;
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), container_id, container_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    rcu_read_lock();
    container = find_container_by_id_rcu(id);
    rcu_read_unlock();

    if (container)
    {
        bpfima_put_container(container);
        return 1;
    }

    return 0;
}

/**
 * bpfima_container_get_leaf_hash - Get the Merkle leaf hash for a container
 * @container_id: Container identifier
 * @leaf_hash: Buffer to store the leaf hash (must be MERKLE_HASH_SIZE bytes)
 * @leaf_hash__sz: Size of the buffer (must be MERKLE_HASH_SIZE)
 *
 * Retrieves the current leaf hash for the specified container.
 * The leaf hash represents the current state of all measurements in the container.
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpfima_container_get_leaf_hash(const char *container_id, u32 container_id__sz,
                                                u8 *leaf_hash, u32 leaf_hash__sz)
{
    struct container_node *container;
    char id[BPFIMA_NAMESPACE_SIZE];
    int ret;

    ret = bpfima_copy_kfunc_string(id, sizeof(id), container_id, container_id__sz, false);
    if (ret || bpfima_validate_namespace(id))
        return -EINVAL;

    if (!leaf_hash || leaf_hash__sz != MERKLE_HASH_SIZE)
        return -EINVAL;

    rcu_read_lock();
    container = find_container_by_id_rcu(id);
    rcu_read_unlock();

    if (!container)
        return -ENOENT;

    spin_lock(&container->measurement_lock);
    memcpy(leaf_hash, container->leaf_hash, MERKLE_HASH_SIZE);
    spin_unlock(&container->measurement_lock);

    bpfima_put_container(container);
    return 0;
}

__bpf_kfunc_end_defs();
