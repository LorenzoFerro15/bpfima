/*
 * Container Management for BPF-IMA
 *
 * This file implements container node management including:
 * - Container creation and lookup
 * - Container measurement list management
 * - Container cleanup operations
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_securityfs.h"

/* Global state */
LIST_HEAD(container_list);
DEFINE_SPINLOCK(container_list_lock);
atomic_t container_count = ATOMIC_INIT(0);

/**
 * find_container_by_id - Find a container node by its ID
 * @container_id: Container identifier to search for
 *
 * Must be called with container_list_lock held.
 * Returns: Pointer to container_node if found, NULL otherwise
 */
struct container_node *find_container_by_id(const char *container_id)
{
    struct container_node *container;

    list_for_each_entry(container, &container_list, list)
    {
        if (strcmp(container->id, container_id) == 0)
            return container;
    }

    return NULL;
}

/**
 * create_container_node - Create and initialize a new container node
 * @container_id: Unique identifier for the container
 *
 * Returns: Pointer to new container_node on success, ERR_PTR on failure
 */
struct container_node *create_container_node(const char *container_id)
{
    struct container_node *container;
    unsigned long flags;
    int ret;

    container = kzalloc(sizeof(*container), GFP_KERNEL);
    if (!container)
        return ERR_PTR(-ENOMEM);

    container->tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(container->tfm))
    {
        kfree(container);
        pr_err("bpfima: Failed to allocate tfm for container %s\n", container_id);
        return ERR_PTR(-ENOMEM);
    }

    strscpy(container->id, container_id, CONTAINER_ID_MAX_LEN);
    INIT_LIST_HEAD(&container->measurement_list);
    spin_lock_init(&container->measurement_lock);
    memset(container->leaf_hash, 0, MERKLE_HASH_SIZE);
    atomic_set(&container->measurement_count, 0);
    container->securityfs_dir = NULL;
    container->securityfs_measurements_file = NULL;

    spin_lock_irqsave(&container_list_lock, flags);
    list_add_tail(&container->list, &container_list);
    spin_unlock_irqrestore(&container_list_lock, flags);

    atomic_inc(&container_count);

    ret = create_container_securityfs(container);
    if (ret < 0)
    {
        pr_err("bpfima: Failed to create securityfs for container %s: %d\n",
               container_id, ret);
        spin_lock_irqsave(&container_list_lock, flags);
        list_del(&container->list);
        spin_unlock_irqrestore(&container_list_lock, flags);
        atomic_dec(&container_count);
        kfree(container);
        return ERR_PTR(ret);
    }

    pr_info("bpfima: Created container node for %s\n", container_id);

    /* 
     * Initialize policy for this namespace by inheriting global policy.
     * This ensures that the new namespace starts with the current global settings.
     */
    {
        struct bpfima_policy_namespace *policy_ns;
        policy_ns = bpfima_policy_namespace_get_or_create(container_id);
        if (IS_ERR(policy_ns)) {
            pr_warn("bpfima: Failed to create policy namespace for %s: %ld (continuing without policy inheritance)\n",
                    container_id, PTR_ERR(policy_ns));
        } else {
            pr_info("bpfima: Inherited global policy for namespace %s\n", container_id);
        }
    }

    return container;
}

/**
 * cleanup_container_measurements - Free all measurements in a container
 * @container: Container to clean up
 */
void cleanup_container_measurements(struct container_node *container)
{
    struct measurement_entry *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &container->measurement_list, list)
    {
        list_del(&entry->list);
        kfree(entry);
    }
}

/**
 * cleanup_all_containers - Remove and free all container nodes
 */
void cleanup_all_containers(void)
{
    struct container_node *container, *tmp;
    unsigned long flags;
    int count = 0;

    spin_lock_irqsave(&container_list_lock, flags);
    list_for_each_entry_safe(container, tmp, &container_list, list)
    {
        list_del(&container->list);
        spin_unlock_irqrestore(&container_list_lock, flags);

        remove_container_securityfs(container);

        cleanup_container_measurements(container);

        if (container->tfm)
            crypto_free_shash(container->tfm);

        kfree(container);
        count++;

        spin_lock_irqsave(&container_list_lock, flags);
    }
    spin_unlock_irqrestore(&container_list_lock, flags);

    pr_info("bpfima: Cleaned up %d containers\n", count);
}
