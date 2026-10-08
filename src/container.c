#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>

#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_container.h"
#include "bpfima_merkle.h"
#include "bpfima_securityfs.h"

/* Global state */
LIST_HEAD(container_list);
DEFINE_SPINLOCK(container_list_lock);
atomic_t container_count = ATOMIC_INIT(0);
static DEFINE_MUTEX(container_create_mutex);
static struct workqueue_struct *container_cleanup_wq;

int bpfima_container_init(void)
{
    container_cleanup_wq = alloc_workqueue("bpfima_cleanup", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    return container_cleanup_wq ? 0 : -ENOMEM;
}

void bpfima_container_cleanup(void)
{
    /* RCU callbacks must enqueue their work before the queue is drained. */
    rcu_barrier();
    destroy_workqueue(container_cleanup_wq);
    container_cleanup_wq = NULL;
}

/**
 * find_container_by_id_rcu - Find a container node by ID and acquire a reference
 * @container_id: Container identifier to search for
 *
 * Must be called under rcu_read_lock() or container_list_lock.
 * Returns: Incremented pointer to container_node if found, NULL otherwise
 */
struct container_node *find_container_by_id_rcu(const char *container_id)
{
    struct container_node *container;

    if (!container_id)
        return NULL;

    list_for_each_entry_rcu(container, &container_list, list)
    {
        if (strcmp(container->id, container_id) == 0)
        {
            if (refcount_inc_not_zero(&container->refcnt))
                return container;
        }
    }

    return NULL;
}

struct container_node *find_container_by_id(const char *container_id)
{
    struct container_node *container;
    rcu_read_lock();
    container = find_container_by_id_rcu(container_id);
    rcu_read_unlock();
    return container;
}

/**
 * bpfima_get_container - Increment reference count on a container node
 */
struct container_node *bpfima_get_container(struct container_node *container)
{
    if (container && refcount_inc_not_zero(&container->refcnt))
        return container;
    return NULL;
}

static void container_node_free_work(struct work_struct *work)
{
    struct container_node *container = container_of(to_rcu_work(work), struct container_node, free_work);

    cleanup_container_measurements(container);
    bpfima_policy_namespace_remove(container->id);

    if (container->tfm)
        crypto_free_shash(container->tfm);

    kfree(container);
}

/**
 * bpfima_put_container - Decrement reference count on a container node
 */
void bpfima_put_container(struct container_node *container)
{
    if (container && refcount_dec_and_test(&container->refcnt))
    {
        queue_rcu_work(container_cleanup_wq, &container->free_work);
    }
}

/**
 * create_container_node - Create and initialize a new container node safely
 * @container_id: Unique identifier for the container
 *
 * Returns: Reference-counted pointer to container_node on success, ERR_PTR on failure
 */
static struct container_node *create_container_node_locked(const char *container_id)
{
    struct container_node *container;
    struct container_node *existing_container;
    unsigned long flags;
    int ret;

    /* 0. Fast check: return existing container if already published */
    existing_container = find_container_by_id(container_id);
    if (existing_container)
        return existing_container;

    /* Pre-allocate memory outside lock */
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
    refcount_set(&container->refcnt, 1);
    INIT_RCU_WORK(&container->free_work, container_node_free_work);
    container->securityfs_dir = NULL;
    container->securityfs_measurements_file = NULL;

    /* 1. Fully initialize SecurityFS & Policy BEFORE publishing to public list */
    ret = create_container_securityfs(container);
    if (ret < 0)
    {
        /* If another thread created the SecurityFS dir concurrently, check if container node exists */
        if (ret == -EEXIST)
        {
            existing_container = find_container_by_id(container_id);
            if (existing_container)
            {
                crypto_free_shash(container->tfm);
                kfree(container);
                return existing_container;
            }
        }
        pr_err("bpfima: Failed to create securityfs for container %s: %d\n", container_id, ret);
        crypto_free_shash(container->tfm);
        kfree(container);
        return ERR_PTR(ret);
    }

    {
        struct bpfima_policy_namespace *policy_ns;
        policy_ns = bpfima_policy_namespace_get_or_create(container_id);
        if (IS_ERR(policy_ns))
        {
            pr_warn("bpfima: Failed to create policy namespace for %s: %ld\n", container_id, PTR_ERR(policy_ns));
        }
    }

    /* 2. Publish to RCU list atomically */
    spin_lock_irqsave(&container_list_lock, flags);
    existing_container = find_container_by_id_rcu(container_id);
    if (existing_container)
    {
        spin_unlock_irqrestore(&container_list_lock, flags);
        /* Lost the race: free local allocation and return existing with refcnt */
        remove_container_securityfs(container);
        crypto_free_shash(container->tfm);
        kfree(container);
        pr_debug("bpfima: Container %s created concurrently, returning existing\n", container_id);
        return existing_container;
    }

    list_add_tail_rcu(&container->list, &container_list);
    spin_unlock_irqrestore(&container_list_lock, flags);

    atomic_inc(&container_count);

    /* Increment reference count for the returned pointer */
    refcount_inc(&container->refcnt);

    pr_info("bpfima: Created container node for %s\n", container_id);
    return container;
}

struct container_node *create_container_node(const char *container_id)
{
    struct container_node *container;

    mutex_lock(&container_create_mutex);
    container = create_container_node_locked(container_id);
    mutex_unlock(&container_create_mutex);
    return container;
}

/**
 * cleanup_container_measurements - Free all measurements in a container
 * @container: Container to clean up
 */
void cleanup_container_measurements(struct container_node *container)
{
    struct measurement_entry *entry, *tmp;

    if (!container)
        return;

    spin_lock(&container->measurement_lock);
    list_for_each_entry_safe(entry, tmp, &container->measurement_list, list)
    {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&container->measurement_lock);
}

/**
 * cleanup_all_containers - Remove and free all container nodes
 */
void cleanup_all_containers(void)
{
    struct container_node *container, *tmp;
    unsigned long flags;
    int count = 0;

    LIST_HEAD(temp_list);

    /* Safely move all items to temp list under lock */
    spin_lock_irqsave(&container_list_lock, flags);
    list_splice_init(&container_list, &temp_list);
    spin_unlock_irqrestore(&container_list_lock, flags);

    /* Process cleanup without holding the lock */
    list_for_each_entry_safe(container, tmp, &temp_list, list)
    {
        list_del_rcu(&container->list);
        remove_container_securityfs(container);
        bpfima_put_container(container);
        count++;
    }

    synchronize_rcu();
    atomic_set(&container_count, 0);
    pr_info("bpfima: Cleaned up %d containers\n", count);
}
