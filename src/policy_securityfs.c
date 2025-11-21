/**
 * policy_securityfs.c - SecurityFS interface for policy updates
 *
 * This file provides a userspace interface to update policies via securityfs.
 * 
 * GLOBAL POLICY:
 *   /sys/kernel/security/bpfima/policy
 *   - Sets default policy for all namespaces
 *   - New namespaces inherit from global policy
 *
 * PER-NAMESPACE POLICY:
 *   /sys/kernel/security/bpfima/namespaces/<namespace_id>/policy
 *   - Overrides global policy for specific namespace
 *   - Fine-grained control per container
 * 
 * Write format: "field=value"
 * Examples:
 *   echo "filter_flags=0x7" > policy
 *   echo "action_flags=0x3F" > policy
 *   echo "min_file_size=10485760" > policy
 *   echo "log_level=3" > policy
 */

#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_securityfs.h"

typedef int (*namespace_update_fn)(const char *namespace_id, u32 value);
typedef void (*global_update_fn)(struct bpfima_policy_config *config, u32 value);

struct policy_field {
    const char *name;
    namespace_update_fn ns_update;
    global_update_fn global_update;
    bool supports_namespace;
};

static void update_filter_flags(struct bpfima_policy_config *config, u32 value)
{
    config->filter_flags = value;
}

static void update_action_flags(struct bpfima_policy_config *config, u32 value)
{
    config->action_flags = value;
}

static void update_min_file_size(struct bpfima_policy_config *config, u32 value)
{
    config->min_file_size = value;
}

static void update_log_level(struct bpfima_policy_config *config, u32 value)
{
    config->log_level = value;
}

static void update_enabled(struct bpfima_policy_config *config, u32 value)
{
    config->enabled = (u8)value;
}

/* Table of policy fields and their update functions */
static const struct policy_field policy_fields[] = {
    {
        .name = "filter_flags",
        .ns_update = bpfima_policy_namespace_update_filter_flags,
        .global_update = update_filter_flags,
        .supports_namespace = true,
    },
    {
        .name = "action_flags",
        .ns_update = bpfima_policy_namespace_update_action_flags,
        .global_update = update_action_flags,
        .supports_namespace = true,
    },
    {
        .name = "min_file_size",
        .ns_update = bpfima_policy_namespace_update_min_file_size,
        .global_update = update_min_file_size,
        .supports_namespace = true,
    },
    {
        .name = "log_level",
        .ns_update = bpfima_policy_namespace_update_log_level,
        .global_update = update_log_level,
        .supports_namespace = true,
    },
    {
        .name = "enabled",
        .ns_update = NULL,
        .global_update = update_enabled,
        .supports_namespace = false,
    },
};

#define NUM_POLICY_FIELDS (sizeof(policy_fields) / sizeof(policy_fields[0]))

/* Global policy file dentry */
static struct dentry *global_policy_file = NULL;

/**
 * parse_and_update_policy - Common function to parse and update policy
 * @buf: Buffer containing "field=value"
 * @namespace_id: Namespace ID (NULL for global policy)
 *
 * Returns: 0 on success, negative error code on failure
 */
static int parse_and_update_policy(const char *buf, const char *namespace_id)
{
    char *field, *value_str, *buf_copy;
    unsigned long value;
    int ret = -EINVAL;
    size_t i;

    buf_copy = kstrdup(buf, GFP_KERNEL);
    if (!buf_copy)
        return -ENOMEM;

    field = buf_copy;
    value_str = strchr(buf_copy, '=');
    if (!value_str) {
        pr_err("bpfima: Invalid format. Use: field=value\n");
        kfree(buf_copy);
        return -EINVAL;
    }

    *value_str = '\0';
    value_str++;

    ret = kstrtoul(value_str, 0, &value);
    if (ret) {
        pr_err("bpfima: Invalid value: %s\n", value_str);
        kfree(buf_copy);
        return ret;
    }

    for (i = 0; i < NUM_POLICY_FIELDS; i++) {
        const struct policy_field *pf = &policy_fields[i];
        
        if (strcmp(field, pf->name) != 0)
            continue;

        if (namespace_id && !pf->supports_namespace) {
            pr_err("bpfima: Field '%s' does not support namespace-specific updates\n", field);
            ret = -ENOTSUPP;
            break;
        }

        if (namespace_id) {
            ret = pf->ns_update(namespace_id, (u32)value);
        } else {
            struct bpfima_policy_config new_config = *bpfima_policy_get();
            pf->global_update(&new_config, (u32)value);
            ret = bpfima_policy_update(&new_config);
        }

        if (ret == 0) {
            pr_info("bpfima: Updated %s=%u (0x%x) for %s\n",
                    pf->name, (u32)value, (u32)value,
                    namespace_id ? namespace_id : "global");
        }
        goto out;
    }

    if (i == NUM_POLICY_FIELDS) {
        pr_err("bpfima: Unknown field: %s\n", field);
        ret = -EINVAL;
    }

out:
    kfree(buf_copy);
    return ret;
}

/**
 * policy_update_write - Handle writes to policy file (namespace-specific)
 * @file: File being written to
 * @user_buf: User buffer containing the write data
 * @count: Number of bytes to write
 * @ppos: File position
 *
 * Accepts commands in format "field=value" to update policies.
 *
 * Returns: Number of bytes written on success, negative error code on failure
 */
static ssize_t policy_update_write(struct file *file, const char __user *user_buf,
                                   size_t count, loff_t *ppos)
{
    char *buf;
    char *namespace_id;
    int ret;

    if (count > 256)
        return -EINVAL;

    buf = kmalloc(count + 1, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, user_buf, count)) {
        kfree(buf);
        return -EFAULT;
    }
    buf[count] = '\0';

    if (count > 0 && buf[count - 1] == '\n')
        buf[count - 1] = '\0';

    namespace_id = file->f_inode->i_private;
    if (!namespace_id) {
        pr_err("bpfima: No namespace_id in policy file\n");
        kfree(buf);
        return -EINVAL;
    }

    ret = parse_and_update_policy(buf, namespace_id);
    kfree(buf);
    
    return ret < 0 ? ret : count;
}

/**
 * global_policy_write - Handle writes to global policy file
 * @file: File being written to
 * @user_buf: User buffer containing the write data
 * @count: Number of bytes to write
 * @ppos: File position
 *
 * Updates the global/default policy configuration.
 *
 * Returns: Number of bytes written on success, negative error code on failure
 */
static ssize_t global_policy_write(struct file *file, const char __user *user_buf,
                                    size_t count, loff_t *ppos)
{
    char *buf;
    int ret;

    if (count > 256)
        return -EINVAL;

    buf = kmalloc(count + 1, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, user_buf, count)) {
        kfree(buf);
        return -EFAULT;
    }
    buf[count] = '\0';

    if (count > 0 && buf[count - 1] == '\n')
        buf[count - 1] = '\0';

    ret = parse_and_update_policy(buf, NULL);
    kfree(buf);
    
    return ret < 0 ? ret : count;
}

/**
 * policy_show - Display current policy configuration
 * @s: seq_file structure for output
 * @v: Unused
 *
 * Shows current policy settings and changes hash for the namespace.
 */
static int policy_show(struct seq_file *s, void *v)
{
    char *namespace_id = s->private;
    struct bpfima_policy_namespace *policy_ns;
    int i;

    if (!namespace_id)
        return -EINVAL;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    seq_printf(s, "namespace_id=%s\n", policy_ns->namespace_id);
    seq_printf(s, "filter_flags=0x%x\n", policy_ns->policy.filter_flags);
    seq_printf(s, "action_flags=0x%x\n", policy_ns->policy.action_flags);
    seq_printf(s, "min_file_size=%u\n", policy_ns->policy.min_file_size);
    seq_printf(s, "log_level=%u\n", policy_ns->policy.log_level);
    seq_printf(s, "enabled=%u\n", policy_ns->policy.enabled);
    seq_printf(s, "\nchanges=%s\n", policy_ns->changes_str);
    
    seq_printf(s, "changes_hash=");
    for (i = 0; i < MERKLE_HASH_SIZE; i++)
        seq_printf(s, "%02x", policy_ns->changes_hash[i]);
    seq_printf(s, "\n");

    return 0;
}

/**
 * global_policy_show - Display global policy configuration
 * @s: seq_file structure for output
 * @v: Unused
 *
 * Shows current global/default policy settings.
 */
static int global_policy_show(struct seq_file *s, void *v)
{
    struct bpfima_policy_config *policy = bpfima_policy_get();
 
    seq_printf(s, "enabled=%u\n", policy->enabled);
    seq_printf(s, "filter_flags=0x%x\n", policy->filter_flags);
    seq_printf(s, "action_flags=0x%x\n", policy->action_flags);
    seq_printf(s, "min_file_size=%u\n", policy->min_file_size);
    seq_printf(s, "max_path_depth=%u\n", policy->max_path_depth);
    seq_printf(s, "log_level=%u\n", policy->log_level);

    return 0;
}

static int global_policy_open(struct inode *inode, struct file *file)
{
    return single_open(file, global_policy_show, NULL);
}

const struct file_operations global_policy_fops = {
    .owner = THIS_MODULE,
    .open = global_policy_open,
    .read = seq_read,
    .write = global_policy_write,
    .llseek = seq_lseek,
    .release = single_release,
};

/**
 * global_policy_changes_show - Display global policy change history
 * @s: seq_file structure for output
 * @v: Unused
 *
 * Shows all global policy changes with format: HASH POLICY_STRING per line
 */
static int global_policy_changes_show(struct seq_file *s, void *v)
{
    struct policy_change_entry *change;
    struct list_head *history;
    spinlock_t *history_lock;
    unsigned long flags;
    int i;

    history = bpfima_global_policy_get_history();
    history_lock = bpfima_global_policy_get_history_lock();

    spin_lock_irqsave(history_lock, flags);
    list_for_each_entry(change, history, list) {
        for (i = 0; i < MERKLE_HASH_SIZE; i++)
            seq_printf(s, "%02x", change->change_hash[i]);
        
        seq_printf(s, " %s\n", change->policy_string);
    }
    spin_unlock_irqrestore(history_lock, flags);

    return 0;
}

static int global_policy_changes_open(struct inode *inode, struct file *file)
{
    return single_open(file, global_policy_changes_show, NULL);
}

const struct file_operations global_policy_changes_fops = {
    .owner = THIS_MODULE,
    .open = global_policy_changes_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int policy_open(struct inode *inode, struct file *file)
{
    return single_open(file, policy_show, inode->i_private);
}

const struct file_operations policy_fops = {
    .owner = THIS_MODULE,
    .open = policy_open,
    .read = seq_read,
    .write = policy_update_write,
    .llseek = seq_lseek,
    .release = single_release,
};

/**
 * policy_changes_show - Display policy change history for a namespace
 * @s: seq_file structure for output
 * @v: Unused
 *
 * Shows all policy changes with format: HASH POLICY_STRING per line
 */
static int policy_changes_show(struct seq_file *s, void *v)
{
    char *namespace_id = s->private;
    struct bpfima_policy_namespace *policy_ns;
    struct policy_change_entry *change;
    unsigned long flags;
    int i;

    if (!namespace_id)
        return -EINVAL;

    policy_ns = bpfima_policy_namespace_get_or_create(namespace_id);
    if (IS_ERR(policy_ns))
        return PTR_ERR(policy_ns);

    spin_lock_irqsave(&policy_ns->change_history_lock, flags);
    list_for_each_entry(change, &policy_ns->change_history, list) {
        for (i = 0; i < MERKLE_HASH_SIZE; i++)
            seq_printf(s, "%02x", change->change_hash[i]);
        
        seq_printf(s, " %s\n", change->policy_string);
    }
    spin_unlock_irqrestore(&policy_ns->change_history_lock, flags);

    return 0;
}

static int policy_changes_open(struct inode *inode, struct file *file)
{
    return single_open(file, policy_changes_show, inode->i_private);
}

const struct file_operations policy_changes_fops = {
    .owner = THIS_MODULE,
    .open = policy_changes_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/**
 * create_namespace_policy_securityfs - Create policy files for a namespace
 * @namespace_id: Namespace identifier
 * @parent_dir: Parent securityfs directory
 *
 * Creates a "policy" file in the namespace directory that can be read to
 * show current policy and written to update policy.
 *
 * Returns: Pointer to policy file dentry, or ERR_PTR on failure
 */
struct dentry *create_namespace_policy_securityfs(const char *namespace_id,
                                                   struct dentry *parent_dir)
{
    struct dentry *policy_file;
    char *ns_copy;

    if (!namespace_id || !parent_dir)
        return ERR_PTR(-EINVAL);

    ns_copy = kstrdup(namespace_id, GFP_KERNEL);
    if (!ns_copy)
        return ERR_PTR(-ENOMEM);

    policy_file = securityfs_create_file("policy", 0644, parent_dir,
                                        ns_copy, &policy_fops);
    if (IS_ERR(policy_file)) {
        pr_err("bpfima: Failed to create policy file for %s: %ld\n",
               namespace_id, PTR_ERR(policy_file));
        kfree(ns_copy);
        return policy_file;
    }

    pr_info("bpfima: Created policy interface for namespace %s\n", namespace_id);
    return policy_file;
}

/**
 * remove_namespace_policy_securityfs - Remove policy file for a namespace
 * @policy_file: Dentry of the policy file to remove
 *
 * Removes the policy file and frees the associated namespace_id copy.
 */
void remove_namespace_policy_securityfs(struct dentry *policy_file)
{
    void *ns_copy;

    if (!policy_file || IS_ERR(policy_file))
        return;

    if (policy_file->d_inode) {
        ns_copy = policy_file->d_inode->i_private;
        kfree(ns_copy);
    }

    securityfs_remove(policy_file);
}

/**
 * create_namespace_policy_changes_securityfs - Create policy_changes file for a namespace
 * @namespace_id: Namespace identifier
 * @parent_dir: Parent securityfs directory
 *
 * Creates a "policy_changes" file in the namespace directory that shows
 * the history of all policy changes with hash and policy string per line.
 *
 * Returns: Pointer to policy_changes file dentry, or ERR_PTR on failure
 */
struct dentry *create_namespace_policy_changes_securityfs(const char *namespace_id,
                                                          struct dentry *parent_dir)
{
    struct dentry *policy_changes_file;
    char *ns_copy;

    if (!namespace_id || !parent_dir)
        return ERR_PTR(-EINVAL);

    ns_copy = kstrdup(namespace_id, GFP_KERNEL);
    if (!ns_copy)
        return ERR_PTR(-ENOMEM);

    policy_changes_file = securityfs_create_file("policy_changes", 0444, parent_dir,
                                                 ns_copy, &policy_changes_fops);
    if (IS_ERR(policy_changes_file)) {
        pr_err("bpfima: Failed to create policy_changes file for %s: %ld\n",
               namespace_id, PTR_ERR(policy_changes_file));
        kfree(ns_copy);
        return policy_changes_file;
    }

    pr_info("bpfima: Created policy_changes interface for namespace %s\n", namespace_id);
    return policy_changes_file;
}

/**
 * remove_namespace_policy_changes_securityfs - Remove policy_changes file for a namespace
 * @policy_changes_file: Dentry of the policy_changes file to remove
 *
 * Removes the policy_changes file and frees the associated namespace_id copy.
 */
void remove_namespace_policy_changes_securityfs(struct dentry *policy_changes_file)
{
    void *ns_copy;

    if (!policy_changes_file || IS_ERR(policy_changes_file))
        return;

    if (policy_changes_file->d_inode) {
        ns_copy = policy_changes_file->d_inode->i_private;
        kfree(ns_copy);
    }

    securityfs_remove(policy_changes_file);
}

/**
 * create_global_policy_securityfs - Create global policy file
 * @parent_dir: Parent securityfs directory (bpfima root)
 *
 * Creates /sys/kernel/security/bpfima/policy for global policy configuration.
 *
 * Returns: 0 on success, negative error code on failure
 */
int create_global_policy_securityfs(struct dentry *parent_dir)
{
    if (!parent_dir)
        return -EINVAL;

    global_policy_file = securityfs_create_file("policy", 0644, parent_dir,
                                                NULL, &global_policy_fops);
    if (IS_ERR(global_policy_file)) {
        pr_err("bpfima: Failed to create global policy file: %ld\n",
               PTR_ERR(global_policy_file));
        return PTR_ERR(global_policy_file);
    }

    pr_info("bpfima: Created global policy interface at /sys/kernel/security/bpfima/policy\n");
    return 0;
}

/**
 * remove_global_policy_securityfs - Remove global policy file
 */
void remove_global_policy_securityfs(void)
{
    if (global_policy_file && !IS_ERR(global_policy_file)) {
        securityfs_remove(global_policy_file);
        global_policy_file = NULL;
    }
}

static struct dentry *global_policy_changes_file = NULL;

/**
 * create_global_policy_changes_securityfs - Create global policy_changes file
 * @parent_dir: Parent securityfs directory (bpfima root)
 *
 * Creates /sys/kernel/security/bpfima/policy_changes for global policy change history.
 *
 * Returns: 0 on success, negative error code on failure
 */
int create_global_policy_changes_securityfs(struct dentry *parent_dir)
{
    if (!parent_dir)
        return -EINVAL;

    global_policy_changes_file = securityfs_create_file("policy_changes", 0444, parent_dir,
                                                         NULL, &global_policy_changes_fops);
    if (IS_ERR(global_policy_changes_file)) {
        pr_err("bpfima: Failed to create global policy_changes file: %ld\n",
               PTR_ERR(global_policy_changes_file));
        return PTR_ERR(global_policy_changes_file);
    }

    pr_info("bpfima: Created global policy_changes interface at /sys/kernel/security/bpfima/policy_changes\n");
    return 0;
}

/**
 * remove_global_policy_changes_securityfs - Remove global policy_changes file
 */
void remove_global_policy_changes_securityfs(void)
{
    if (global_policy_changes_file && !IS_ERR(global_policy_changes_file)) {
        securityfs_remove(global_policy_changes_file);
        global_policy_changes_file = NULL;
    }
}
