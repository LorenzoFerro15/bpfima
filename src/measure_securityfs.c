#include "bpfima_common.h"
#include "bpfima_securityfs.h"
#include "bpfima_merkle.h"
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>

static struct dentry *measure_policy_file = NULL;

/*
 * measure_policy_write - Handle policy measurements from userspace
 *
 * Expected format: 64-character hex string representing the SHA-256 hash of the new policy.
 */
static ssize_t measure_policy_write(struct file *file, const char __user *buf,
                                    size_t count, loff_t *ppos)
{
    char hash_hex[MERKLE_HASH_SIZE * 2 + 1];
    char measurement_data[512];
    u8 measurement_digest[MERKLE_HASH_SIZE];
    int ret;

    if (count > sizeof(hash_hex) - 1)
        count = sizeof(hash_hex) - 1;

    if (copy_from_user(hash_hex, buf, count))
        return -EFAULT;

    hash_hex[count] = '\0';

    /* Strip trailing newline if present */
    if (count > 0 && hash_hex[count - 1] == '\n') {
        hash_hex[count - 1] = '\0';
        count--;
    }

    if (count != MERKLE_HASH_SIZE * 2) {
        pr_warn("bpfima: Invalid policy hash length: %zu\n", count);
        return -EINVAL;
    }

    /* Format the measurement string */
    snprintf(measurement_data, sizeof(measurement_data), "global_policy_update %s", hash_hex);

    /* Hash the measurement string */
    ret = calculate_sha256_hash(measurement_data, strlen(measurement_data), measurement_digest);
    if (ret < 0) {
        pr_err("bpfima: Failed to calculate measurement hash for global policy update: %d\n", ret);
        return ret;
    }

    /* Record the measurement */
    ret = add_merkle_root_history_entry(measurement_digest, "global_policy");
    if (ret < 0) {
        pr_warn("bpfima: Failed to add merkle root history entry for global policy: %d\n", ret);
    }

    ret = extend_merkle_root(measurement_digest);
    if (ret < 0) {
        pr_err("bpfima: Failed to extend Merkle root with global policy change: %d\n", ret);
        return ret;
    }

    pr_info("bpfima: Global policy change recorded and Merkle root extended\n");

    return count;
}

static const struct file_operations measure_policy_fops = {
    .owner = THIS_MODULE,
    .write = measure_policy_write,
};

int create_measure_policy_securityfs(struct dentry *parent_dir)
{
    if (!parent_dir)
        return -EINVAL;

    measure_policy_file = securityfs_create_file("measure_policy", 0200,
                                                 parent_dir, NULL, &measure_policy_fops);
    if (IS_ERR(measure_policy_file)) {
        pr_err("bpfima: Failed to create measure_policy file: %ld\n", PTR_ERR(measure_policy_file));
        measure_policy_file = NULL;
        return PTR_ERR(measure_policy_file);
    }

    return 0;
}

void remove_measure_policy_securityfs(void)
{
    if (measure_policy_file && !IS_ERR(measure_policy_file)) {
        securityfs_remove(measure_policy_file);
        measure_policy_file = NULL;
    }
}
