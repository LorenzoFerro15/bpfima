#include "bpfima_common.h"

/* TPM PCR configuration */
static int tpm_pcr_index = 23; /* Default PCR index for bpfima measurements */
module_param(tpm_pcr_index, int, 0644);
MODULE_PARM_DESC(tpm_pcr_index, "TPM PCR index to use for measurements (default: 23)");

#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE

DEFINE_MUTEX(bpfima_tpm_mutex);

#ifndef TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE 64
#endif

/**
 * extend_tpm_pcr - Extend TPM Platform Configuration Register with measurement
 * @hash_value: SHA256 digest to extend into the PCR (must be SHA256_DIGEST_SIZE bytes)
 * @event_name: Event name for logging purposes (used in success/failure messages)
 *
 * Attempts to extend the configured TPM PCR with the provided hash value.
 * This function handles TPM chip acquisition, digest preparation, PCR extension,
 * and proper cleanup. It provides detailed logging for both success and failure cases.
 *
 * The function assumes it's called in a context where sleeping is allowed
 * (i.e., not in atomic context) since TPM operations can sleep.
 *
 * Note: The PCR index is configurable via the tpm_pcr_index module parameter.
 *
 * Returns: 0 on successful PCR extension, negative error code on failure
 */
int extend_tpm_pcr(const u8 *hash_value, const char *event_name)
{
    struct tpm_chip *chip;
    struct tpm_digest *digests;
    int ret;
    int i;

    if (!hash_value || !event_name)
    {
        printk(KERN_ERR "bpfima: Invalid parameters to extend_tpm_pcr\n");
        return -EINVAL;
    }

    if (in_atomic() || irqs_disabled())
    {
        printk(KERN_INFO "bpfima: Skipping TPM extend from atomic context for event: %s\n",
               event_name);
        return -EAGAIN;
    }

    if (tpm_pcr_index < 0 || tpm_pcr_index > 23)
    {
        printk(KERN_ERR "bpfima: Invalid TPM PCR index %d (must be 0-23)\n", tpm_pcr_index);
        return -EINVAL;
    }

    mutex_lock(&bpfima_tpm_mutex);

    chip = tpm_default_chip();
    if (!chip)
    {
        mutex_unlock(&bpfima_tpm_mutex);
        printk(KERN_WARNING "bpfima: TPM not available, measurement added to list only\n");
        return -ENODEV;
    }

    /* Allocate digests array for all allocated banks */
    digests = kcalloc(chip->nr_allocated_banks, sizeof(struct tpm_digest), GFP_KERNEL);
    if (!digests)
    {
        put_device(&chip->dev);
        mutex_unlock(&bpfima_tpm_mutex);
        printk(KERN_ERR "bpfima: Failed to allocate memory for TPM digests\n");
        return -ENOMEM;
    }

    /* Populate digests for all banks */
    for (i = 0; i < chip->nr_allocated_banks; i++)
    {
        digests[i].alg_id = chip->allocated_banks[i].alg_id;

        if (digests[i].alg_id == TPM_ALG_SHA256)
        {
            memcpy(digests[i].digest, hash_value, SHA256_DIGEST_SIZE);
        }
        else
        {
            /* For other banks, extend with zeros to maintain consistency */
            memset(digests[i].digest, 0, TPM_MAX_DIGEST_SIZE);
        }
    }

    ret = tpm_pcr_extend(chip, tpm_pcr_index, digests);

    kfree(digests);
    put_device(&chip->dev);

    mutex_unlock(&bpfima_tpm_mutex);

    if (ret != 0)
    {
        printk(KERN_ERR "bpfima: Failed to extend TPM PCR %d for event '%s': TPM RC %d\n",
               tpm_pcr_index, event_name, ret);
        return ret > 0 ? -EIO : ret;
    }

    printk(KERN_INFO "bpfima: Successfully extended TPM PCR %d for event: %s\n",
           tpm_pcr_index, event_name);
    return 0;
}

/**
 * extend_tpm_pcr_with_root - Extend TPM PCR with the Merkle root hash
 * @root_hash: The Merkle root hash to extend into the TPM PCR
 * @event_name: Event name for logging purposes
 *
 * This is a convenience wrapper around extend_tpm_pcr() specifically for
 * Merkle root hash extensions. It provides the same functionality but with
 * a more descriptive name for code clarity.
 *
 * Returns: 0 on successful PCR extension, negative error code on failure
 */
int extend_tpm_pcr_with_root(const u8 *root_hash, const char *event_name)
{
    return extend_tpm_pcr(root_hash, event_name);
}
