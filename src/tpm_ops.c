#include "bpfima_common.h"

#define TPM_PCR_INDEX 23
#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE

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
 * Returns: 0 on successful PCR extension, negative error code on failure
 */
int extend_tpm_pcr(const u8 *hash_value, const char *event_name)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1];
    int ret;

    chip = tpm_default_chip();
    if (!chip) {
        printk(KERN_WARNING "TPM not available, measurement added to list only\n");
        return -ENODEV;
    }

    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;
    memcpy(digest[0].digest, hash_value, SHA256_DIGEST_SIZE);
    
    ret = tpm_pcr_extend(chip, TPM_PCR_INDEX, digest);
    if (ret < 0) {
        printk(KERN_ERR "Failed to extend TPM PCR %d: %d\n", TPM_PCR_INDEX, ret);
    } else {
        printk(KERN_INFO "Extended TPM PCR %d with measurement for event: %s\n", TPM_PCR_INDEX, event_name);
    }
    
    tpm_put_ops(chip);
    return ret;
}

/**
 * extend_tpm_pcr_with_root - Extend TPM PCR with the Merkle root hash
 * @root_hash: The Merkle root hash to extend into the TPM PCR
 * @event_name: Event name for logging purposes
 *
 * This function extends the configured TPM PCR (default PCR 23) with the
 * Merkle root hash value. This creates a hardware-backed attestation of
 * the current system integrity state as represented by all container
 * measurements.
 *
 * The function handles TPM chip acquisition, digest preparation, PCR extension,
 * and proper cleanup. It provides detailed logging for both success and failure cases.
 *
 * The function assumes it's called in a context where sleeping is allowed
 * (i.e., not in atomic context) since TPM operations can sleep.
 *
 * Returns: 0 on successful PCR extension, negative error code on failure
 */
int extend_tpm_pcr_with_root(const u8 *root_hash, const char *event_name)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1];
    int ret;

    chip = tpm_default_chip();
    if (!chip) {
        pr_warn("bpfima: TPM not available, measurement added to list only\n");
        return -ENODEV;
    }

    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;
    memcpy(digest[0].digest, root_hash, SHA256_DIGEST_SIZE);
    
    ret = tpm_pcr_extend(chip, TPM_PCR_INDEX, digest);
    if (ret < 0) {
        pr_err("bpfima: Failed to extend TPM PCR %d: %d\n", TPM_PCR_INDEX, ret);
    } else {
        pr_info("bpfima: Extended TPM PCR %d with measurement for event: %s\n", 
                TPM_PCR_INDEX, event_name);
    }
    
    tpm_put_ops(chip);
    return ret;
}
