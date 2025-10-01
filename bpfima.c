#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ima.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <linux/tpm.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <crypto/sha2.h>

#define IMA_DIGEST_SIZE SHA256_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX 255
#define TPM_PCR_INDEX 23

struct bpf_ima_template_entry {
    struct list_head list;
    char event_name[IMA_EVENT_NAME_LEN_MAX + 1];
    char event_data[256];
    u8 digest[IMA_DIGEST_SIZE];
};

static LIST_HEAD(bpf_measurement_list);
static DEFINE_SPINLOCK(measurement_list_lock);
static atomic_t measurement_count = ATOMIC_INIT(0);

__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len);
__bpf_kfunc int bpf_ima_get_measurement_count(void);
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size);
__bpf_kfunc int bpf_tpm_is_available(void);

__bpf_kfunc_start_defs();


/* Calculate SHA256 hash of data for TPM PCR extension */
static int calculate_sha256_hash(const void *data, size_t len, u8 *digest)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, data, len, digest);

    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/* Unified function to process measurement data: calculate SHA256, add to list, and extend TPM PCR */
static int process_measurement(const char *event_name, const char *data, u32 data_len)
{
    struct bpf_ima_template_entry *entry;
    struct tpm_chip *chip;
    struct tpm_digest digest[1];
    unsigned long flags;
    int ret = 0;
    u8 hash_value[SHA256_DIGEST_SIZE];

    if (!event_name || !data || data_len == 0)
        return -EINVAL;

    /* Calculate SHA256 hash of the data */
    ret = calculate_sha256_hash(data, data_len, hash_value);
    if (ret) {
        printk(KERN_ERR "Failed to calculate SHA256 hash: %d\n", ret);
        return ret;
    }

    /* Allocate and prepare measurement entry */
    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;

    strncpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX);
    entry->event_name[IMA_EVENT_NAME_LEN_MAX] = '\0';
    
    strncpy(entry->event_data, data, min_t(u32, data_len, sizeof(entry->event_data) - 1));
    entry->event_data[sizeof(entry->event_data) - 1] = '\0';
    
    memcpy(entry->digest, hash_value, IMA_DIGEST_SIZE);

    /* Acquire single lock to ensure atomicity of both list and TPM operations */
    spin_lock_irqsave(&measurement_list_lock, flags);

    /* Add to measurement list */
    list_add_tail(&entry->list, &bpf_measurement_list);
    atomic_inc(&measurement_count);
    
    /* Prepare TPM digest structure */
    chip = tpm_default_chip();
    if (chip) {
        memset(digest, 0, sizeof(digest));
        digest[0].alg_id = TPM_ALG_SHA256;
        memcpy(digest[0].digest, hash_value, SHA256_DIGEST_SIZE);
        
        /* Extend TPM PCR */
        ret = tpm_pcr_extend(chip, TPM_PCR_INDEX, digest);
        if (ret < 0) {
            printk(KERN_ERR "Failed to extend TPM PCR %d: %d\n", TPM_PCR_INDEX, ret);
        } else {
            printk(KERN_INFO "Extended TPM PCR %d with measurement for event: %s\n", TPM_PCR_INDEX, event_name);
        }
        
        tpm_put_ops(chip);
    } else {
        printk(KERN_WARNING "TPM not available, measurement added to list only\n");
    }

    spin_unlock_irqrestore(&measurement_list_lock, flags);

    printk(KERN_INFO "IMA_MEASUREMENT: event=%s count=%d digest=%*ph\n", 
           event_name, atomic_read(&measurement_count), IMA_DIGEST_SIZE, hash_value);
    
    return atomic_read(&measurement_count);
}

/* Add measurement to list and extend TPM PCR using unified function */
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len)
{
    return process_measurement(event_name, data, data_len);
}

/* Return total number of measurements in the list */
__bpf_kfunc int bpf_ima_get_measurement_count(void)
{
    return atomic_read(&measurement_count);
}

/* Get real TPM PCR value or simulate if TPM not available */
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1]; 
    int ret;
    
    if (!pcr_buf || buf_size < 80) 
        return -EINVAL;
    
    chip = tpm_default_chip();
    if (!chip) {
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_INFO "TPM not available, using simulation\n");
        return 0;
    }
    
    /* Initialize digest array */
    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;
    
    /* Read actual PCR value from TPM */
    ret = tpm_pcr_read(chip, TPM_PCR_INDEX, digest);
    if (ret < 0) {
        /* TPM read failed, use simulation */
        snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
                 TPM_PCR_INDEX, atomic_read(&measurement_count));
        printk(KERN_WARNING "TPM PCR read failed (%d), using simulation\n", ret);
        tpm_put_ops(chip);
        return ret;
    }
    
    /* Format the real PCR value as hex string */
    snprintf(pcr_buf, buf_size, "PCR%d_REAL:", TPM_PCR_INDEX);
    for (int i = 0; i < SHA256_DIGEST_SIZE && strlen(pcr_buf) < buf_size - 3; i++) {
        snprintf(pcr_buf + strlen(pcr_buf), buf_size - strlen(pcr_buf), 
                 "%02x", digest[0].digest[i]);
    }
    
    tpm_put_ops(chip);
    return 0;
}

/* Check if TPM is available */
__bpf_kfunc int bpf_tpm_is_available(void)
{
    struct tpm_chip *chip;
    
    chip = tpm_default_chip();
    if (!chip)
        return 0; 
        
    tpm_put_ops(chip);
    return 1; 
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_ima_extend_measurement)
BTF_ID_FLAGS(func, bpf_ima_get_measurement_count)
BTF_ID_FLAGS(func, bpf_ima_get_pcr_value)
BTF_ID_FLAGS(func, bpf_tpm_is_available)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* Initialize module and register kfuncs */
static int __init bpfima_init(void)
{
    int ret;

    printk(KERN_INFO "BPF-IMA module initializing...\n");
    
    /* Register kfuncs for kprobe programs */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpfima: Failed to register BTF kfunc ID set for kprobe\n");
        return ret;
    }
    
    /* Register kfuncs for tracepoint programs */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpfima: Failed to register BTF kfunc ID set for tracepoint\n");
        return ret;
    }
    
    printk(KERN_INFO "bpfima: Module loaded successfully\n");
    return 0;
}

/* Clean up module and measurement list */
static void __exit bpfima_exit(void)
{
    struct bpf_ima_template_entry *entry, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&measurement_list_lock, flags);
    list_for_each_entry_safe(entry, tmp, &bpf_measurement_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&measurement_list_lock, flags);

    printk(KERN_INFO "IMA measurements cleaned up. Total measurements: %d\n", 
           atomic_read(&measurement_count));
    printk(KERN_INFO "BPF-IMA module unloaded.\n");
}

module_init(bpfima_init);
module_exit(bpfima_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TORSEC");
MODULE_DESCRIPTION("BPF-IMA: eBPF-enhanced Integrity Measurement Architecture with TPM integration");
MODULE_VERSION("1.0");