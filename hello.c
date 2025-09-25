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

#define IMA_DIGEST_SIZE 20
#define IMA_EVENT_NAME_LEN_MAX 255
#define TPM_PCR_INDEX 10

struct bpf_ima_template_entry {
    struct list_head list;
    char event_name[IMA_EVENT_NAME_LEN_MAX + 1];
    char event_data[256];
    u8 digest[IMA_DIGEST_SIZE];
};

static LIST_HEAD(bpf_measurement_list);
static DEFINE_SPINLOCK(measurement_list_lock);
static atomic_t measurement_count = ATOMIC_INIT(0);

__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);
__bpf_kfunc int bpf_ima_is_enabled(void);
__bpf_kfunc int bpf_get_file_path(struct file *file, char *buf, u32 buf_size);
__bpf_kfunc int bpf_ima_measure_data(const char *event_label, const char *event_name, const char *data, u32 data_len);
__bpf_kfunc int bpf_ima_file_info(struct file *file, char *hash_buf, u32 buf_size);
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len);
__bpf_kfunc int bpf_ima_get_measurement_count(void);
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size);

__bpf_kfunc_start_defs();

/* String search functionality for eBPF programs */
__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz)
{
    if (substr__sz == 0)
        return 0;
    if (substr__sz > str__sz)
        return -1;
    
    for (size_t i = 0; i <= str__sz - substr__sz; i++)
    {
        size_t j = 0;
        while (j < substr__sz && str[i + j] == substr[j])
            j++;
        if (j == substr__sz)
            return i;
    }
    return -1;
}

/* Check if IMA is enabled in kernel configuration */
__bpf_kfunc int bpf_ima_is_enabled(void)
{
#ifdef CONFIG_IMA
    return 1;
#else
    return 0;
#endif
}

/* Extract file path from file structure for monitoring */
__bpf_kfunc int bpf_get_file_path(struct file *file, char *buf, u32 buf_size)
{
    if (!file || !buf || buf_size == 0)
        return -EINVAL;
    
    if (!file->f_path.dentry || !file->f_path.dentry->d_name.name)
        return -ENOENT;
    
    const char *name = file->f_path.dentry->d_name.name;
    u32 len = strlen(name);
    
    if (len >= buf_size)
        len = buf_size - 1;
    
    memcpy(buf, name, len);
    buf[len] = '\0';
    
    return len;
}

/* Log measurement data in IMA template format */
__bpf_kfunc int bpf_ima_measure_data(const char *event_label, const char *event_name, const char *data, u32 data_len)
{
    if (!event_label || !event_name || !data || data_len == 0)
        return -EINVAL;
    
    printk(KERN_INFO "IMA_TEMPLATE: label=%s name=%s data_len=%u data=%.32s%s\n", 
           event_label, event_name, data_len, data, 
           data_len > 32 ? "..." : "");
    
    return 0;
}

/* Generate file information string for IMA measurements */
__bpf_kfunc int bpf_ima_file_info(struct file *file, char *hash_buf, u32 buf_size)
{
    if (!file || !hash_buf || buf_size == 0)
        return -EINVAL;
    
    if (!file->f_path.dentry)
        return -ENOENT;
        
    const char *filename = file->f_path.dentry->d_name.name;
    u32 len = strlen(filename);
    
    snprintf(hash_buf, buf_size, "file:%s:ino:%lu", 
             filename, file->f_inode ? file->f_inode->i_ino : 0);
    
    printk(KERN_INFO "IMA_FILE_INFO: %s\n", hash_buf);
    return len;
}

/* Calculate SHA1 hash of data for integrity measurements */
static int calculate_sha1_hash(const void *data, size_t len, u8 *digest)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha1", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
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

/* Add measurement to list and simulate PCR extension */
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len)
{
    struct bpf_ima_template_entry *entry;
    unsigned long flags;
    int ret = 0;

    if (!event_name || !data || data_len == 0)
        return -EINVAL;

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;

    strncpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX);
    entry->event_name[IMA_EVENT_NAME_LEN_MAX] = '\0';
    
    strncpy(entry->event_data, data, min_t(u32, data_len, sizeof(entry->event_data) - 1));
    entry->event_data[sizeof(entry->event_data) - 1] = '\0';

    ret = calculate_sha1_hash(data, data_len, entry->digest);
    if (ret) {
        kfree(entry);
        return ret;
    }

    spin_lock_irqsave(&measurement_list_lock, flags);
    list_add_tail(&entry->list, &bpf_measurement_list);
    atomic_inc(&measurement_count);
    spin_unlock_irqrestore(&measurement_list_lock, flags);

    printk(KERN_INFO "IMA_EXTEND: event=%s count=%d digest=%*ph\n", 
           event_name, atomic_read(&measurement_count), IMA_DIGEST_SIZE, entry->digest);
    
    return atomic_read(&measurement_count);
}

/* Return total number of measurements in the list */
__bpf_kfunc int bpf_ima_get_measurement_count(void)
{
    return atomic_read(&measurement_count);
}

/* Simulate TPM PCR value based on measurement count */
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size)
{
    if (!pcr_buf || buf_size < 41)
        return -EINVAL;
        
    snprintf(pcr_buf, buf_size, "PCR%d_MEASUREMENTS_%d_HASH_SIMULATION", 
             TPM_PCR_INDEX, atomic_read(&measurement_count));
             
    return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_ID_FLAGS(func, bpf_ima_is_enabled)
BTF_ID_FLAGS(func, bpf_get_file_path)
BTF_ID_FLAGS(func, bpf_ima_measure_data)
BTF_ID_FLAGS(func, bpf_ima_file_info)
BTF_ID_FLAGS(func, bpf_ima_extend_measurement)
BTF_ID_FLAGS(func, bpf_ima_get_measurement_count)
BTF_ID_FLAGS(func, bpf_ima_get_pcr_value)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* Initialize module and register kfuncs */
static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpf_kfunc_example: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: Module loaded successfully\n");
    return 0;
}

/* Clean up module and measurement list */
static void __exit hello_exit(void)
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
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("IMA-like measurement system with eBPF kfuncs");
MODULE_VERSION("1.0");