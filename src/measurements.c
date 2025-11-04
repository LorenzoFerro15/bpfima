#include "bpfima_common.h"
#include "bpfima_measurements.h"

/**
 * create_measurement_entry - Create and initialize a measurement entry
 * @event_name: Event name/description
 * @event_data: Additional event data (can be NULL)
 * @digest: SHA256 hash digest
 * @gfp_flags: GFP allocation flags (GFP_KERNEL or GFP_ATOMIC)
 *
 * Returns: Pointer to new measurement_entry on success, NULL on failure
 */
struct measurement_entry *create_measurement_entry(const char *event_name,
                                                   const char *event_data,
                                                   const u8 *digest,
                                                   gfp_t gfp_flags)
{
    struct measurement_entry *entry;
    
    if (!event_name || !digest)
        return NULL;
    
    entry = kzalloc(sizeof(*entry), gfp_flags);
    if (!entry)
        return NULL;
    
    /* Initialize measurement entry */
    strscpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX + 1);
    
    if (event_data && event_data[0] != '\0')
        strscpy(entry->event_data, event_data, sizeof(entry->event_data));
    else
        entry->event_data[0] = '\0';
    
    memcpy(entry->digest, digest, MERKLE_HASH_SIZE);
    
    return entry;
}

/**
 * create_bpf_ima_entry - Create and initialize a BPF IMA template entry
 * @event_name: Event name/description
 * @event_data: Additional event data
 * @digest: SHA256 hash digest
 * @gfp_flags: GFP allocation flags (GFP_KERNEL or GFP_ATOMIC)
 *
 * Creates a BPF IMA template entry for the legacy measurement list.
 * Returns: Pointer to new bpf_ima_template_entry on success, NULL on failure
 */
struct bpf_ima_template_entry *create_bpf_ima_entry(const char *event_name,
                                                     const char *event_data,
                                                     const u8 *digest,
                                                     gfp_t gfp_flags)
{
    struct bpf_ima_template_entry *entry;
    
    if (!event_name || !digest)
        return NULL;
    
    entry = kzalloc(sizeof(*entry), gfp_flags);
    if (!entry)
        return NULL;
    
    strscpy(entry->event_name, event_name, IMA_EVENT_NAME_LEN_MAX + 1);
    
    if (event_data && event_data[0] != '\0')
        strscpy(entry->event_data, event_data, sizeof(entry->event_data));
    else
        entry->event_data[0] = '\0';
    
    memcpy(entry->digest, digest, IMA_DIGEST_SIZE);
    
    return entry;
}
