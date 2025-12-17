#include "bpfima_common.h"
#include "bpfima_measurements.h"

/**
 * create_measurement_entry - Create and initialize a measurement entry
 * @event_name: Event name/description
 * @event_data: Additional event data (can be NULL)
 * @dependencies: Dependencies string (can be NULL)
 * @digest: SHA256 hash digest
 * @gfp_flags: GFP allocation flags (GFP_KERNEL or GFP_ATOMIC)
 *
 * Returns: Pointer to new measurement_entry on success, NULL on failure
 */
struct measurement_entry *create_measurement_entry(const char *event_name,
                                                   const char *event_data,
                                                   const char *dependencies,
                                                   const u8 *digest,
                                                   gfp_t gfp_flags)
{
    struct measurement_entry *entry;

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

    if (dependencies && dependencies[0] != '\0')
        strscpy(entry->dependencies, dependencies, sizeof(entry->dependencies));
    else
        entry->dependencies[0] = '\0';

    memcpy(entry->digest, digest, MERKLE_HASH_SIZE);

    return entry;
}
