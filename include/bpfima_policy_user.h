#ifndef BPFIMA_POLICY_USER_H
#define BPFIMA_POLICY_USER_H

#include <stdint.h>
#include <endian.h>
#include "bpfima_kfunc_types.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* SecurityFS requests use a fixed little-endian wire encoding on every host. */
static inline void bpfima_policy_encode_request(struct bpfima_policy_request *request)
{
    struct bpfima_policy_config *config = &request->record.snapshot.config;
    request->version = htole32(request->version);
    request->expected_generation = htole64(request->expected_generation);
    config->filter_flags = htole32(config->filter_flags);
    config->action_flags = htole32(config->action_flags);
    config->min_file_size = htole32(config->min_file_size);
    config->max_path_depth = htole32(config->max_path_depth);
    config->log_level = htole32(config->log_level);
    config->merkle_history_max_size = htole32(config->merkle_history_max_size);
    for (int i = 0; i < HOOK_MAX; i++) {
        struct bpfima_hook_config *hook = &request->record.snapshot.hooks[i];
        hook->flags = htole32(hook->flags);
        hook->filter_override = htole32(hook->filter_override);
        hook->action_override = htole32(hook->action_override);
    }
}

#endif /* BPFIMA_POLICY_USER_H */
