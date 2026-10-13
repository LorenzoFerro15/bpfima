#ifndef BPFIMA_POLICY_H
#define BPFIMA_POLICY_H

#include "bpfima_common.h"
#include "bpfima_kfunc_types.h"

/* Policy change tracking */
#define MAX_POLICY_CHANGES_STR 1024
#define MAX_POLICY_STRING_SIZE 512

/**
 * struct policy_change_entry - Single policy change record
 * @list: Linked list node
 * @change_hash: SHA-256 hash of the policy_string
 * @policy_string: Full policy configuration string (e.g., "enabled=1,filter_flags=0x0,action_flags=0x3F,min_file_size=0,log_level=2")
 */
struct policy_change_entry {
    struct list_head list;
    u8 change_hash[MERKLE_HASH_SIZE];
    char policy_string[MAX_POLICY_STRING_SIZE];
};

/**
 * struct bpfima_policy_namespace - Per-namespace policy configuration
 * @namespace_id: Namespace/container identifier
 * Active namespace configuration is stored only in the policy map.
 * @changes_str: Concatenated string of all policy changes (e.g., "filter_flags=0x7,action_flags=0x3F")
 * @changes_hash: SHA-256 hash of the changes_str
 * @list: Linked list node
 * @change_history: List of policy_change_entry records
 * @change_history_lock: Spinlock protecting the change history list
 */
struct bpfima_policy_namespace {
    char namespace_id[CONTAINER_ID_MAX_LEN];
    char changes_str[MAX_POLICY_CHANGES_STR];
    u8 changes_hash[MERKLE_HASH_SIZE];
    struct list_head list;
    struct list_head change_history;
    spinlock_t change_history_lock;
};

#ifdef __KERNEL__
extern struct mutex bpfima_policy_namespace_mutex;
int bpfima_policy_init(void);
void bpfima_policy_cleanup(void);
int bpfima_policy_bind_map(u32 fd);
int bpfima_policy_apply(const struct bpfima_policy_request *request);
int bpfima_policy_update_field(const char *namespace_id, const char *field, u32 value);
int bpfima_policy_read(const char *namespace_id, struct bpfima_policy_config *config);
int bpfima_policy_read_locked(const char *namespace_id, struct bpfima_policy_config *config, u64 *generation);
void bpfima_policy_get_config(struct bpfima_policy_config *config);
u64 bpfima_policy_generation(void);
u32 bpfima_policy_map_id(void);
int bpfima_policy_resolve_context(const struct bpfima_policy_context *context,
                                  struct bpfima_policy_result *result);
bool bpfima_policy_match_root(const char *text, u32 filter_flags, bool path);

int bpfima_policy_namespace_init(void);
void bpfima_policy_namespace_cleanup(void);
struct bpfima_policy_namespace *bpfima_policy_namespace_get_or_create(const char *namespace_id);
struct bpfima_policy_namespace *bpfima_policy_namespace_get_locked(const char *namespace_id);
void bpfima_policy_namespace_remove(const char *namespace_id);
int bpfima_policy_namespace_update_filter_flags(const char *namespace_id, u32 value);
int bpfima_policy_namespace_update_action_flags(const char *namespace_id, u32 value);
int bpfima_policy_namespace_update_min_file_size(const char *namespace_id, u32 value);
int bpfima_policy_namespace_update_log_level(const char *namespace_id, u32 value);
int bpfima_policy_namespace_get_changes_hash(const char *namespace_id, u8 *hash, u32 size);
__bpf_kfunc int bpfima_policy_namespace_get_config(const char *namespace_id, u32 namespace_id__sz,
                                                  void *config, u32 config__sz);
void bpfima_global_policy_cleanup_history(void);
struct list_head *bpfima_global_policy_get_history(void);
spinlock_t *bpfima_global_policy_get_history_lock(void);
bool bpfima_policy_should_ignore_cgroup(const char *text__nullable, u32 text__sz, u32 filter_flags);
bool bpfima_policy_should_ignore_path(const char *text__nullable, u32 text__sz, u32 filter_flags);
#endif

#endif /* BPFIMA_POLICY_H */
