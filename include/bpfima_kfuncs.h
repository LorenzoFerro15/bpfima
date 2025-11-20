#ifndef BPFIMA_KFUNCS_H
#define BPFIMA_KFUNCS_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include "bpfima_common.h"
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, 
                                           const char *namespace_id, 
                                           const char *dependencies, 
                                           const char *additional_data, 
                                           u32 additional_data_len);
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size);
__bpf_kfunc int bpf_tpm_is_available(void);
__bpf_kfunc int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size);

__bpf_kfunc int bpf_container_create_or_get(const char *container_id);
__bpf_kfunc int bpf_get_merkle_root(u8 *root_hash, u32 hash_size);

__bpf_kfunc int bpf_container_get_measurement_count(const char *container_id);
__bpf_kfunc int bpf_container_get_count(void);
__bpf_kfunc int bpf_container_exists(const char *container_id);
__bpf_kfunc int bpf_get_container_leaf_hash(const char *container_id, u8 *leaf_hash, u32 hash_size);

__bpf_kfunc int bpf_policy_update_filter_flags(const char *namespace_id, u32 new_flags);
__bpf_kfunc int bpf_policy_update_action_flags(const char *namespace_id, u32 new_flags);
__bpf_kfunc int bpf_policy_update_min_file_size(const char *namespace_id, u32 new_size);
__bpf_kfunc int bpf_policy_update_log_level(const char *namespace_id, u32 new_level);
__bpf_kfunc int bpf_policy_get_changes_hash(const char *namespace_id, u8 *hash_out, u32 hash_size);

extern const struct btf_kfunc_id_set bpf_kfunc_example_set;

#endif /* BPFIMA_KFUNCS_H */
