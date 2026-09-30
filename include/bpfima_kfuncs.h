#ifndef BPFIMA_KFUNCS_H
#define BPFIMA_KFUNCS_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include "bpfima_common.h"

/* Every memory argument has an adjacent verifier-checked __sz parameter. */
__bpf_kfunc int bpfima_measurement_extend(const void *data, u32 data__sz);
__bpf_kfunc int bpfima_tpm_get_pcr_value(char *pcr_buf, u32 pcr_buf__sz);
__bpf_kfunc int bpfima_tpm_is_available(void);

/* Container kfuncs */
__bpf_kfunc int bpfima_container_get_or_create(const char *container_id, u32 container_id__sz);
__bpf_kfunc int bpfima_container_get_count(void);
__bpf_kfunc int bpfima_container_get_measurement_count(const char *container_id, u32 container_id__sz);
__bpf_kfunc int bpfima_container_exists(const char *container_id, u32 container_id__sz);
__bpf_kfunc int bpfima_container_get_leaf_hash(const char *container_id, u32 container_id__sz,
                                           u8 *leaf_hash, u32 leaf_hash__sz);

/* Merkle tree kfuncs */
__bpf_kfunc int bpfima_merkle_get_root(u8 *root_hash, u32 root_hash__sz);

/* Policy kfuncs */
__bpf_kfunc int bpfima_policy_update_filter_flags(const char *namespace_id, u32 namespace_id__sz, u32 new_flags);
__bpf_kfunc int bpfima_policy_update_action_flags(const char *namespace_id, u32 namespace_id__sz, u32 new_flags);
__bpf_kfunc int bpfima_policy_update_min_file_size(const char *namespace_id, u32 namespace_id__sz, u32 new_size);
__bpf_kfunc int bpfima_policy_update_log_level(const char *namespace_id, u32 namespace_id__sz, u32 new_level);
__bpf_kfunc int bpfima_policy_get_changes_hash(const char *namespace_id, u32 namespace_id__sz,
                                           u8 *hash_out, u32 hash_out__sz);
__bpf_kfunc int bpfima_policy_namespace_get_config(const char *namespace_id, u32 namespace_id__sz,
                                                void *config, u32 config__sz);
__bpf_kfunc bool bpfima_policy_should_ignore_cgroup(const char *cgroup_name__nullable,
                                                 u32 cgroup_name__sz, u32 filter_flags);
__bpf_kfunc bool bpfima_policy_should_ignore_path(const char *path__nullable,
                                               u32 path__sz, u32 filter_flags);

extern const struct btf_kfunc_id_set bpf_kfunc_example_set;

#endif /* BPFIMA_KFUNCS_H */
