#ifndef BPFIMA_KFUNCS_H
#define BPFIMA_KFUNCS_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include "bpfima_common.h"

/* Measurement kfuncs */
__bpf_kfunc int bpfima_measurement_extend(const char *event_name, 
                                          const char *namespace_id, 
                                          const char *dependencies, 
                                          const char *additional_data, 
                                          u32 additional_data_len);
__bpf_kfunc int bpfima_tpm_get_pcr_value(char *pcr_buf, u32 buf_size);
__bpf_kfunc int bpfima_tpm_is_available(void);
__bpf_kfunc int bpfima_file_hash(u64 file_scalar, u8 *digest, u32 digest_size);

/* Container kfuncs */
__bpf_kfunc int bpfima_container_get_or_create(const char *container_id);
__bpf_kfunc int bpfima_container_get_count(void);
__bpf_kfunc int bpfima_container_get_measurement_count(const char *container_id);
__bpf_kfunc int bpfima_container_exists(const char *container_id);
__bpf_kfunc int bpfima_container_get_leaf_hash(const char *container_id, u8 *leaf_hash, u32 hash_size);

/* Merkle tree kfuncs */
__bpf_kfunc int bpfima_merkle_get_root(u8 *root_hash, u32 hash_size);



extern const struct btf_kfunc_id_set bpf_kfunc_example_set;

#endif /* BPFIMA_KFUNCS_H */
