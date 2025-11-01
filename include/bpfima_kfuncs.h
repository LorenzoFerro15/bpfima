#ifndef BPFIMA_KFUNCS_H
#define BPFIMA_KFUNCS_H

#include <linux/bpf.h>
#include <linux/btf.h>
#include "bpfima_common.h"

/* BPF kfunc declarations */
__bpf_kfunc int bpf_ima_extend_measurement(const char *event_name, 
                                           const char *namespace_id, 
                                           const char *dependencies, 
                                           const char *additional_data, 
                                           u32 additional_data_len);
__bpf_kfunc int bpf_ima_get_measurement_count(void);
__bpf_kfunc int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size);
__bpf_kfunc int bpf_tpm_is_available(void);
__bpf_kfunc int bpf_ima_print_measurement_list(void);
__bpf_kfunc int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size);

/* Container tracking kfuncs */
__bpf_kfunc int bpf_container_create_or_get(const char *container_id);
__bpf_kfunc int bpf_container_add_measurement(const char *container_id, 
                                               const char *event_name, 
                                               const char *event_data, 
                                               const u8 *digest, 
                                               u32 digest_size);
__bpf_kfunc int bpf_host_add_measurement(const char *event_name, 
                                          const char *event_data, 
                                          const u8 *digest, 
                                          u32 digest_size);
__bpf_kfunc int bpf_get_merkle_root(u8 *root_hash, u32 hash_size);

/* BTF kfunc set registration */
extern const struct btf_kfunc_id_set bpf_kfunc_example_set;

#endif /* BPFIMA_KFUNCS_H */
