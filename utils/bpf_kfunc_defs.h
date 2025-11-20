/**
 * bpf_kfunc_defs.h - Centralized eBPF kfunc declarations
 *
 * This header contains all extern kfunc declarations for use in eBPF programs.
 * These declarations allow eBPF programs to call kernel-side kfuncs.
 *
 * Include this header in your eBPF programs instead of manually declaring
 * kfuncs to avoid duplication and inconsistencies.
 */

#ifndef BPF_KFUNC_DEFS_H
#define BPF_KFUNC_DEFS_H

/* ===== IMA Measurement kfuncs ===== */

/**
 * bpf_ima_extend_measurement - Extend IMA measurement list
 * @event_name: Name of the event being measured
 * @namespace_id: Namespace/container ID (NULL for host-level measurement)
 * @dependencies: Dependency chain string
 * @additional_data: Additional data to include in measurement
 * @additional_data_len: Length of additional data
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_ima_extend_measurement(const char *event_name,
                                      const char *namespace_id,
                                      const char *dependencies,
                                      const char *additional_data,
                                      u32 additional_data_len) __ksym;

/**
 * bpf_tpm_is_available - Check if TPM is available
 * Returns: 1 if available, 0 if not, negative on error
 */
extern int bpf_tpm_is_available(void) __ksym;

/* ===== File Hashing kfuncs ===== */

/**
 * bpf_ima_file_hash_custom - Compute SHA-256 hash of a file
 * @file_scalar: Scalar value representing file pointer
 * @digest: Buffer to store the hash (must be at least 32 bytes)
 * @digest_size: Size of digest buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_ima_file_hash_custom(u64 file_scalar, u8 *digest, u32 digest_size) __ksym;

/**
 * bpf_ima_custom_file_hash_scalar - Alternative file hash function
 * @file: File structure pointer
 * @digest: Buffer to store the hash
 * @digest_size: Size of digest buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_ima_custom_file_hash_scalar(struct file *file, u8 *digest, u32 digest_size) __ksym;

/**
 * bpf_ima_hash_by_inode - Compute hash using inode number and device ID
 * @inode_number: Inode number
 * @dev_id: Device ID
 * @digest: Buffer to store the hash
 * @digest_size: Size of digest buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_ima_hash_by_inode(u64 inode_number, u32 dev_id, u8 *digest, u32 digest_size) __ksym;

/**
 * bpf_ima_hash_by_inode_content - Compute hash using inode and device details
 * @inode_number: Inode number
 * @device_major: Major device number
 * @device_minor: Minor device number
 * @digest: Buffer to store the hash
 * @digest_size: Size of digest buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_ima_hash_by_inode_content(u64 inode_number, u64 device_major, u64 device_minor, u8 *digest, u32 digest_size) __ksym;

/* ===== Container/Namespace Tracking kfuncs ===== */

/**
 * bpf_container_create_or_get - Create or get existing container tracking
 * @container_id: Container/namespace identifier
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_container_create_or_get(const char *container_id) __ksym;

/**
 * bpf_container_exists - Check if container exists
 * @container_id: Container/namespace identifier
 *
 * Returns: 1 if exists, 0 if not, negative on error
 */
extern int bpf_container_exists(const char *container_id) __ksym;

/**
 * bpf_container_get_measurement_count - Get measurement count for a container
 * @container_id: Container/namespace identifier
 *
 * Returns: Number of measurements, negative on error
 */
extern int bpf_container_get_measurement_count(const char *container_id) __ksym;

/**
 * bpf_container_get_count - Get total number of tracked containers
 * Returns: Number of containers, negative on error
 */
extern int bpf_container_get_count(void) __ksym;

/**
 * bpf_get_container_leaf_hash - Get the leaf hash for a container
 * @container_id: Container/namespace identifier
 * @leaf_hash: Buffer to store the leaf hash
 * @hash_size: Size of hash buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_get_container_leaf_hash(const char *container_id, u8 *leaf_hash, u32 hash_size) __ksym;

/* ===== Merkle Tree kfuncs ===== */

/**
 * bpf_get_merkle_root - Get the current Merkle tree root hash
 * @root_hash: Buffer to store the root hash (must be at least 32 bytes)
 * @hash_size: Size of hash buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_get_merkle_root(u8 *root_hash, u32 hash_size) __ksym;

/**
 * bpf_host_add_measurement - Add measurement to host-level list
 * @event_name: Name of the event
 * @event_data: Event data string
 * @digest: SHA-256 digest of the measurement
 * @digest_size: Size of digest (should be 32 for SHA-256)
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_host_add_measurement(const char *event_name,
                                    const char *event_data,
                                    const u8 *digest,
                                    u32 digest_size) __ksym;

/* ===== Policy Management kfuncs ===== */

/**
 * bpf_policy_update_filter_flags - Update filter flags for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_flags: New filter flag values
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_policy_update_filter_flags(const char *namespace_id, u32 new_flags) __ksym;

/**
 * bpf_policy_update_action_flags - Update action flags for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_flags: New action flag values
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_policy_update_action_flags(const char *namespace_id, u32 new_flags) __ksym;

/**
 * bpf_policy_update_min_file_size - Update minimum file size threshold
 * @namespace_id: Namespace/container identifier
 * @new_size: New minimum file size in bytes
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_policy_update_min_file_size(const char *namespace_id, u32 new_size) __ksym;

/**
 * bpf_policy_update_log_level - Update logging level for a namespace
 * @namespace_id: Namespace/container identifier
 * @new_level: New log level (0=none, 1=error, 2=info, 3=debug)
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_policy_update_log_level(const char *namespace_id, u32 new_level) __ksym;

/**
 * bpf_policy_get_changes_hash - Get hash of all policy changes
 * @namespace_id: Namespace/container identifier
 * @hash_out: Buffer to store the hash
 * @hash_size: Size of hash buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
extern int bpf_policy_get_changes_hash(const char *namespace_id, u8 *hash_out, u32 hash_size) __ksym;

#endif /* BPF_KFUNC_DEFS_H */
