#include "../utils/headers_bpf.h"
#include "../utils/utils.h"
#include "../utils/bpf_kfunc_defs.h"

#define TEMP_BUFFER_LEN 32

/* --------------------------------------------------------- */

/* Measure file access and extend IMA measurement
    * 
    * @param file: pointer to struct file representing the accessed file
    * @param event_name: name of the event for measurement
    * @param cgroup_name: name of the cgroup (namespace) if in container context
    * @param is_container_context: boolean indicating if in container context
    * @param deps: dependency chain string
    * @param deps_actual: actual length of dependencies string
    * @param deps_max: maximum length of dependencies string buffer
    * @param out_hash: output buffer to store the computed file hash
    * 
    * @returns
    * - 0 on success, -1 on failure
*/
static __always_inline int measure_accessed_file(
                                                struct file *file, 
                                                const char *event_name,
                                                const char *cgroup_name,
                                                bool is_container_context,
                                                char *deps,
                                                int deps_actual,
                                                int deps_max,
                                                u8 *out_hash,
                                                u64 *hash_duration,
                                                u64 *extend_duration)
{
    if (!file) {
        bpf_printk("No file provided for hashing.\n");
        return -1;
    }

    if (deps_actual < 0) {
        bpf_printk("Invalid dependencies length: %d\n", deps_actual);
        return -1;
    }

    if (file) {
        int ret;
        u8 digest[32] = {0};
        u64 file_scalar = 0;

        if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) == 0 && file_scalar != 0) {
            u64 start = bpf_ktime_get_ns();
            ret = bpfima_file_hash(file_scalar, digest, sizeof(digest));
            u64 end = bpf_ktime_get_ns();
            if (hash_duration) *hash_duration = end - start;

            if (ret == 0) {
                if (out_hash) {
                    __builtin_memcpy(out_hash, digest, 32);
                }
                print_hex_digest(digest, 32);
                char digest_hex[65] = {0};
                
                bpf_printk(" deps_actual=%d deps_max=%d\n", deps_actual, deps_max);

                int written = bytes_to_hex_str(digest, 32, digest_hex, sizeof(digest_hex));
                if (written < 0) {
                    bpf_printk(" failed converting digest to hex string\n");
                    return -1;
                }

                deps[(deps_actual < deps_max ? deps_actual : deps_max - 1)] = '\0';

                digest_hex[64] = '\0';
                
                start = bpf_ktime_get_ns();
                ret = bpfima_measurement_extend(event_name, 
                                                (const char *)(is_container_context ? cgroup_name : NULL), 
                                                deps, 
                                                digest_hex, 
                                                64);
                end = bpf_ktime_get_ns();
                if (extend_duration) *extend_duration = end - start;
                if (ret == 0) {
                    bpf_printk(" Measurement processed: %s (namespace=%s)\n", 
                            event_name, is_container_context ? cgroup_name : "host");
                } else {
                    bpf_printk(" Failed to process measurement: %d\n", ret);
                    return -1;
                }
            }
            else {
                bpf_printk(" failed hashing failed extending found data about it");
                return -1;
            }
        }
    }
    return 0;
}

/* Measure socket connection and extend IMA measurement
    * 
    * @param event_name: name of the event for measurement
    * @param cgroup_name: name of the cgroup (namespace) if in container context
    * @param is_container_context: boolean indicating if in container context
    * @param deps: dependency chain string
    * @param deps_actual: actual length of dependencies string
    * @param deps_max: maximum length of dependencies string buffer
    * @param additional_data: additional data string for measurement
    * @param additional_data_len: length of additional data string
    * 
    * @returns
    * - 0 on success, -1 on failure
*/  
static __always_inline int measure_socket_data(const char *event_name,
                                               const char *cgroup_name,
                                               bool is_container_context,
                                               char *deps,
                                               int deps_actual,
                                               int deps_max,
                                               const char *additional_data,
                                               int additional_data_len,
                                               u64 *extend_duration)
{
    if (additional_data_len < 0 || additional_data_len >= 512) {
        bpf_printk("Invalid additional data length: %d\n", additional_data_len);
        return -1;
    }

    if (deps_actual < 0) {
        bpf_printk("Invalid dependencies length: %d\n", deps_actual);
        return -1;
    }

    u64 start = bpf_ktime_get_ns();
    int ret = bpfima_measurement_extend(event_name, 
                                        (const char *)(is_container_context ? cgroup_name : NULL), 
                                        deps, 
                                        additional_data, 
                                        additional_data_len);
    u64 end = bpf_ktime_get_ns();
    if (extend_duration) *extend_duration = end - start;
    if (ret == 0) {
        bpf_printk(" Measurement processed: %s (namespace=%s)\n", 
                event_name, is_container_context ? cgroup_name : "host");
    } else {
        bpf_printk(" Failed to process measurement: %d\n", ret);
        return -1;
    }

    return 0;
}