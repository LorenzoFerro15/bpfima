#include "../utils/headers_bpf.h"
#include "../utils/utils.h"
#include "../utils/bpf_kfunc_defs.h"

/* Measure file access and extend IMA measurement
    * 
    * Parameters:
    * - file: pointer to struct file representing the accessed file
    * - event_name: name of the event for measurement
    * - cgroup_name: name of the cgroup (namespace) if in container context
    * - is_container_context: boolean indicating if in container context
    * - deps: dependency chain string
    * - deps_actual: actual length of dependencies string
    * - deps_max: maximum length of dependencies string buffer
    * 
    * Returns:
    * - 0 on success, -1 on failure
*/
static __always_inline int measure_accessed_file(
                                                struct file *file, 
                                                const char *event_name,
                                                const char *cgroup_name,
                                                bool is_container_context,
                                                char *deps,
                                                int deps_actual,
                                                int deps_max)
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
            ret = bpf_ima_file_hash_custom(file_scalar, digest, sizeof(digest));
            if (ret == 0) {
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
                ret = bpf_ima_extend_measurement(event_name, 
                                                (const char *)(is_container_context ? cgroup_name : NULL), 
                                                deps, 
                                                digest_hex, 
                                                64);
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