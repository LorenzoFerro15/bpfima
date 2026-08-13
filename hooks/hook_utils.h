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
struct file_measure_ctx {
    struct file *file;
    const char *event_name;
    const char *cgroup_name;
    bool is_container_context;
    const char *fname;
    struct task_struct *cur;
    struct bpfima_policy_config *policy;
    u8 *out_hash;
    u64 *hash_duration;
    u64 *extend_duration;
    u64 *deps_duration;
};

struct socket_measure_ctx {
    const char *event_name;
    const char *cgroup_name;
    bool is_container_context;
    char *deps;
    int deps_actual;
    int deps_max;
    const char *additional_data;
    int additional_data_len;
    u64 *extend_duration;
};

static __attribute__((noinline, unused)) int measure_accessed_file(struct file_measure_ctx *ctx)
{
    if (!ctx || !ctx->file || !ctx->event_name) {
        bpf_printk("No file or event_name provided for hashing.\n");
        return -1;
    }

    u8 digest[32] = {0};
    u64 file_scalar = 0;
    struct file *file = ctx->file;

    if (bpf_probe_read_kernel(&file_scalar, sizeof(file_scalar), &file) != 0 || file_scalar == 0) {
        return -1;
    }

    /* Perform sleepable file hashing FIRST before accessing per-CPU scratch buffer */
    u64 start = bpf_ktime_get_ns();
    int ret = bpfima_file_hash(file_scalar, digest, sizeof(digest));
    u64 end = bpf_ktime_get_ns();
    if (ctx->hash_duration)
        *ctx->hash_duration = end - start;

    if (ret != 0) {
        bpf_printk(" failed hashing failed extending found data about it\n");
        return -1;
    }

    if (ctx->out_hash) {
        __builtin_memcpy(ctx->out_hash, digest, 32);
    }

    /* Safely access per-CPU scratch buffer AFTER sleep point */
    u32 scratch_key = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_buf_map, &scratch_key);
    if (!scratch)
        return -1;

    char *deps = scratch->buf;
    int deps_actual = 0;
    int deps_max = sizeof(scratch->buf);

    if (ctx->fname && ctx->cur && (!ctx->policy || (ctx->policy->action_flags & POLICY_ACTION_BUILD_DEPS))) {
        u64 d_start = bpf_ktime_get_ns();
        deps_actual = build_dependencies(deps, deps_max, ctx->fname, ctx->cur);
        u64 d_end = bpf_ktime_get_ns();
        if (deps_actual < 0)
            return -1;
        if (ctx->deps_duration)
            *ctx->deps_duration = d_end - d_start;
        if (!ctx->policy || ctx->policy->log_level >= 2) {
            bpf_printk(" dependencies: %s\n", deps);
        }
    }

    char *digest_hex = scratch->digest_hex;
    int written = bytes_to_hex_str(digest, 32, digest_hex, sizeof(scratch->digest_hex));
    if (written < 0) {
        bpf_printk(" failed converting digest to hex string\n");
        return -1;
    }

    start = bpf_ktime_get_ns();
    ret = bpfima_measurement_extend(ctx->event_name, 
                                    (const char *)(ctx->is_container_context ? ctx->cgroup_name : NULL), 
                                    deps, 
                                    digest_hex, 
                                    64);
    end = bpf_ktime_get_ns();
    if (ctx->extend_duration)
        *ctx->extend_duration = end - start;

    if (ret != 0) {
        bpf_printk(" Failed to process measurement: %d\n", ret);
        return -1;
    }

    bpf_printk(" Measurement processed: %s (namespace=%s)\n", 
            ctx->event_name, ctx->is_container_context ? ctx->cgroup_name : "host");
    return 0;
}

static __attribute__((noinline, unused)) int measure_socket_data(struct socket_measure_ctx *ctx)
{
    if (!ctx || !ctx->event_name)
        return -1;

    if (ctx->additional_data_len < 0 || ctx->additional_data_len >= 512) {
        bpf_printk("Invalid additional data length: %d\n", ctx->additional_data_len);
        return -1;
    }

    if (ctx->deps_actual < 0) {
        bpf_printk("Invalid dependencies length: %d\n", ctx->deps_actual);
        return -1;
    }

    u64 start = bpf_ktime_get_ns();
    int ret = bpfima_measurement_extend(ctx->event_name, 
                                        (const char *)(ctx->is_container_context ? ctx->cgroup_name : NULL), 
                                        ctx->deps, 
                                        ctx->additional_data, 
                                        ctx->additional_data_len);
    u64 end = bpf_ktime_get_ns();
    if (ctx->extend_duration)
        *ctx->extend_duration = end - start;

    if (ret != 0) {
        bpf_printk(" Failed to process measurement: %d\n", ret);
        return -1;
    }

    bpf_printk(" Measurement processed: %s (namespace=%s)\n", 
            ctx->event_name, ctx->is_container_context ? ctx->cgroup_name : "host");
    return 0;
}