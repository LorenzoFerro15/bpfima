#include "../utils/headers_bpf.h"
#include "../utils/utils.h"
#include "../utils/bpf_kfunc_defs.h"

static __attribute__((noinline, unused)) struct scratch_t *bpfima_scratch(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    return task ? bpf_task_storage_get(&scratch_buf_map, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE) : NULL;
}

/* Resolve configuration, hook enablement and filters from one committed map generation. */
static __attribute__((noinline, unused)) int bpfima_policy_for_hook(u32 hook, const char *path,
                                                                  u64 size, u32 flags)
{
    struct scratch_t *scratch = bpfima_scratch();
    struct bpfima_policy_context *context;
    struct task_struct *task;
    int ret;

    if (!scratch)
        return -12;
    context = &scratch->policy_context;
    __builtin_memset(context, 0, sizeof(*context));
    task = bpf_get_current_task_btf();
    fetch_cgroup_name(task, context->cgroup, sizeof(context->cgroup));
    if (context->cgroup[0] && context->cgroup[0] != '/')
        __builtin_memcpy(context->namespace_id, context->cgroup, sizeof(context->namespace_id));
    else
        __builtin_memcpy(context->namespace_id, "default", 8);
    if (path) {
        ret = bpf_probe_read_kernel_str(context->path, sizeof(context->path), path);
        if (ret <= 0 || ret >= sizeof(context->path))
            return -36;
    }
    context->hook = hook;
    context->file_size = size;
    context->flags = flags;
    ret = bpfima_policy_resolve(context, sizeof(*context), &scratch->policy_result,
                               sizeof(scratch->policy_result));
    return ret ? ret : scratch->policy_result.skip;
}

static __attribute__((noinline, unused)) struct bpfima_policy_config *bpfima_get_policy(void)
{
    struct scratch_t *scratch = bpfima_scratch();
    return scratch ? &scratch->policy_result.config : NULL;
}

static __attribute__((noinline, unused)) bool bpfima_logging_enabled(u32 level)
{
    struct bpfima_policy_config *policy = bpfima_get_policy();
    return policy && (policy->action_flags & POLICY_ACTION_LOG_KERNEL) && policy->log_level >= level;
}

static __attribute__((noinline, unused)) const char *bpfima_current_namespace(void)
{
    struct scratch_t *scratch = bpfima_scratch();
    if (!scratch)
        return NULL;
    return (scratch->policy_result.hook.flags & HOOK_FLAG_TRACK_CONTAINERS) ||
           (scratch->policy_result.config.action_flags & POLICY_ACTION_TRACK_CONTAINER) ?
           scratch->policy_context.namespace_id : "default";
}

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
    const u8 *digest;
    const char *event_name;
    const char *cgroup_name;
    bool is_container_context;
    const char *fname;
    struct task_struct *cur;
    struct bpfima_policy_config *policy;
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

struct measurement_ctx
{
    const char *event_name;
    const char *namespace_id;
    const char *dependencies;
    const char *additional_data;
    int additional_data_len;
};

static __attribute__((noinline, unused)) int bpfima_submit_measurement(struct measurement_ctx *ctx)
{
    struct task_struct *task;
    struct scratch_t *scratch;
    struct bpfima_measurement_request *request;
    int ret;

    if (!ctx || !ctx->event_name || ctx->additional_data_len < 0 ||
        ctx->additional_data_len >= BPFIMA_EVENT_DATA_SIZE ||
        (!ctx->additional_data && ctx->additional_data_len))
        return -1;

    task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return -1;
    scratch = bpf_task_storage_get(&scratch_buf_map, task, 0,
                                  BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!scratch)
        return -1;

    request = &scratch->measurement;
    __builtin_memset(request, 0, sizeof(*request));
    ret = bpf_probe_read_kernel_str(request->event_name, sizeof(request->event_name),
                                    ctx->event_name);
    if (ret <= 1 || ret >= sizeof(request->event_name))
        return -1;

    if (ctx->namespace_id)
    {
        ret = bpf_probe_read_kernel_str(request->namespace_id, sizeof(request->namespace_id),
                                        ctx->namespace_id);
        if (ret <= 0 || ret >= sizeof(request->namespace_id))
            return -1;
    }

    if (ctx->dependencies)
    {
        ret = bpf_probe_read_kernel_str(request->dependencies, sizeof(request->dependencies),
                                        ctx->dependencies);
        if (ret <= 0 || ret >= sizeof(request->dependencies))
            return -1;
        request->flags = BPFIMA_MEASUREMENT_HAS_DEPENDENCIES;
    }

    if (ctx->additional_data_len &&
        bpf_probe_read_kernel(request->additional_data, ctx->additional_data_len,
                              ctx->additional_data))
        return -1;

    request->additional_data_len = ctx->additional_data_len;
    return bpfima_measurement_extend(request, sizeof(*request));
}

static __attribute__((noinline, unused)) int measure_accessed_file(struct file_measure_ctx *ctx)
{
    if (!ctx || !ctx->digest || !ctx->event_name) {
        bpf_printk("No digest or event_name provided for measurement.\n");
        return -1;
    }

    /* Get the current task context */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) {
        bpf_printk("hook_utils: Failed to get current task.\n");
        return -1;
    }

    /* Retrieve or create the task-local storage for this thread */
    struct scratch_t *scratch = bpf_task_storage_get(&scratch_buf_map,
                                                     task,
                                                     0,
                                                     BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!scratch)
        return -1;

    char *deps = scratch->buf;
    int deps_actual = 0;
    int deps_max = sizeof(scratch->buf);
    deps[0] = '\0';

    if (ctx->fname && ctx->cur && (!ctx->policy || (ctx->policy->action_flags & POLICY_ACTION_BUILD_DEPS))) {
        u64 d_start = bpf_ktime_get_ns();
        deps_actual = build_dependencies(deps, deps_max, ctx->fname, ctx->cur, ctx->policy ? ctx->policy->max_path_depth : 32);
        u64 d_end = bpf_ktime_get_ns();
        if (deps_actual < 0)
            return -1;
        if (ctx->deps_duration)
            *ctx->deps_duration = d_end - d_start;
        if (bpfima_logging_enabled(2)) {
            bpf_printk(" dependencies: %s\n", deps);
        }
    }

    char *digest_hex = scratch->digest_hex;
    int written = bytes_to_hex_str(ctx->digest, 32, digest_hex, sizeof(scratch->digest_hex));
    if (written < 0) {
        bpf_printk(" failed converting digest to hex string\n");
        return -1;
    }

    u64 start = bpf_ktime_get_ns();
    struct measurement_ctx measurement = {
        .event_name = ctx->event_name,
        .namespace_id = ctx->cgroup_name,
        .dependencies = deps,
        .additional_data = digest_hex,
        .additional_data_len = 64,
    };
    int ret = bpfima_submit_measurement(&measurement);
    u64 end = bpf_ktime_get_ns();
    if (ctx->extend_duration)
        *ctx->extend_duration = end - start;

    if (ret != 0) {
        bpf_printk(" Failed to process measurement: %d\n", ret);
        return ret;
    }

    if (bpfima_logging_enabled(2))
        bpf_printk(" Measurement processed: %s (namespace=%s)\n",
            ctx->event_name, ctx->is_container_context ? ctx->cgroup_name : "host");
    return 0;
}

static __attribute__((noinline, unused)) int measure_socket_data(struct socket_measure_ctx *ctx)
{
    if (!ctx || !ctx->event_name)
        return -1;

    if (ctx->additional_data_len < 0 || ctx->additional_data_len >= BPFIMA_EVENT_DATA_SIZE) {
        bpf_printk("Invalid additional data length: %d\n", ctx->additional_data_len);
        return -1;
    }

    if (ctx->deps_actual < 0) {
        bpf_printk("Invalid dependencies length: %d\n", ctx->deps_actual);
        return -1;
    }

    u64 start = bpf_ktime_get_ns();
    struct measurement_ctx measurement = {
        .event_name = ctx->event_name,
        .namespace_id = ctx->cgroup_name,
        .dependencies = ctx->deps,
        .additional_data = ctx->additional_data,
        .additional_data_len = ctx->additional_data_len,
    };
    int ret = bpfima_submit_measurement(&measurement);
    u64 end = bpf_ktime_get_ns();
    if (ctx->extend_duration)
        *ctx->extend_duration = end - start;

    if (ret != 0) {
        bpf_printk(" Failed to process measurement: %d\n", ret);
        return ret;
    }

    if (bpfima_logging_enabled(2))
        bpf_printk(" Measurement processed: %s (namespace=%s)\n",
            ctx->event_name, ctx->is_container_context ? ctx->cgroup_name : "host");
    return 0;
}
