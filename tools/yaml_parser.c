#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <yaml.h>

#include "yaml_parser.h"
#include "../include/bpfima_policy_user.h"

#define MAX_KEY_LEN 256

/* Handler function type */
typedef int (*value_handler_t)(const char *value, void *ctx);

/* Table entry for mapping keys to handlers */
struct parse_handler {
    const char *key;
    value_handler_t handler;
};

/* --- Helper functions --- */

static int parse_bool(const char *value, void *ctx)
{
    uint8_t *res = (uint8_t *)ctx;
    if (strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0)
        *res = 1;
    else if (strcasecmp(value, "false") == 0 || strcasecmp(value, "no") == 0 ||
             strcmp(value, "0") == 0)
        *res = 0;
    else
        return -1;
    return 0;
}

static int parse_int(const char *value, void *ctx)
{
    char *end;
    unsigned long result;

    if (!value || value[0] == '-' || value[0] == '\0')
        return -1;
    errno = 0;
    result = strtoul(value, &end, 10);
    if (errno || *end || result > 3)
        return -1;
    *(u32 *)ctx = result;
    return 0;
}

static int parse_u32(const char *value, u32 maximum, u32 *output)
{
    char *end;
    if (!value || !value[0] || value[0] == '-')
        return -1;
    errno = 0;
    unsigned long number = strtoul(value, &end, 0);
    if (errno || *end || number > maximum)
        return -1;
    *output = number;
    return 0;
}

/* 
 * Re-designing for the table-driven request:
 * Since we can't easily statically define "pointer to member of instance",
 * we will define handlers that take the WHOLE struct and know what to set.
 */

typedef int (*policy_field_handler)(struct yaml_policy *policy, const char *value);

static int handle_policy_enabled(struct yaml_policy *p, const char *v) { return parse_bool(v, &p->enabled); }
static int handle_policy_loglevel(struct yaml_policy *p, const char *v) { return parse_int(v, &p->log_level); }
static int handle_policy_measure(struct yaml_policy *p, const char *v) { return parse_bool(v, &p->measure_enabled); }
static int handle_policy_appraise(struct yaml_policy *p, const char *v) { return parse_bool(v, &p->appraise_enabled); }
static int handle_policy_enforce(struct yaml_policy *p, const char *v) { return parse_bool(v, &p->enforce_enabled); }
static int handle_policy_tracking(struct yaml_policy *p, const char *v) { return parse_bool(v, &p->container_tracking); }
static int handle_policy_filters(struct yaml_policy *p, const char *v) { return parse_u32(v, 255, &p->filter_flags); }
static int handle_policy_min_size(struct yaml_policy *p, const char *v) { return parse_u32(v, UINT32_MAX, &p->min_file_size); }
static int handle_policy_depth(struct yaml_policy *p, const char *v) { return parse_u32(v, 32, &p->max_path_depth); }

struct policy_dispatch_entry {
    const char *key;
    policy_field_handler handler;
};

static const struct policy_dispatch_entry policy_handlers[] = {
    { "enabled", handle_policy_enabled },
    { "log_level", handle_policy_loglevel },
    { "measure_enabled", handle_policy_measure },
    { "appraise_enabled", handle_policy_appraise },
    { "enforce_enabled", handle_policy_enforce },
    { "container_tracking", handle_policy_tracking },
    { "filter_flags", handle_policy_filters },
    { "min_file_size", handle_policy_min_size },
    { "max_path_depth", handle_policy_depth },
};

/* Generic map parser */
static int parse_generic_map(yaml_parser_t *parser, void *ctx, 
                             int (*dispatcher)(const char *key, const char *val, void *ctx))
{
    yaml_event_t event;
    char key[MAX_KEY_LEN] = {0};
    int parsing = 1;
    int ret = 0;

    while (parsing) {
        if (!yaml_parser_parse(parser, &event)) {
             fprintf(stderr, "YAML parser error: %s\n", parser->problem);
             return -1;
        }

        switch (event.type) {
        case YAML_SCALAR_EVENT:
            if (key[0] == '\0') {
                snprintf(key, sizeof(key), "%s", (char *)event.data.scalar.value);
            } else {
                if (dispatcher(key, (char *)event.data.scalar.value, ctx) < 0) {
                    fprintf(stderr, "Error: Unknown or invalid key '%s'\n", key);
                    yaml_event_delete(&event);
                    return -1;
                }
                key[0] = '\0';
            }
            break;
        case YAML_MAPPING_END_EVENT:
            parsing = 0;
            break;
        default:
            break;
        }
        yaml_event_delete(&event);
    }
    return ret;
}

/* Policy Dispatcher */
static int policy_dispatcher(const char *key, const char *val, void *ctx)
{
    struct yaml_policy *policy = (struct yaml_policy *)ctx;
    for (size_t i = 0; i < sizeof(policy_handlers)/sizeof(policy_handlers[0]); i++) {
        if (strcmp(key, policy_handlers[i].key) == 0) {
            return policy_handlers[i].handler(policy, val);
        }
    }
    return -1;
}

int parse_policy_section(yaml_parser_t *parser, struct yaml_policy *policy)
{
    return parse_generic_map(parser, policy, policy_dispatcher);
}

/* --- Hook Config Parsing --- */

typedef int (*hook_field_handler)(struct yaml_hook_config *hook, const char *value);

static int handle_hook_name(struct yaml_hook_config *h, const char *v) { 
    snprintf(h->hook_name, sizeof(h->hook_name), "%s", v); 
    return 0; 
}
static int handle_hook_enabled(struct yaml_hook_config *h, const char *v) { return parse_bool(v, &h->enabled); }
static int handle_hook_measure(struct yaml_hook_config *h, const char *v) { return parse_bool(v, &h->measure); }
static int handle_hook_appraise(struct yaml_hook_config *h, const char *v) { return parse_bool(v, &h->appraise); }
static int handle_hook_enforce(struct yaml_hook_config *h, const char *v) { return parse_bool(v, &h->enforce); }

static const struct {
    const char *key;
    hook_field_handler handler;
} hook_handlers[] = {
    { "name", handle_hook_name },
    { "enabled", handle_hook_enabled },
    { "measure", handle_hook_measure },
    { "appraise", handle_hook_appraise },
    { "enforce", handle_hook_enforce },
};

static int hook_dispatcher(const char *key, const char *val, void *ctx)
{
    struct yaml_hook_config *hook = (struct yaml_hook_config *)ctx;
    for (size_t i = 0; i < sizeof(hook_handlers)/sizeof(hook_handlers[0]); i++) {
        if (strcmp(key, hook_handlers[i].key) == 0) {
            return hook_handlers[i].handler(hook, val);
        }
    }
    return -1;
}

static int parse_hook_config(yaml_parser_t *parser, struct yaml_hook_config *config)
{
    return parse_generic_map(parser, config, hook_dispatcher);
}

/* --- Sequence Parsing --- */

static int parse_string_sequence(yaml_parser_t *parser, char patterns[][256], int max_patterns)
{
    yaml_event_t event;
    int count = 0;
    int in_sequence = 1;

    while (in_sequence) {
        if (!yaml_parser_parse(parser, &event)) return -1;

        switch (event.type) {
        case YAML_SCALAR_EVENT:
            if (count >= max_patterns || event.data.scalar.length >= MAX_PATTERN_LEN) {
                yaml_event_delete(&event);
                return -1;
            }
            if (count < max_patterns) {
                snprintf(patterns[count], 255, "%s", (char *)event.data.scalar.value);
                patterns[count][255] = '\0';
                count++;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:
            in_sequence = 0;
            break;
        default: break;
        }
        yaml_event_delete(&event);
    }
    return count;
}

/* --- Filters Section Parsing --- */

int parse_filters_section(yaml_parser_t *parser,
                          char cgroup_filters[][256], int max_cgroups,
                          char path_filters[][256], int max_paths)
{
    yaml_event_t event;
    char key[MAX_KEY_LEN] = {0};
    int in_filters = 1;

    while (in_filters) {
        if (!yaml_parser_parse(parser, &event)) return -1;

        switch (event.type) {
        case YAML_SCALAR_EVENT:
            if (key[0] == '\0') {
                snprintf(key, sizeof(key), "%s", (char *)event.data.scalar.value);
            }
            break;
        case YAML_SEQUENCE_START_EVENT:
            if (strcmp(key, "cgroup_patterns") == 0) {
                if (parse_string_sequence(parser, cgroup_filters, max_cgroups) < 0) {
                    yaml_event_delete(&event);
                    return -1;
                }
            } else if (strcmp(key, "path_patterns") == 0) {
                if (parse_string_sequence(parser, path_filters, max_paths) < 0) {
                    yaml_event_delete(&event);
                    return -1;
                }
            }
            key[0] = '\0';
            break;
        case YAML_MAPPING_END_EVENT:
            in_filters = 0;
            break;
        default: break;
        }
        yaml_event_delete(&event);
    }
    return 0;
}

/* --- Hooks List Parsing --- */

int parse_hooks_section(yaml_parser_t *parser, struct yaml_hook_config *hook_configs, int max_hooks)
{
    yaml_event_t event;
    int count = 0;
    int in_hooks = 1;

    while (in_hooks) {
        if (!yaml_parser_parse(parser, &event)) return -1;

        switch (event.type) {
        case YAML_MAPPING_START_EVENT:
            if (count < max_hooks) {
                if (parse_hook_config(parser, &hook_configs[count]) == 0) {
                    count++;
                }
            }
            break;
        case YAML_SEQUENCE_END_EVENT:
            in_hooks = 0;
            break;
        default: break;
        }
        yaml_event_delete(&event);
    }
    return count;
}

/* --- Main Parser --- */

int parse_yaml_policy(const char *config_file,
                      struct yaml_policy *policy,
                      char cgroup_filters[][256], int max_cgroups,
                      char path_filters[][256], int max_paths,
                      struct yaml_hook_config *hook_configs, int max_hooks)
{
    FILE *file;
    yaml_parser_t parser;
    yaml_event_t event;
    int ret = -1;
    char key[MAX_KEY_LEN] = {0};
    int done = 0;

    file = fopen(config_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open '%s': %s\n", config_file, strerror(errno));
        return -1;
    }

    if (!yaml_parser_initialize(&parser)) {
        fclose(file);
        return -1;
    }
    yaml_parser_set_input_file(&parser, file);

    /* Zero out everything first */
    memset(policy, 0, sizeof(*policy));
    policy->max_path_depth = DEFAULT_MAX_PATH_DEPTH;
    memset(cgroup_filters, 0, max_cgroups * 256);
    memset(path_filters, 0, max_paths * 256);
    memset(hook_configs, 0, max_hooks * sizeof(*hook_configs));

    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
             fprintf(stderr, "YAML Error: %s\n", parser.problem);
             goto cleanup;
        }

        switch (event.type) {
        case YAML_SCALAR_EVENT:
            snprintf(key, sizeof(key), "%s", (char *)event.data.scalar.value);
            break;
        case YAML_MAPPING_START_EVENT:
            if (strcmp(key, "policy") == 0) {
                if (parse_policy_section(&parser, policy) < 0) goto cleanup;
            } else if (strcmp(key, "filters") == 0) {
                if (parse_filters_section(&parser, cgroup_filters, max_cgroups,
                                          path_filters, max_paths) < 0) goto cleanup;
            }
            key[0] = '\0';
            break;
        case YAML_SEQUENCE_START_EVENT:
            if (strcmp(key, "hooks") == 0) {
                if (parse_hooks_section(&parser, hook_configs, max_hooks) < 0) goto cleanup;
            }
            key[0] = '\0';
            break;
        case YAML_DOCUMENT_END_EVENT:
        case YAML_STREAM_END_EVENT:
            done = 1;
            break;
        default: break;
        }
        yaml_event_delete(&event);
    }

    ret = 0;
    printf("Successfully parsed YAML policy from '%s'\n", config_file);

cleanup:
    yaml_parser_delete(&parser);
    fclose(file);
    return ret;
}

/* --- Map Updater --- */
static int get_hook_id(const char *name)
{
    const char *names[] = {"lsm_bprm_check_security", "lsm_file_open", "lsm_file_post_open",
                           "lsm_mmap_file", "lsm_socket_connect", "lsm_container_events",
                           "kprobe_file_open", "lsm_inode_setattr"};

    for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!strcmp(name, names[i]))
            return i;
    }
    return -1;
}

int build_policy_from_yaml(struct bpfima_policy_snapshot *snapshot,
                            const struct yaml_policy *policy,
                            char cgroup_filters[][256], int num_cgroups,
                            char path_filters[][256], int num_paths,
                            const struct yaml_hook_config *hooks, int num_hooks)
{
    if (!snapshot || !policy || num_cgroups < 0 || num_cgroups > MAX_IGNORE_PATTERNS ||
        num_paths < 0 || num_paths > MAX_PATH_FILTERS || num_hooks < 0 || num_hooks > MAX_HOOK_CONFIGS)
        return -EINVAL;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->config.enabled = policy->enabled;
    snapshot->config.log_level = policy->log_level;
    snapshot->config.max_path_depth = policy->max_path_depth;
    snapshot->config.filter_flags = policy->filter_flags;
    snapshot->config.min_file_size = policy->min_file_size;
    snapshot->config.merkle_history_max_size = DEFAULT_MERKLE_HISTORY_MAX_SIZE;
    if (policy->appraise_enabled || policy->enforce_enabled)
        return -EOPNOTSUPP;
    if (!policy->measure_enabled)
        return -EINVAL; /* Recording and TPM extension are one mandatory transaction. */
    snapshot->config.action_flags = POLICY_ACTION_EXTEND_TPM | POLICY_ACTION_LOG_SECURITYFS | POLICY_ACTION_BUILD_DEPS;
    if (policy->log_level)
        snapshot->config.action_flags |= POLICY_ACTION_LOG_KERNEL;
    if (policy->container_tracking)
        snapshot->config.action_flags |= POLICY_ACTION_TRACK_CONTAINER;
    for (int i = 0; i < HOOK_MAX; i++)
        snapshot->hooks[i].flags = HOOK_FLAG_ENABLED | HOOK_FLAG_TRACK_CONTAINERS | HOOK_FLAG_MEASURE_HASH;
    snapshot->hooks[HOOK_KPROBE_FILE_OPEN].flags = 0;
    for (int i = 0; i < num_hooks; i++) {
        if (!hooks[i].hook_name[0])
            continue;
        if (hooks[i].appraise || hooks[i].enforce)
            return -EOPNOTSUPP;
        int id = get_hook_id(hooks[i].hook_name);
        if (id < 0)
            return -EINVAL;
        snapshot->hooks[id].flags = (hooks[i].enabled ? HOOK_FLAG_ENABLED : 0) |
                                   (hooks[i].measure ? HOOK_FLAG_MEASURE_HASH : 0) |
                                   (policy->container_tracking ? HOOK_FLAG_TRACK_CONTAINERS : 0);
    }
    for (int i = 0; i < num_cgroups + num_paths; i++) {
        const char *pattern = i < num_cgroups ? cgroup_filters[i] : path_filters[i - num_cgroups];
        struct bpfima_pattern_entry *entry = i < num_cgroups ? &snapshot->cgroups[i] : &snapshot->paths[i - num_cgroups];
        if (strlen(pattern) >= MAX_PATTERN_LEN)
            return -EINVAL;
        if (pattern[0]) {
            snprintf(entry->pattern, sizeof(entry->pattern), "%s", pattern);
            entry->enabled = 1;
            entry->match_type = 1;
        }
    }
    return 0;
}

/* One complete little-endian request replaces the former independent map writes. */
int apply_policy_snapshot(const char *namespace_id, const struct bpfima_policy_snapshot *snapshot)
{
    struct bpfima_policy_request request = {0};
    char path[PATH_MAX];
    const char *directory = getenv("BPFIMA_SECURITYFS_DIR");
    ssize_t written;
    int fd, ret;

    if (!snapshot || (namespace_id && strlen(namespace_id) >= BPFIMA_NAMESPACE_SIZE))
        return -EINVAL;
    request.version = BPFIMA_POLICY_VERSION;
    request.record.snapshot = *snapshot;
    if (namespace_id)
        snprintf(request.record.namespace_id, sizeof(request.record.namespace_id), "%s", namespace_id);
    bpfima_policy_encode_request(&request);
    snprintf(path, sizeof(path), "%s/policy_apply", directory ? directory : "/sys/kernel/security/bpfima");
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    written = write(fd, &request, sizeof(request));
    ret = written == sizeof(request) ? 0 : written < 0 ? -errno : -EIO;
    close(fd);
    return ret;
}
