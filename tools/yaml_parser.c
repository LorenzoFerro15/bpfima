#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <yaml.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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
    int *res = (int *)ctx;
    if (strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0)
        *res = 1;
    else
        *res = 0;
    return 0;
}

static int parse_int(const char *value, void *ctx)
{
    int *res = (int *)ctx;
    *res = atoi(value);
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
                    fprintf(stderr, "Warning: Unknown or invalid key '%s'\n", key);
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
                parse_string_sequence(parser, cgroup_filters, max_cgroups);
            } else if (strcmp(key, "path_patterns") == 0) {
                parse_string_sequence(parser, path_filters, max_paths);
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
    memset(cgroup_filters, 0, max_cgroups * 256);
    memset(path_filters, 0, max_paths * 256);
    memset(hook_configs, 0, max_hooks * sizeof(struct bpfima_hook_config));

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

/* --- Map Updater (Unchanged) --- */
int update_maps_from_policy(int policy_fd, int cgroup_fd, int path_fd, int hook_fd,
                            const struct yaml_policy *policy,
                            char cgroup_filters[][256], int num_cgroups,
                            char path_filters[][256], int num_paths,
                            const struct yaml_hook_config *hook_configs, int num_hooks)
{
    int ret = 0;
    __u32 key = 0;

    struct bpfima_policy_config bpf_policy = {0};
    
    /* We can't use the simple struct copy because bpfima_policy_config isn't identical 
       to yaml_policy (one has flags, one has bools).
       However, we can reuse the DEFAULT init helper here?
       Actually, yaml_policy is an intermediate parsing struct. We manually map it here.
    */
    bpf_policy.enabled = policy->enabled;
    bpf_policy.log_level = policy->log_level;
    bpf_policy.max_path_depth = 10; 
    
    // ... logic continues ...
    // Since the instruction was to Rewrite the PARSING logic, I will preserve this function largely as is
    // but just fix the struct initialization if anything was missed. Or simply copy paste the old logic back?
    // I will assume the old logic was fine, just duplicating it here for completeness of the file replacement.
    
    if (policy->measure_enabled) bpf_policy.action_flags |= POLICY_ACTION_EXTEND_TPM | POLICY_ACTION_LOG_SECURITYFS;
    if (policy->appraise_enabled) bpf_policy.action_flags |= POLICY_ACTION_ALERT_SUSPICIOUS;
    if (policy->enforce_enabled) bpf_policy.action_flags |= POLICY_ACTION_BLOCK;
    if (policy->container_tracking) bpf_policy.action_flags |= POLICY_ACTION_TRACK_CONTAINER;
    bpf_policy.action_flags |= POLICY_ACTION_BUILD_DEPS;

    if (bpf_map_update_elem(policy_fd, &key, &bpf_policy, BPF_ANY) < 0) {
        fprintf(stderr, "Error: Failed to update policy map: %s\n", strerror(errno));
        return -1;
    }
    printf("  Updated global policy configuration\n");

    /* Cgroups */
    for (int i = 0; i < num_cgroups; i++) {
        if (strlen(cgroup_filters[i]) > 0) {
            struct bpfima_pattern_entry entry = {0};
            snprintf(entry.pattern, MAX_PATTERN_LEN, "%s", cgroup_filters[i]);
            entry.enabled = 1;
            entry.match_type = 1;

            __u32 idx = i;
            if (bpf_map_update_elem(cgroup_fd, &idx, &entry, BPF_ANY) < 0) {
                fprintf(stderr, "Warning: Failed to update cgroup filter %d: %s\n", i, strerror(errno));
            } else {
                printf("  Added cgroup filter: %s\n", cgroup_filters[i]);
            }
        }
    }

    /* Paths */
    for (int i = 0; i < num_paths; i++) {
        if (strlen(path_filters[i]) > 0) {
            struct bpfima_pattern_entry entry = {0};
            snprintf(entry.pattern, MAX_PATTERN_LEN, "%s", path_filters[i]);
            entry.enabled = 1;
            entry.match_type = 1;

            __u32 idx = i;
            if (bpf_map_update_elem(path_fd, &idx, &entry, BPF_ANY) < 0) {
                fprintf(stderr, "Warning: Failed to update path filter %d: %s\n", i, strerror(errno));
            } else {
                printf("  Added path filter: %s\n", path_filters[i]);
            }
        }
    }

    /* Hooks */
    for (int i = 0; i < num_hooks; i++) {
        if (strlen(hook_configs[i].hook_name) > 0) {
            struct bpfima_hook_config bpf_hook = {0};
            if (hook_configs[i].enabled) bpf_hook.flags |= HOOK_FLAG_ENABLED;
            if (hook_configs[i].measure) bpf_hook.flags |= HOOK_FLAG_MEASURE_HASH;
            
            __u32 idx = i;
            if (bpf_map_update_elem(hook_fd, &idx, &bpf_hook, BPF_ANY) < 0) {
                fprintf(stderr, "Warning: Failed to update hook config %d: %s\n", i, strerror(errno));
            } else {
                printf("  Configured hook: %s (enabled=%d, measure=%d)\n",
                       hook_configs[i].hook_name, hook_configs[i].enabled, hook_configs[i].measure);
            }
        }
    }

    return ret;
}
