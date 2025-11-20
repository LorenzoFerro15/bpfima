#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <yaml.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "yaml_parser.h"
#include "../include/bpfima_policy_user.h"

#define MAX_YAML_DEPTH 10
#define MAX_KEY_LEN 256

/**
 * @brief Helper to parse a boolean value from YAML
 */
static int parse_bool(const char *value)
{
    if (strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief Parse the policy section
 */
int parse_policy_section(yaml_parser_t *parser, struct yaml_policy *policy)
{
    yaml_event_t event;
    char key[MAX_KEY_LEN] = {0};
    int in_policy = 1;

    while (in_policy)
    {
        if (!yaml_parser_parse(parser, &event))
        {
            fprintf(stderr, "YAML parser error: %s\n", parser->problem);
            return -1;
        }

        switch (event.type)
        {
        case YAML_SCALAR_EVENT:
            if (key[0] == '\0')
            {
                strncpy(key, (char *)event.data.scalar.value, MAX_KEY_LEN - 1);
            }
            else
            {
                const char *value = (char *)event.data.scalar.value;

                if (strcmp(key, "enabled") == 0)
                {
                    policy->enabled = parse_bool(value);
                }
                else if (strcmp(key, "log_level") == 0)
                {
                    policy->log_level = atoi(value);
                }
                else if (strcmp(key, "measure_enabled") == 0)
                {
                    policy->measure_enabled = parse_bool(value);
                }
                else if (strcmp(key, "appraise_enabled") == 0)
                {
                    policy->appraise_enabled = parse_bool(value);
                }
                else if (strcmp(key, "enforce_enabled") == 0)
                {
                    policy->enforce_enabled = parse_bool(value);
                }
                else if (strcmp(key, "container_tracking") == 0)
                {
                    policy->container_tracking = parse_bool(value);
                }

                key[0] = '\0';
            }
            break;

        case YAML_MAPPING_END_EVENT:
            in_policy = 0;
            break;

        default:
            break;
        }

        yaml_event_delete(&event);
    }

    return 0;
}

/**
 * @brief Parse a sequence of string patterns
 */
static int parse_string_sequence(yaml_parser_t *parser, char patterns[][256], int max_patterns)
{
    yaml_event_t event;
    int count = 0;
    int in_sequence = 1;

    while (in_sequence)
    {
        if (!yaml_parser_parse(parser, &event))
        {
            fprintf(stderr, "YAML parser error: %s\n", parser->problem);
            return -1;
        }

        switch (event.type)
        {
        case YAML_SCALAR_EVENT:
            if (count < max_patterns)
            {
                strncpy(patterns[count], (char *)event.data.scalar.value, 255);
                patterns[count][255] = '\0';
                count++;
            }
            else
            {
                fprintf(stderr, "Warning: Too many patterns, skipping\n");
            }
            break;

        case YAML_SEQUENCE_END_EVENT:
            in_sequence = 0;
            break;

        default:
            break;
        }

        yaml_event_delete(&event);
    }

    return count;
}

/**
 * @brief Parse the filters section
 */
int parse_filters_section(yaml_parser_t *parser,
                          char cgroup_filters[][256], int max_cgroups,
                          char path_filters[][256], int max_paths)
{
    yaml_event_t event;
    char key[MAX_KEY_LEN] = {0};
    int in_filters = 1;

    while (in_filters)
    {
        if (!yaml_parser_parse(parser, &event))
        {
            fprintf(stderr, "YAML parser error: %s\n", parser->problem);
            return -1;
        }

        switch (event.type)
        {
        case YAML_SCALAR_EVENT:
            strncpy(key, (char *)event.data.scalar.value, MAX_KEY_LEN - 1);
            break;

        case YAML_SEQUENCE_START_EVENT:
            if (strcmp(key, "cgroup_patterns") == 0)
            {
                parse_string_sequence(parser, cgroup_filters, max_cgroups);
            }
            else if (strcmp(key, "path_patterns") == 0)
            {
                parse_string_sequence(parser, path_filters, max_paths);
            }
            key[0] = '\0';
            break;

        case YAML_MAPPING_END_EVENT:
            in_filters = 0;
            break;

        default:
            break;
        }

        yaml_event_delete(&event);
    }

    return 0;
}

/**
 * @brief Parse a single hook configuration
 */
static int parse_hook_config(yaml_parser_t *parser, struct yaml_hook_config *config)
{
    yaml_event_t event;
    char key[MAX_KEY_LEN] = {0};
    int in_hook = 1;

    while (in_hook)
    {
        if (!yaml_parser_parse(parser, &event))
        {
            fprintf(stderr, "YAML parser error: %s\n", parser->problem);
            return -1;
        }

        switch (event.type)
        {
        case YAML_SCALAR_EVENT:
            if (key[0] == '\0')
            {
                strncpy(key, (char *)event.data.scalar.value, MAX_KEY_LEN - 1);
            }
            else
            {
                const char *value = (char *)event.data.scalar.value;

                if (strcmp(key, "name") == 0)
                {
                    strncpy(config->hook_name, value, sizeof(config->hook_name) - 1);
                }
                else if (strcmp(key, "enabled") == 0)
                {
                    config->enabled = parse_bool(value);
                }
                else if (strcmp(key, "measure") == 0)
                {
                    config->measure = parse_bool(value);
                }
                else if (strcmp(key, "appraise") == 0)
                {
                    config->appraise = parse_bool(value);
                }
                else if (strcmp(key, "enforce") == 0)
                {
                    config->enforce = parse_bool(value);
                }

                key[0] = '\0';
            }
            break;

        case YAML_MAPPING_END_EVENT:
            in_hook = 0;
            break;

        default:
            break;
        }

        yaml_event_delete(&event);
    }

    return 0;
}

/**
 * @brief Parse the hooks section
 */
int parse_hooks_section(yaml_parser_t *parser,
                        struct yaml_hook_config *hook_configs,
                        int max_hooks)
{
    yaml_event_t event;
    int count = 0;
    int in_hooks = 1;

    while (in_hooks)
    {
        if (!yaml_parser_parse(parser, &event))
        {
            fprintf(stderr, "YAML parser error: %s\n", parser->problem);
            return -1;
        }

        switch (event.type)
        {
        case YAML_MAPPING_START_EVENT:
            if (count < max_hooks)
            {
                if (parse_hook_config(parser, &hook_configs[count]) == 0)
                {
                    count++;
                }
            }
            break;

        case YAML_SEQUENCE_END_EVENT:
            in_hooks = 0;
            break;

        default:
            break;
        }

        yaml_event_delete(&event);
    }

    return count;
}

/**
 * @brief Main YAML policy parsing function
 */
int parse_yaml_policy(const char *config_file,
                      struct yaml_policy *policy,
                      char cgroup_filters[][256], int max_cgroups,
                      char path_filters[][256], int max_paths,
                      struct yaml_hook_config *hook_configs, int max_hooks)
{
    FILE *file = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    int ret = -1;
    char key[MAX_KEY_LEN] = {0};

    file = fopen(config_file, "r");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open config file '%s': %s\n",
                config_file, strerror(errno));
        return -1;
    }

    if (!yaml_parser_initialize(&parser))
    {
        fprintf(stderr, "Error: Failed to initialize YAML parser\n");
        fclose(file);
        return -1;
    }

    yaml_parser_set_input_file(&parser, file);

    memset(policy, 0, sizeof(*policy));
    memset(cgroup_filters, 0, max_cgroups * 256);
    memset(path_filters, 0, max_paths * 256);
    memset(hook_configs, 0, max_hooks * sizeof(struct bpfima_hook_config));

    int done = 0;
    while (!done)
    {
        if (!yaml_parser_parse(&parser, &event))
        {
            fprintf(stderr, "YAML parser error: %s\n", parser.problem);
            goto cleanup;
        }

        switch (event.type)
        {
        case YAML_STREAM_START_EVENT:
        case YAML_DOCUMENT_START_EVENT:
            break;

        case YAML_SCALAR_EVENT:
            strncpy(key, (char *)event.data.scalar.value, MAX_KEY_LEN - 1);
            break;

        case YAML_MAPPING_START_EVENT:
            if (strcmp(key, "policy") == 0)
            {
                if (parse_policy_section(&parser, policy) < 0)
                {
                    goto cleanup;
                }
            }
            else if (strcmp(key, "filters") == 0)
            {
                if (parse_filters_section(&parser, cgroup_filters, max_cgroups,
                                          path_filters, max_paths) < 0)
                {
                    goto cleanup;
                }
            }
            key[0] = '\0';
            break;

        case YAML_SEQUENCE_START_EVENT:
            if (strcmp(key, "hooks") == 0)
            {
                if (parse_hooks_section(&parser, hook_configs, max_hooks) < 0)
                {
                    goto cleanup;
                }
            }
            key[0] = '\0';
            break;

        case YAML_DOCUMENT_END_EVENT:
        case YAML_STREAM_END_EVENT:
            done = 1;
            break;

        default:
            break;
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

/**
 * @brief Update BPF maps with parsed policy data
 */
int update_maps_from_policy(int policy_fd, int cgroup_fd, int path_fd, int hook_fd,
                            const struct yaml_policy *policy,
                            char cgroup_filters[][256], int num_cgroups,
                            char path_filters[][256], int num_paths,
                            const struct yaml_hook_config *hook_configs, int num_hooks)
{
    int ret = 0;
    __u32 key = 0;

    struct bpfima_policy_config bpf_policy = {
        .enabled = policy->enabled,
        .log_level = policy->log_level,
        .filter_flags = 0,
        .action_flags = 0,
        .min_file_size = 0,
        .max_path_depth = 10,
    };

    if (policy->measure_enabled)
    {
        bpf_policy.action_flags |= POLICY_ACTION_EXTEND_TPM | POLICY_ACTION_LOG_SECURITYFS;
    }
    if (policy->appraise_enabled)
    {
        bpf_policy.action_flags |= POLICY_ACTION_ALERT_SUSPICIOUS;
    }
    if (policy->enforce_enabled)
    {
        bpf_policy.action_flags |= POLICY_ACTION_BLOCK;
    }
    if (policy->container_tracking)
    {
        bpf_policy.action_flags |= POLICY_ACTION_TRACK_CONTAINER;
    }

    bpf_policy.action_flags |= POLICY_ACTION_BUILD_DEPS;

    if (bpf_map_update_elem(policy_fd, &key, &bpf_policy, BPF_ANY) < 0)
    {
        fprintf(stderr, "Error: Failed to update policy map: %s\n", strerror(errno));
        return -1;
    }
    printf("  Updated global policy configuration\n");

    for (int i = 0; i < num_cgroups; i++)
    {
        if (strlen(cgroup_filters[i]) > 0)
        {
            struct bpfima_pattern_entry entry = {0};
            strncpy(entry.pattern, cgroup_filters[i], MAX_PATTERN_LEN - 1);
            entry.enabled = 1;
            entry.match_type = 1;

            __u32 idx = i;
            if (bpf_map_update_elem(cgroup_fd, &idx, &entry, BPF_ANY) < 0)
            {
                fprintf(stderr, "Warning: Failed to update cgroup filter %d: %s\n",
                        i, strerror(errno));
            }
            else
            {
                printf("  Added cgroup filter: %s\n", cgroup_filters[i]);
            }
        }
    }

    for (int i = 0; i < num_paths; i++)
    {
        if (strlen(path_filters[i]) > 0)
        {
            struct bpfima_pattern_entry entry = {0};
            strncpy(entry.pattern, path_filters[i], MAX_PATTERN_LEN - 1);
            entry.enabled = 1;
            entry.match_type = 1;

            __u32 idx = i;
            if (bpf_map_update_elem(path_fd, &idx, &entry, BPF_ANY) < 0)
            {
                fprintf(stderr, "Warning: Failed to update path filter %d: %s\n",
                        i, strerror(errno));
            }
            else
            {
                printf("  Added path filter: %s\n", path_filters[i]);
            }
        }
    }

    for (int i = 0; i < num_hooks; i++)
    {
        if (strlen(hook_configs[i].hook_name) > 0)
        {
            struct bpfima_hook_config bpf_hook = {0};

            if (hook_configs[i].enabled)
            {
                bpf_hook.flags |= HOOK_FLAG_ENABLED;
            }
            if (hook_configs[i].measure)
            {
                bpf_hook.flags |= HOOK_FLAG_MEASURE_HASH;
            }

            __u32 idx = i;
            if (bpf_map_update_elem(hook_fd, &idx, &bpf_hook, BPF_ANY) < 0)
            {
                fprintf(stderr, "Warning: Failed to update hook config %d (%s): %s\n",
                        i, hook_configs[i].hook_name, strerror(errno));
            }
            else
            {
                printf("  Configured hook: %s (enabled=%d, measure=%d)\n",
                       hook_configs[i].hook_name,
                       hook_configs[i].enabled,
                       hook_configs[i].measure);
            }
        }
    }

    return ret;
}
