/**
 * @file yaml_parser.h
 * @brief YAML policy configuration parser for BPF IMA
 * 
 * This module provides functions to parse YAML policy files and convert them
 * into data structures that can be used to update BPF maps.
 */

#ifndef YAML_PARSER_H
#define YAML_PARSER_H

#include <yaml.h>
#include "../include/bpfima_policy_user.h"

/* Maximum array sizes for parsing */
#define MAX_CGROUP_PATTERNS MAX_IGNORE_PATTERNS
#define MAX_PATH_PATTERNS MAX_PATH_FILTERS
#define MAX_HOOK_CONFIGS 16

/* Simplified structures for YAML parsing */
struct yaml_policy {
    u8 enabled;
    u32 log_level;
    u32 filter_flags;
    u32 min_file_size;
    u32 max_path_depth;
    u8 measure_enabled;
    u8 appraise_enabled;
    u8 enforce_enabled;
    u8 container_tracking;
};

struct yaml_hook_config {
    char hook_name[64];
    u8 enabled;
    u8 measure;
    u8 appraise;
    u8 enforce;
};

/**
 * @brief Parse a YAML policy configuration file
 * 
 * Reads and parses a YAML file containing policy configuration including
 * global settings, filters, actions, and hook-specific configurations.
 * 
 * @param config_file Path to the YAML configuration file
 * @param policy Output pointer to store the parsed global policy
 * @param cgroup_filters Output array to store parsed cgroup filters
 * @param max_cgroups Maximum number of cgroup filters to parse
 * @param path_filters Output array to store parsed path filters
 * @param max_paths Maximum number of path filters to parse
 * @param hook_configs Output array to store parsed hook configurations
 * @param max_hooks Maximum number of hook configurations to parse
 * @return 0 on success, negative error code on failure
 */
int parse_yaml_policy(const char *config_file,
                      struct yaml_policy *policy,
                      char cgroup_filters[][256], int max_cgroups,
                      char path_filters[][256], int max_paths,
                      struct yaml_hook_config *hook_configs, int max_hooks);

/**
 * @brief Parse the global policy section from YAML
 * 
 * @param parser YAML parser instance
 * @param policy Output pointer to store parsed policy settings
 * @return 0 on success, negative error code on failure
 */
int parse_policy_section(yaml_parser_t *parser, struct yaml_policy *policy);

/**
 * @brief Parse the filters section from YAML
 * 
 * @param parser YAML parser instance
 * @param cgroup_filters Output array for cgroup filter patterns
 * @param max_cgroups Maximum number of cgroup filters
 * @param path_filters Output array for path filter patterns
 * @param max_paths Maximum number of path filters
 * @return 0 on success, negative error code on failure
 */
int parse_filters_section(yaml_parser_t *parser,
                         char cgroup_filters[][256], int max_cgroups,
                         char path_filters[][256], int max_paths);

/**
 * @brief Parse the hooks section from YAML
 * 
 * @param parser YAML parser instance
 * @param hook_configs Output array for hook configurations
 * @param max_hooks Maximum number of hook configurations
 * @return 0 on success, negative error code on failure
 */
int parse_hooks_section(yaml_parser_t *parser,
                       struct yaml_hook_config *hook_configs,
                       int max_hooks);

int build_policy_from_yaml(struct bpfima_policy_snapshot *snapshot,
                            const struct yaml_policy *policy,
                            char cgroup_filters[][256], int num_cgroups,
                            char path_filters[][256], int num_paths,
                            const struct yaml_hook_config *hooks, int num_hooks);
int apply_policy_snapshot(const char *namespace_id, const struct bpfima_policy_snapshot *snapshot);

#endif /* YAML_PARSER_H */
