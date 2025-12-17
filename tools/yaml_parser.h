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
#define MAX_CGROUP_PATTERNS 32
#define MAX_PATH_PATTERNS 64
#define MAX_HOOK_CONFIGS 16

/* Simplified structures for YAML parsing */
struct yaml_policy {
    u8 enabled;
    u32 log_level;
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

/**
 * @brief Update BPF maps with parsed policy data
 * 
 * Takes the parsed policy configuration and updates the corresponding
 * BPF maps using bpf_map_update_elem.
 * 
 * @param policy_fd File descriptor for the policy map
 * @param cgroup_fd File descriptor for the cgroup filter map
 * @param path_fd File descriptor for the path filter map
 * @param hook_fd File descriptor for the hook config map
 * @param policy Parsed policy structure
 * @param cgroup_filters Array of cgroup filter patterns
 * @param num_cgroups Number of cgroup filters
 * @param path_filters Array of path filter patterns
 * @param num_paths Number of path filters
 * @param hook_configs Array of hook configurations
 * @param num_hooks Number of hook configurations
 * @return 0 on success, negative error code on failure
 */
int update_maps_from_policy(int policy_fd, int cgroup_fd, int path_fd, int hook_fd,
                            const struct yaml_policy *policy,
                            char cgroup_filters[][256], int num_cgroups,
                            char path_filters[][256], int num_paths,
                            const struct yaml_hook_config *hook_configs, int num_hooks);

#endif /* YAML_PARSER_H */
