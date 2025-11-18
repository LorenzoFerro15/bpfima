#include "bpfima_common.h"
#include "bpfima_policy.h"

/* Default ignore patterns for cgroups */
static const char *default_cgroup_patterns[] = {
    "/",
    "init.scope",
};

/* Default ignore patterns for paths */
static const char *default_path_patterns[] = {
    "/proc/",
    "/sys/",
};

/* Global policy configuration (kernel-side storage) */
static struct bpfima_policy_config global_policy;
static struct bpfima_pattern_entry cgroup_patterns[MAX_IGNORE_PATTERNS];
static struct bpfima_pattern_entry path_patterns[MAX_PATH_FILTERS];
static struct bpfima_hook_config hook_configs[HOOK_MAX];
static DEFINE_SPINLOCK(policy_lock);

/**
 * bpfima_policy_init - Initialize policy subsystem with default values
 *
 * Sets up default policy configuration that will be used by eBPF programs
 * through BPF maps. The default policy enables basic filtering and actions.
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_init(void)
{
    int i;
    unsigned long flags;

    pr_info("bpfima: Initializing policy subsystem\n");

    spin_lock_irqsave(&policy_lock, flags);

    /* Initialize global policy with defaults */
    memset(&global_policy, 0, sizeof(global_policy));
    global_policy.enabled = 1;
    global_policy.filter_flags = DEFAULT_FILTER_FLAGS;
    global_policy.action_flags = DEFAULT_ACTION_FLAGS;
    global_policy.min_file_size = DEFAULT_MIN_FILE_SIZE;
    global_policy.max_path_depth = DEFAULT_MAX_PATH_DEPTH;
    global_policy.log_level = DEFAULT_LOG_LEVEL;

    /* Initialize cgroup patterns */
    memset(cgroup_patterns, 0, sizeof(cgroup_patterns));
    for (i = 0; i < 2 && i < MAX_IGNORE_PATTERNS; i++) {
        strncpy(cgroup_patterns[i].pattern, default_cgroup_patterns[i], MAX_PATTERN_LEN - 1);
        cgroup_patterns[i].enabled = 1;
        cgroup_patterns[i].match_type = 0; /* Exact match */
    }

    /* Initialize path patterns */
    memset(path_patterns, 0, sizeof(path_patterns));
    for (i = 0; i < 2 && i < MAX_PATH_FILTERS; i++) {
        strncpy(path_patterns[i].pattern, default_path_patterns[i], MAX_PATTERN_LEN - 1);
        path_patterns[i].enabled = 1;
        path_patterns[i].match_type = 1; /* Prefix match */
    }

    /* Initialize hook configurations - all enabled by default */
    memset(hook_configs, 0, sizeof(hook_configs));
    for (i = 0; i < HOOK_MAX; i++) {
        hook_configs[i].flags = HOOK_FLAG_ENABLED | HOOK_FLAG_TRACK_CONTAINERS | HOOK_FLAG_MEASURE_HASH;
        hook_configs[i].filter_override = 0;
        hook_configs[i].action_override = 0;
    }

    /* Disable some hooks by default */
    hook_configs[HOOK_LSM_SOCKET_CONNECT].flags = 0; /* Disabled */

    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Policy subsystem initialized with default configuration\n");
    return 0;
}

/**
 * bpfima_policy_cleanup - Clean up policy subsystem
 */
void bpfima_policy_cleanup(void)
{
    pr_info("bpfima: Cleaning up policy subsystem\n");
    /* Nothing to do for now - everything is statically allocated */
}

/**
 * bpfima_policy_set_default - Reset policy to default values
 *
 * Returns: 0 on success
 */
int bpfima_policy_set_default(void)
{
    unsigned long flags;

    spin_lock_irqsave(&policy_lock, flags);
    
    /* Re-initialize to defaults */
    global_policy.enabled = 1;
    global_policy.filter_flags = DEFAULT_FILTER_FLAGS;
    global_policy.action_flags = DEFAULT_ACTION_FLAGS;
    global_policy.min_file_size = DEFAULT_MIN_FILE_SIZE;
    global_policy.max_path_depth = DEFAULT_MAX_PATH_DEPTH;
    global_policy.log_level = DEFAULT_LOG_LEVEL;

    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Policy reset to defaults\n");
    return 0;
}

/**
 * bpfima_policy_get - Get current policy configuration
 *
 * Returns: Pointer to current policy configuration
 */
struct bpfima_policy_config *bpfima_policy_get(void)
{
    return &global_policy;
}

/**
 * bpfima_policy_update - Update policy configuration
 * @new_config: New policy configuration to apply
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_update(struct bpfima_policy_config *new_config)
{
    unsigned long flags;

    if (!new_config)
        return -EINVAL;

    spin_lock_irqsave(&policy_lock, flags);
    memcpy(&global_policy, new_config, sizeof(global_policy));
    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Policy configuration updated\n");
    return 0;
}

/**
 * bpfima_policy_add_cgroup_pattern - Add or update cgroup ignore pattern
 * @pattern: Pattern string to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_add_cgroup_pattern(const char *pattern)
{
    unsigned long flags;
    int i, empty_slot = -1;

    if (!pattern || strlen(pattern) >= MAX_PATTERN_LEN)
        return -EINVAL;

    spin_lock_irqsave(&policy_lock, flags);

    /* Check if pattern already exists or find empty slot */
    for (i = 0; i < MAX_IGNORE_PATTERNS; i++) {
        if (cgroup_patterns[i].enabled && 
            strcmp(cgroup_patterns[i].pattern, pattern) == 0) {
            spin_unlock_irqrestore(&policy_lock, flags);
            return 0; /* Pattern already exists */
        }
        if (!cgroup_patterns[i].enabled && empty_slot == -1) {
            empty_slot = i;
        }
    }

    if (empty_slot == -1) {
        spin_unlock_irqrestore(&policy_lock, flags);
        pr_err("bpfima: No space for new cgroup pattern\n");
        return -ENOMEM;
    }

    strncpy(cgroup_patterns[empty_slot].pattern, pattern, MAX_PATTERN_LEN - 1);
    cgroup_patterns[empty_slot].enabled = 1;
    cgroup_patterns[empty_slot].match_type = 0; /* Exact match by default */

    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Added cgroup pattern: %s\n", pattern);
    return 0;
}

/**
 * bpfima_policy_add_path_pattern - Add or update path ignore pattern
 * @pattern: Pattern string to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_add_path_pattern(const char *pattern)
{
    unsigned long flags;
    int i, empty_slot = -1;

    if (!pattern || strlen(pattern) >= MAX_PATTERN_LEN)
        return -EINVAL;

    spin_lock_irqsave(&policy_lock, flags);

    /* Check if pattern already exists or find empty slot */
    for (i = 0; i < MAX_PATH_FILTERS; i++) {
        if (path_patterns[i].enabled && 
            strcmp(path_patterns[i].pattern, pattern) == 0) {
            spin_unlock_irqrestore(&policy_lock, flags);
            return 0; /* Pattern already exists */
        }
        if (!path_patterns[i].enabled && empty_slot == -1) {
            empty_slot = i;
        }
    }

    if (empty_slot == -1) {
        spin_unlock_irqrestore(&policy_lock, flags);
        pr_err("bpfima: No space for new path pattern\n");
        return -ENOMEM;
    }

    strncpy(path_patterns[empty_slot].pattern, pattern, MAX_PATTERN_LEN - 1);
    path_patterns[empty_slot].enabled = 1;
    path_patterns[empty_slot].match_type = 1; /* Prefix match by default */

    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Added path pattern: %s\n", pattern);
    return 0;
}

/**
 * bpfima_policy_set_hook_config - Set configuration for a specific hook
 * @hook: Hook identifier
 * @config: Hook configuration to apply
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_policy_set_hook_config(enum bpfima_hook_id hook, struct bpfima_hook_config *config)
{
    unsigned long flags;

    if (hook >= HOOK_MAX || !config)
        return -EINVAL;

    spin_lock_irqsave(&policy_lock, flags);
    memcpy(&hook_configs[hook], config, sizeof(struct bpfima_hook_config));
    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Hook %d configuration updated\n", hook);
    return 0;
}

/**
 * bpfima_policy_get_cgroup_patterns - Get cgroup patterns array
 *
 * Returns: Pointer to cgroup patterns array
 */
struct bpfima_pattern_entry *bpfima_policy_get_cgroup_patterns(void)
{
    return cgroup_patterns;
}

/**
 * bpfima_policy_get_path_patterns - Get path patterns array
 *
 * Returns: Pointer to path patterns array
 */
struct bpfima_pattern_entry *bpfima_policy_get_path_patterns(void)
{
    return path_patterns;
}

/**
 * bpfima_policy_get_hook_config - Get configuration for a specific hook
 * @hook: Hook identifier
 *
 * Returns: Pointer to hook configuration, NULL if invalid
 */
struct bpfima_hook_config *bpfima_policy_get_hook_config(enum bpfima_hook_id hook)
{
    if (hook >= HOOK_MAX)
        return NULL;
    return &hook_configs[hook];
}
