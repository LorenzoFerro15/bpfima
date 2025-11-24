#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_merkle.h"
#include "bpfima_container.h"
#include "bpfima_measurements.h"

static const char *default_cgroup_patterns[] = {
    "/",
    "init.scope",
};

static const char *default_path_patterns[] = {
    "/proc/",
    "/sys/",
};

static struct bpfima_policy_config global_policy;
static struct bpfima_pattern_entry cgroup_patterns[MAX_IGNORE_PATTERNS];
static struct bpfima_pattern_entry path_patterns[MAX_PATH_FILTERS];
static struct bpfima_hook_config hook_configs[HOOK_MAX];
static DEFINE_SPINLOCK(policy_lock);

static LIST_HEAD(global_policy_change_history);
static DEFINE_SPINLOCK(global_policy_history_lock);

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

    memset(&global_policy, 0, sizeof(global_policy));
    global_policy.enabled = 1;
    global_policy.filter_flags = DEFAULT_FILTER_FLAGS;
    global_policy.action_flags = DEFAULT_ACTION_FLAGS;
    global_policy.min_file_size = DEFAULT_MIN_FILE_SIZE;
    global_policy.max_path_depth = DEFAULT_MAX_PATH_DEPTH;
    global_policy.log_level = DEFAULT_LOG_LEVEL;
    global_policy.merkle_history_max_size = DEFAULT_MERKLE_HISTORY_MAX_SIZE;
    global_policy.merkle_history_scope = DEFAULT_MERKLE_HISTORY_SCOPE;

    memset(cgroup_patterns, 0, sizeof(cgroup_patterns));
    for (i = 0; i < 2 && i < MAX_IGNORE_PATTERNS; i++)
    {
        strncpy(cgroup_patterns[i].pattern, default_cgroup_patterns[i], MAX_PATTERN_LEN - 1);
        cgroup_patterns[i].enabled = 1;
        cgroup_patterns[i].match_type = 0;
    }

    memset(path_patterns, 0, sizeof(path_patterns));
    for (i = 0; i < 2 && i < MAX_PATH_FILTERS; i++)
    {
        strncpy(path_patterns[i].pattern, default_path_patterns[i], MAX_PATTERN_LEN - 1);
        path_patterns[i].enabled = 1;
        path_patterns[i].match_type = 1;
    }

    memset(hook_configs, 0, sizeof(hook_configs));
    for (i = 0; i < HOOK_MAX; i++)
    {
        hook_configs[i].flags = HOOK_FLAG_ENABLED | HOOK_FLAG_TRACK_CONTAINERS | HOOK_FLAG_MEASURE_HASH;
        hook_configs[i].filter_override = 0;
        hook_configs[i].action_override = 0;
    }

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
    bpfima_global_policy_cleanup_history();
}

/**
 * bpfima_global_policy_init_history - Initialize global policy change history
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_global_policy_init_history(void)
{
    pr_info("bpfima: Initializing global policy change history\n");
    return 0;
}

/**
 * bpfima_global_policy_cleanup_history - Clean up global policy change history
 */
void bpfima_global_policy_cleanup_history(void)
{
    struct policy_change_entry *change, *tmp;
    unsigned long flags;

    pr_info("bpfima: Cleaning up global policy change history\n");

    spin_lock_irqsave(&global_policy_history_lock, flags);
    list_for_each_entry_safe(change, tmp, &global_policy_change_history, list)
    {
        list_del(&change->list);
        kfree(change);
    }
    spin_unlock_irqrestore(&global_policy_history_lock, flags);
}

/**
 * bpfima_global_policy_get_history - Get pointer to global policy change history list
 *
 * Returns: Pointer to the global policy change history list
 */
struct list_head *bpfima_global_policy_get_history(void)
{
    return &global_policy_change_history;
}

/**
 * bpfima_global_policy_get_history_lock - Get pointer to global policy history lock
 *
 * Returns: Pointer to the global policy history spinlock
 */
spinlock_t *bpfima_global_policy_get_history_lock(void)
{
    return &global_policy_history_lock;
}

/**
 * bpfima_global_policy_record_change - Record global policy change and extend Merkle root
 * @policy: Current policy configuration
 *
 * Creates a policy change entry with full policy string, hashes it,
 * and extends the Merkle root directly (global policy has no container leaf).
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpfima_global_policy_record_change(struct bpfima_policy_config *policy)
{
    struct policy_change_entry *change_entry;
    unsigned long flags;
    int ret;
    char policy_string[MAX_POLICY_STRING_SIZE];

    if (!policy)
        return -EINVAL;

    ret = snprintf(policy_string, sizeof(policy_string),
                   "enabled=%u,filter_flags=0x%x,action_flags=0x%x,min_file_size=%u,max_path_depth=%u,log_level=%u",
                   policy->enabled,
                   policy->filter_flags,
                   policy->action_flags,
                   policy->min_file_size,
                   policy->max_path_depth,
                   policy->log_level);

    if (ret < 0 || ret >= sizeof(policy_string))
    {
        pr_err("bpfima: Failed to format global policy string\n");
        return -EINVAL;
    }

    change_entry = kzalloc(sizeof(*change_entry), GFP_KERNEL);
    if (!change_entry)
        return -ENOMEM;

    strscpy(change_entry->policy_string, policy_string, MAX_POLICY_STRING_SIZE);

    ret = calculate_sha256_hash(policy_string, strlen(policy_string),
                                change_entry->change_hash);
    if (ret < 0)
    {
        pr_err("bpfima: Failed to calculate global policy change hash: %d\n", ret);
        kfree(change_entry);
        return ret;
    }

    spin_lock_irqsave(&global_policy_history_lock, flags);
    list_add_tail(&change_entry->list, &global_policy_change_history);
    spin_unlock_irqrestore(&global_policy_history_lock, flags);

    pr_info("bpfima: Recorded global policy change\n");

    char policy_hash_hex[MERKLE_HASH_SIZE * 2 + 1];
    u8 measurement_digest[MERKLE_HASH_SIZE];
    char measurement_data[512];
    int i;

    for (i = 0; i < MERKLE_HASH_SIZE; i++)
    {
        snprintf(&policy_hash_hex[i * 2], 3, "%02x", change_entry->change_hash[i]);
    }
    policy_hash_hex[MERKLE_HASH_SIZE * 2] = '\0';

    snprintf(measurement_data, sizeof(measurement_data), "global_policy_update %s", policy_hash_hex);

    ret = calculate_sha256_hash(measurement_data, strlen(measurement_data), measurement_digest);
    if (ret < 0)
    {
        pr_err("bpfima: Failed to calculate measurement hash for global policy update: %d\n", ret);
        
        spin_lock_irqsave(&global_policy_history_lock, flags);
        list_del(&change_entry->list);
        spin_unlock_irqrestore(&global_policy_history_lock, flags);
        
        kfree(change_entry);
        return ret;
    }

    ret = add_merkle_root_history_entry(measurement_digest, "global_policy");
    if (ret < 0)
    {
        pr_warn("bpfima: Failed to add merkle root history entry for global policy: %d\n", ret);
    }

    ret = extend_merkle_root(measurement_digest);
    if (ret < 0)
    {
        pr_err("bpfima: Failed to extend Merkle root with global policy change: %d\n", ret);
        
        spin_lock_irqsave(&global_policy_history_lock, flags);
        list_del(&change_entry->list);
        spin_unlock_irqrestore(&global_policy_history_lock, flags);
        
        kfree(change_entry);
        return ret;
    }

    pr_info("bpfima: Global policy change recorded and Merkle root extended\n");

    return 0;
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

    global_policy.enabled = 1;
    global_policy.filter_flags = DEFAULT_FILTER_FLAGS;
    global_policy.action_flags = DEFAULT_ACTION_FLAGS;
    global_policy.min_file_size = DEFAULT_MIN_FILE_SIZE;
    global_policy.max_path_depth = DEFAULT_MAX_PATH_DEPTH;
    global_policy.log_level = DEFAULT_LOG_LEVEL;
    global_policy.merkle_history_max_size = DEFAULT_MERKLE_HISTORY_MAX_SIZE;
    global_policy.merkle_history_scope = DEFAULT_MERKLE_HISTORY_SCOPE;

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
    int ret;

    if (!new_config)
        return -EINVAL;

    spin_lock_irqsave(&policy_lock, flags);
    memcpy(&global_policy, new_config, sizeof(global_policy));
    spin_unlock_irqrestore(&policy_lock, flags);

    pr_info("bpfima: Policy configuration updated\n");

    ret = bpfima_global_policy_record_change(new_config);
    if (ret < 0)
    {
        pr_warn("bpfima: Failed to record global policy change: %d\n", ret);
    }

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

    for (i = 0; i < MAX_IGNORE_PATTERNS; i++)
    {
        if (cgroup_patterns[i].enabled &&
            strcmp(cgroup_patterns[i].pattern, pattern) == 0)
        {
            spin_unlock_irqrestore(&policy_lock, flags);
            return 0;
        }
        if (!cgroup_patterns[i].enabled && empty_slot == -1)
        {
            empty_slot = i;
        }
    }

    if (empty_slot == -1)
    {
        spin_unlock_irqrestore(&policy_lock, flags);
        pr_err("bpfima: No space for new cgroup pattern\n");
        return -ENOMEM;
    }

    strncpy(cgroup_patterns[empty_slot].pattern, pattern, MAX_PATTERN_LEN - 1);
    cgroup_patterns[empty_slot].enabled = 1;
    cgroup_patterns[empty_slot].match_type = 0;

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

    for (i = 0; i < MAX_PATH_FILTERS; i++)
    {
        if (path_patterns[i].enabled &&
            strcmp(path_patterns[i].pattern, pattern) == 0)
        {
            spin_unlock_irqrestore(&policy_lock, flags);
            return 0;
        }
        if (!path_patterns[i].enabled && empty_slot == -1)
        {
            empty_slot = i;
        }
    }

    if (empty_slot == -1)
    {
        spin_unlock_irqrestore(&policy_lock, flags);
        pr_err("bpfima: No space for new path pattern\n");
        return -ENOMEM;
    }

    strncpy(path_patterns[empty_slot].pattern, pattern, MAX_PATTERN_LEN - 1);
    path_patterns[empty_slot].enabled = 1;
    path_patterns[empty_slot].match_type = 1;

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
