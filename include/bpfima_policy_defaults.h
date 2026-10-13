#ifndef BPFIMA_POLICY_DEFAULTS_H
#define BPFIMA_POLICY_DEFAULTS_H

#include "bpfima_kfunc_types.h"

#if defined(__KERNEL__) && !defined(BPFIMA_POLICY_TEST)
#include <linux/string.h>
#define bpfima_strcpy(d, s, l) strscpy(d, s, l)
#else
#include <stdio.h>
#include <string.h>
#define bpfima_strcpy(d, s, l) snprintf(d, l, "%s", s)
#endif

static inline void bpfima_init_default_config(struct bpfima_policy_config *policy)
{
    policy->enabled = 1;
    policy->filter_flags = DEFAULT_FILTER_FLAGS;
    policy->action_flags = DEFAULT_ACTION_FLAGS;
    policy->min_file_size = DEFAULT_MIN_FILE_SIZE;
    policy->max_path_depth = DEFAULT_MAX_PATH_DEPTH;
    policy->log_level = DEFAULT_LOG_LEVEL;
    policy->merkle_history_max_size = DEFAULT_MERKLE_HISTORY_MAX_SIZE;
    policy->merkle_history_scope = DEFAULT_MERKLE_HISTORY_SCOPE;
}

static inline void bpfima_init_default_cgroup_patterns(struct bpfima_pattern_entry *patterns, int max_patterns)
{
    /* Clear array first */
    // Note: Caller responsible for memset/clearing if needed, but we set values here.
    // In kernel we might not have memset available as a simple function in a header without includes.
    // We assume caller has zeroed structure or we set specific fields.

    if (max_patterns > 0) {
        bpfima_strcpy(patterns[0].pattern, DEFAULT_CGROUP_PATTERN_1, MAX_PATTERN_LEN);
        patterns[0].enabled = 1;
        patterns[0].match_type = 0;
    }
    if (max_patterns > 1) {
        bpfima_strcpy(patterns[1].pattern, DEFAULT_CGROUP_PATTERN_2, MAX_PATTERN_LEN);
        patterns[1].enabled = 1;
        patterns[1].match_type = 0;
    }
}

static inline void bpfima_init_default_path_patterns(struct bpfima_pattern_entry *patterns, int max_patterns)
{
    if (max_patterns > 0) {
        bpfima_strcpy(patterns[0].pattern, DEFAULT_PATH_PATTERN_1, MAX_PATTERN_LEN);
        patterns[0].enabled = 1;
        patterns[0].match_type = 1;
    }
    if (max_patterns > 1) {
        bpfima_strcpy(patterns[1].pattern, DEFAULT_PATH_PATTERN_2, MAX_PATTERN_LEN);
        patterns[1].enabled = 1;
        patterns[1].match_type = 1;
    }
}

static inline void bpfima_init_default_snapshot(struct bpfima_policy_snapshot *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    bpfima_init_default_config(&snapshot->config);
    bpfima_init_default_cgroup_patterns(snapshot->cgroups, MAX_IGNORE_PATTERNS);
    bpfima_init_default_path_patterns(snapshot->paths, MAX_PATH_FILTERS);
    for (int i = 0; i < HOOK_MAX; i++)
        snapshot->hooks[i].flags = HOOK_FLAG_ENABLED | HOOK_FLAG_TRACK_CONTAINERS | HOOK_FLAG_MEASURE_HASH;
    snapshot->hooks[HOOK_KPROBE_FILE_OPEN].flags = 0;
}

/* Filter bits skip measurements: AND expands coverage, action bits compose with OR. */
static inline void bpfima_policy_merge_config(const struct bpfima_policy_config *root,
                                             const struct bpfima_policy_config *extra,
                                             struct bpfima_policy_config *effective)
{
    *effective = *root;
    if (!extra)
        return;
    effective->enabled |= extra->enabled;
    effective->filter_flags &= extra->filter_flags;
    effective->action_flags |= extra->action_flags;
    if (extra->min_file_size < effective->min_file_size)
        effective->min_file_size = extra->min_file_size;
    if (extra->max_path_depth > effective->max_path_depth)
        effective->max_path_depth = extra->max_path_depth;
    if (extra->log_level > effective->log_level)
        effective->log_level = extra->log_level;
}

static inline int bpfima_pattern_matches(const struct bpfima_pattern_entry *entry, const char *text)
{
    size_t text_len, pattern_len;

    if (!entry->enabled || !text || !text[0])
        return 0;
    pattern_len = strlen(entry->pattern);
    text_len = strlen(text);
    switch (entry->match_type) {
    case 0: return strcmp(text, entry->pattern) == 0;
    case 1: return strncmp(text, entry->pattern, pattern_len) == 0;
    case 2: return text_len >= pattern_len && strcmp(text + text_len - pattern_len, entry->pattern) == 0;
    case 3: return strstr(text, entry->pattern) != NULL;
    default: return 0;
    }
}

/* Conservative subset check: uncertain pattern relationships cannot weaken root coverage. */
static inline int bpfima_pattern_is_subset(const struct bpfima_pattern_entry *extra,
                                          const struct bpfima_pattern_entry *root)
{
    if (!extra->enabled)
        return 1;
    if (!root->enabled)
        return 0;
    if (extra->match_type == 0)
        return bpfima_pattern_matches(root, extra->pattern);
    if (extra->match_type == root->match_type) {
        if (extra->match_type == 1)
            return strncmp(extra->pattern, root->pattern, strlen(root->pattern)) == 0;
        if (extra->match_type == 2) {
            size_t len = strlen(extra->pattern), root_len = strlen(root->pattern);
            return len >= root_len && strcmp(extra->pattern + len - root_len, root->pattern) == 0;
        }
        if (extra->match_type == 3)
            return strstr(extra->pattern, root->pattern) != NULL;
    }
    return 0;
}

#endif /* BPFIMA_POLICY_DEFAULTS_H */
