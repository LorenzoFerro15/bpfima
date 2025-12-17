#ifndef BPFIMA_POLICY_DEFAULTS_H
#define BPFIMA_POLICY_DEFAULTS_H

#ifdef __KERNEL__
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

#endif /* BPFIMA_POLICY_DEFAULTS_H */
