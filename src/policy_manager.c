#include "bpfima_common.h"
#include "bpfima_policy.h"
#include "bpfima_merkle.h"
#include "bpfima_policy_defaults.h"
#include "bpfima_kfunc_buffer.h"
#ifndef BPFIMA_POLICY_TEST
#include <linux/rcupdate.h>
#endif

/* Only the map holds active configuration. Kernel lists hold audit history only. */
static struct bpf_map __rcu *policy_map;
static DEFINE_SPINLOCK(policy_snapshot_lock);
static LIST_HEAD(global_policy_change_history);
static DEFINE_SPINLOCK(global_policy_history_lock);

static struct bpfima_policy_state *map_state(struct bpf_map *map, u32 key)
{
    struct bpfima_policy_state *state;
    rcu_read_lock();
    state = map->ops->map_lookup_elem(map, &key);
    rcu_read_unlock();
    return state;
}

static struct bpfima_policy_state *active_state(struct bpf_map *map)
{
    struct bpfima_policy_state *control = map_state(map, 0);
    u64 generation = smp_load_acquire(&control->generation);

    return generation ? map_state(map, 1 + (generation & 1)) : NULL;
}

static int namespace_index(const struct bpfima_policy_state *state, const char *id)
{
    if (!id || !id[0])
        return 0;
    for (u32 i = 1; i <= state->namespace_count; i++)
        if (!strcmp(state->records[i].namespace_id, id))
            return i;
    return -ENOENT;
}

static bool valid_namespace(const char *id)
{
    if (!memchr(id, '\0', BPFIMA_NAMESPACE_SIZE) || bpfima_validate_namespace(id) || !strcmp(id, "[root]"))
        return false;
    for (const unsigned char *p = (const unsigned char *)id; *p; p++)
        if (*p <= ' ' || *p == ':' || *p == 127)
            return false;
    return true;
}

/* Normalize padding and inactive entries before hashing the complete configuration. */
static int normalize_snapshot(const struct bpfima_policy_snapshot *input,
                               struct bpfima_policy_snapshot *output)
{
    const struct bpfima_policy_config *config = &input->config;
    struct bpfima_policy_config *clean = &output->config;
    const u32 required = POLICY_ACTION_EXTEND_TPM | POLICY_ACTION_LOG_SECURITYFS;

    if (config->action_flags & (POLICY_ACTION_ALERT_SUSPICIOUS | POLICY_ACTION_BLOCK))
        return -EOPNOTSUPP;
    if (config->enabled > 1 || config->filter_flags & ~0xffU ||
        config->action_flags & ~0x7fU || (config->action_flags & required) != required ||
        config->log_level > 3 || config->max_path_depth > 32 ||
        config->merkle_history_scope > MERKLE_HISTORY_SCOPE_ROOT_ONLY || config->reserved[0])
        return -EINVAL;
    memset(output, 0, sizeof(*output));
    clean->enabled = config->enabled;
    clean->filter_flags = config->filter_flags;
    clean->action_flags = config->action_flags;
    clean->min_file_size = config->min_file_size;
    clean->max_path_depth = config->max_path_depth;
    clean->log_level = config->log_level;
    clean->merkle_history_max_size = config->merkle_history_max_size;
    clean->merkle_history_scope = config->merkle_history_scope;
    for (int i = 0; i < MAX_IGNORE_PATTERNS + MAX_PATH_FILTERS; i++) {
        const struct bpfima_pattern_entry *entry = i < MAX_IGNORE_PATTERNS ?
            &input->cgroups[i] : &input->paths[i - MAX_IGNORE_PATTERNS];
        struct bpfima_pattern_entry *copy = i < MAX_IGNORE_PATTERNS ?
            &output->cgroups[i] : &output->paths[i - MAX_IGNORE_PATTERNS];
        if (entry->enabled > 1 || entry->match_type > 3 || entry->reserved ||
            !memchr(entry->pattern, '\0', MAX_PATTERN_LEN) ||
            (entry->enabled && !entry->pattern[0]))
            return -EINVAL;
        if (entry->enabled) {
            strscpy(copy->pattern, entry->pattern, sizeof(copy->pattern));
            copy->enabled = 1;
            copy->match_type = entry->match_type;
        }
    }
    for (int i = 0; i < HOOK_MAX; i++) {
        const struct bpfima_hook_config *hook = &input->hooks[i];
        if (hook->flags & ~7U || hook->filter_override || hook->action_override || hook->reserved[0])
            return -EINVAL;
        output->hooks[i].flags = hook->flags;
    }
    return 0;
}

static int validate_extension(const struct bpfima_policy_snapshot *root,
                               const struct bpfima_policy_snapshot *extra)
{
    if (extra->config.enabled < root->config.enabled ||
        (extra->config.filter_flags & ~root->config.filter_flags) ||
        (root->config.action_flags & ~extra->config.action_flags) ||
        extra->config.min_file_size > root->config.min_file_size ||
        extra->config.max_path_depth < root->config.max_path_depth ||
        extra->config.log_level < root->config.log_level ||
        extra->config.merkle_history_max_size != root->config.merkle_history_max_size ||
        extra->config.merkle_history_scope != root->config.merkle_history_scope)
        return -EPERM;
    for (int i = 0; i < HOOK_MAX; i++)
        if (root->hooks[i].flags & ~extra->hooks[i].flags)
            return -EPERM;
    for (int i = 0; i < MAX_IGNORE_PATTERNS + MAX_PATH_FILTERS; i++) {
        const struct bpfima_pattern_entry *entry = i < MAX_IGNORE_PATTERNS ?
            &extra->cgroups[i] : &extra->paths[i - MAX_IGNORE_PATTERNS];
        const struct bpfima_pattern_entry *base = i < MAX_IGNORE_PATTERNS ? root->cgroups : root->paths;
        int count = i < MAX_IGNORE_PATTERNS ? MAX_IGNORE_PATTERNS : MAX_PATH_FILTERS;
        bool subset = !entry->enabled;
        for (int j = 0; j < count && !subset; j++)
            subset = bpfima_pattern_is_subset(entry, &base[j]);
        if (!subset)
            return -EPERM;
    }
    return 0;
}

/* Every input below is normalized; explicitly encode integers little-endian. */
static int snapshot_digest(const struct bpfima_policy_record *record, u8 *digest)
{
    u8 *bytes = kzalloc(sizeof(*record), GFP_KERNEL);
    struct bpfima_policy_record *wire = (struct bpfima_policy_record *)bytes;
    int ret;

    if (!bytes)
        return -ENOMEM;
    memcpy(wire, record, sizeof(*record));
    wire->snapshot.config.filter_flags = cpu_to_le32(record->snapshot.config.filter_flags);
    wire->snapshot.config.action_flags = cpu_to_le32(record->snapshot.config.action_flags);
    wire->snapshot.config.min_file_size = cpu_to_le32(record->snapshot.config.min_file_size);
    wire->snapshot.config.max_path_depth = cpu_to_le32(record->snapshot.config.max_path_depth);
    wire->snapshot.config.log_level = cpu_to_le32(record->snapshot.config.log_level);
    wire->snapshot.config.merkle_history_max_size = cpu_to_le32(record->snapshot.config.merkle_history_max_size);
    for (int i = 0; i < HOOK_MAX; i++)
        wire->snapshot.hooks[i].flags = cpu_to_le32(record->snapshot.hooks[i].flags);
    ret = calculate_sha256_hash(bytes, sizeof(*record), digest);
    kfree(bytes);
    return ret;
}

/* All allocation, hashing and map lookup occurs before the TPM command. */
static int publish_policy_locked(struct bpf_map *map, struct bpfima_policy_state *candidate,
                                 int index, struct bpfima_policy_namespace *metadata)
{
    struct bpfima_policy_state *control = map_state(map, 0), *staged;
    struct policy_change_entry *change;
    u8 digest[MERKLE_HASH_SIZE], event_digest[MERKLE_HASH_SIZE], next_hash[MERKLE_HASH_SIZE];
    char hex[MERKLE_HASH_SIZE * 2 + 1];
    const char *id = candidate->records[index].namespace_id;
    unsigned long flags;
    u64 generation = smp_load_acquire(&control->generation);
    int ret;

    lockdep_assert_held(&bpfima_policy_namespace_mutex);
    if (generation == U64_MAX)
        return -EOVERFLOW;
    candidate->generation = generation + 1;
    staged = map_state(map, 1 + (candidate->generation & 1));
    if (!staged)
        return -EINVAL;
    change = kzalloc(sizeof(*change), GFP_KERNEL);
    if (!change)
        return -ENOMEM;
    ret = snapshot_digest(&candidate->records[index], digest);
    if (ret)
        goto free_change;
    for (int i = 0; i < MERKLE_HASH_SIZE; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    snprintf(change->policy_string, sizeof(change->policy_string), "policy_v2:%llu:%s:%s",
             candidate->generation, id[0] ? id : "[root]", hex);
    ret = calculate_sha256_hash(change->policy_string, strlen(change->policy_string), event_digest);
    if (ret)
        goto free_change;
    memcpy(change->change_hash, event_digest, sizeof(event_digest));
    if (metadata) {
        u8 input[MERKLE_HASH_SIZE * 2];
        memcpy(input, metadata->changes_hash, MERKLE_HASH_SIZE);
        memcpy(input + MERKLE_HASH_SIZE, event_digest, MERKLE_HASH_SIZE);
        ret = calculate_sha256_hash(input, sizeof(input), next_hash);
        if (ret)
            goto free_change;
    }
    spin_lock_irqsave(&policy_snapshot_lock, flags);
    memcpy(staged, candidate, sizeof(*candidate));
    spin_unlock_irqrestore(&policy_snapshot_lock, flags);
    mutex_lock(&bpfima_commit_mutex);
    ret = bpfima_commit_root_locked(event_digest, id[0] ? id : "global_policy");
    if (!ret) {
        if (metadata) {
            spin_lock_irqsave(&metadata->change_history_lock, flags);
            list_add_tail(&change->list, &metadata->change_history);
            memcpy(metadata->changes_hash, next_hash, sizeof(next_hash));
            strscpy(metadata->changes_str, change->policy_string, sizeof(metadata->changes_str));
            spin_unlock_irqrestore(&metadata->change_history_lock, flags);
        } else {
            spin_lock_irqsave(&global_policy_history_lock, flags);
            list_add_tail(&change->list, &global_policy_change_history);
            spin_unlock_irqrestore(&global_policy_history_lock, flags);
        }
        /* Release publishes the fully prepared snapshot only after the synchronous commit. */
        spin_lock_irqsave(&policy_snapshot_lock, flags);
        smp_store_release(&control->generation, candidate->generation);
        spin_unlock_irqrestore(&policy_snapshot_lock, flags);
    }
    mutex_unlock(&bpfima_commit_mutex);
    if (!ret)
        return 0;
free_change:
    kfree(change);
    return ret;
}

int bpfima_policy_bind_map(u32 fd)
{
    struct bpf_map *map = bpf_map_get(fd), *existing;
    struct bpfima_policy_state *initial;
    int ret = 0;

    if (IS_ERR(map))
        return PTR_ERR(map);
    if (map->map_type != BPF_MAP_TYPE_ARRAY || map->key_size != sizeof(u32) ||
        map->value_size != sizeof(*initial) || map->max_entries != BPFIMA_POLICY_MAP_ENTRIES ||
        map->map_flags != BPFIMA_POLICY_MAP_FLAGS) {
        ret = -EINVAL;
        goto put_map;
    }
    /* Syscall read-only flags are per FD. Freeze protects every reopened FD. */
    if (!READ_ONCE(map->frozen)) {
        ret = -EPERM;
        goto put_map;
    }
    if (atomic64_read(&map->writecnt)) {
        ret = -EBUSY; /* A writer authorized before freezing has not drained yet. */
        goto put_map;
    }
    initial = kvzalloc(sizeof(*initial), GFP_KERNEL);
    if (!initial) {
        ret = -ENOMEM;
        goto put_map;
    }
    mutex_lock(&bpfima_policy_namespace_mutex);
    existing = rcu_dereference_protected(policy_map, 1);
    if (existing) {
        ret = existing == map ? bpfima_commit_get_error() : -EBUSY;
        goto unlock;
    }
    for (u32 i = 0; i < BPFIMA_POLICY_MAP_ENTRIES; i++) {
        struct bpfima_policy_state *state = map_state(map, i);
        if (!state || memchr_inv(state, 0, sizeof(*state))) {
            ret = -ESTALE;
            goto unlock;
        }
    }
    bpfima_init_default_snapshot(&initial->records[0].snapshot);
    ret = publish_policy_locked(map, initial, 0, NULL);
    if (ret)
        for (u32 i = 0; i < BPFIMA_POLICY_MAP_ENTRIES; i++)
            memset(map_state(map, i), 0, sizeof(*initial));
    if (!ret) {
        rcu_assign_pointer(policy_map, map);
        map = NULL;
    }
unlock:
    mutex_unlock(&bpfima_policy_namespace_mutex);
    kvfree(initial);
put_map:
    if (map)
        bpf_map_put(map);
    return ret;
}

static int apply_locked(const struct bpfima_policy_request *request)
{
    struct bpf_map *map = rcu_dereference_protected(policy_map, 1);
    struct bpfima_policy_state *active, *candidate;
    struct bpfima_policy_namespace *metadata = NULL;
    struct bpfima_policy_snapshot *snapshot;
    const char *id = request->record.namespace_id;
    int index, ret;

    lockdep_assert_held(&bpfima_policy_namespace_mutex);
    if (!map)
        return -ENXIO;
    ret = bpfima_commit_get_error();
    if (ret)
        return ret;
    active = active_state(map);
    if (request->expected_generation && request->expected_generation != active->generation)
        return -EAGAIN;
    candidate = kvmalloc(sizeof(*candidate), GFP_KERNEL);
    if (!candidate)
        return -ENOMEM;
    memcpy(candidate, active, sizeof(*candidate));
    index = namespace_index(active, id);
    if (index < 0) {
        if (candidate->namespace_count == BPFIMA_POLICY_NAMESPACES) {
            ret = -ENOSPC;
            goto free_candidate;
        }
        index = ++candidate->namespace_count;
        memset(&candidate->records[index], 0, sizeof(candidate->records[index]));
        strscpy(candidate->records[index].namespace_id, id, BPFIMA_NAMESPACE_SIZE);
    }
    snapshot = &candidate->records[index].snapshot;
    ret = normalize_snapshot(&request->record.snapshot, snapshot);
    if (ret)
        goto free_candidate;
    if (index) {
        ret = validate_extension(&candidate->records[0].snapshot, snapshot);
        if (ret)
            goto free_candidate;
        metadata = bpfima_policy_namespace_get_locked(id);
        if (IS_ERR(metadata)) {
            ret = PTR_ERR(metadata);
            goto free_candidate;
        }
    }
    if ((u32)index <= active->namespace_count &&
        !memcmp(snapshot, &active->records[index].snapshot, sizeof(*snapshot))) {
        ret = 0;
        goto free_candidate;
    }
    ret = publish_policy_locked(map, candidate, index, metadata);
free_candidate:
    kvfree(candidate);
    return ret;
}

int bpfima_policy_apply(const struct bpfima_policy_request *request)
{
    int ret;

    if (!request || request->version != BPFIMA_POLICY_VERSION || request->reserved ||
        !memchr(request->record.namespace_id, '\0', BPFIMA_NAMESPACE_SIZE) ||
        (request->record.namespace_id[0] && !valid_namespace(request->record.namespace_id)))
        return -EINVAL;
    mutex_lock(&bpfima_policy_namespace_mutex);
    ret = apply_locked(request);
    mutex_unlock(&bpfima_policy_namespace_mutex);
    return ret;
}

/* Scalar edits preserve existing additions while adopting a newer root floor. */
static void rebase_extension(const struct bpfima_policy_snapshot *root,
                              struct bpfima_policy_snapshot *snapshot)
{
    struct bpfima_policy_config previous = snapshot->config;
    bpfima_policy_merge_config(&root->config, &previous, &snapshot->config);
    for (int i = 0; i < HOOK_MAX; i++)
        snapshot->hooks[i].flags |= root->hooks[i].flags;
    for (int i = 0; i < MAX_IGNORE_PATTERNS + MAX_PATH_FILTERS; i++) {
        struct bpfima_pattern_entry *entry = i < MAX_IGNORE_PATTERNS ?
            &snapshot->cgroups[i] : &snapshot->paths[i - MAX_IGNORE_PATTERNS];
        const struct bpfima_pattern_entry *base = i < MAX_IGNORE_PATTERNS ? root->cgroups : root->paths;
        int count = i < MAX_IGNORE_PATTERNS ? MAX_IGNORE_PATTERNS : MAX_PATH_FILTERS;
        bool subset = !entry->enabled;
        for (int j = 0; j < count && !subset; j++)
            subset = bpfima_pattern_is_subset(entry, &base[j]);
        if (!subset)
            memset(entry, 0, sizeof(*entry));
    }
}

int bpfima_policy_update_field(const char *id, const char *field, u32 value)
{
    struct bpfima_policy_request *request;
    struct bpfima_policy_state *state;
    struct bpf_map *map;
    int index, ret = -EINVAL;

    if (!field || (id && !valid_namespace(id)))
        return -EINVAL;
    request = kzalloc(sizeof(*request), GFP_KERNEL);
    if (!request)
        return -ENOMEM;
    mutex_lock(&bpfima_policy_namespace_mutex);
    map = rcu_dereference_protected(policy_map, 1);
    if (!map) {
        ret = -ENXIO;
        goto unlock;
    }
    state = active_state(map);
    index = namespace_index(state, id);
    if (index < 0)
        index = 0;
    request->version = BPFIMA_POLICY_VERSION;
    request->record.snapshot = state->records[index].snapshot;
    if (index > 0)
        rebase_extension(&state->records[0].snapshot, &request->record.snapshot);
    if (id)
        strscpy(request->record.namespace_id, id, BPFIMA_NAMESPACE_SIZE);
    if (!strcmp(field, "enabled")) {
        if (value > 1)
            goto unlock;
        request->record.snapshot.config.enabled = value;
    } else if (!strcmp(field, "filter_flags"))
        request->record.snapshot.config.filter_flags = value;
    else if (!strcmp(field, "action_flags"))
        request->record.snapshot.config.action_flags = value;
    else if (!strcmp(field, "min_file_size"))
        request->record.snapshot.config.min_file_size = value;
    else if (!strcmp(field, "log_level"))
        request->record.snapshot.config.log_level = value;
    else
        goto unlock;
    ret = apply_locked(request);
unlock:
    mutex_unlock(&bpfima_policy_namespace_mutex);
    kfree(request);
    return ret;
}

int bpfima_policy_read_locked(const char *id, struct bpfima_policy_config *config, u64 *generation)
{
    struct bpf_map *map;
    struct bpfima_policy_state *state;
    int index;

    lockdep_assert_held(&bpfima_policy_namespace_mutex);
    map = rcu_dereference_protected(policy_map, 1);
    if (!map)
        return -ENXIO;
    state = active_state(map);
    index = namespace_index(state, id);
    bpfima_policy_merge_config(&state->records[0].snapshot.config,
                              index > 0 ? &state->records[index].snapshot.config : NULL, config);
    if (generation)
        *generation = state->generation;
    return 0;
}

int bpfima_policy_read(const char *id, struct bpfima_policy_config *config)
{
    int ret;
    mutex_lock(&bpfima_policy_namespace_mutex);
    ret = bpfima_policy_read_locked(id, config, NULL);
    mutex_unlock(&bpfima_policy_namespace_mutex);
    return ret;
}

/* Commit/history paths may already hold the policy mutex. Read the root without taking it again. */
void bpfima_policy_get_config(struct bpfima_policy_config *config)
{
    struct bpf_map *map;
    struct bpfima_policy_state *control, *state;
    unsigned long flags;

    memset(config, 0, sizeof(*config));
    bpfima_init_default_config(config);
    rcu_read_lock();
    map = rcu_dereference(policy_map);
    if (map) {
        spin_lock_irqsave(&policy_snapshot_lock, flags);
        control = map_state(map, 0);
        u64 generation = smp_load_acquire(&control->generation);
        state = map_state(map, 1 + (generation & 1));
        memcpy(config, &state->records[0].snapshot.config, sizeof(*config));
        spin_unlock_irqrestore(&policy_snapshot_lock, flags);
    }
    rcu_read_unlock();
}

u64 bpfima_policy_generation(void)
{
    struct bpf_map *map;
    u64 generation = 0;

    rcu_read_lock();
    map = rcu_dereference(policy_map);
    if (map)
        generation = smp_load_acquire(&map_state(map, 0)->generation);
    rcu_read_unlock();
    return generation;
}

u32 bpfima_policy_map_id(void)
{
    struct bpf_map *map;
    u32 id = 0;
    rcu_read_lock();
    map = rcu_dereference(policy_map);
    if (map)
        id = map->id;
    rcu_read_unlock();
    return id;
}

static bool patterns_match(const struct bpfima_pattern_entry *patterns, int count, const char *text)
{
    for (int i = 0; i < count; i++)
        if (bpfima_pattern_matches(&patterns[i], text))
            return true;
    return false;
}

static bool filtered(const struct bpfima_policy_snapshot *snapshot,
                      const struct bpfima_policy_context *context)
{
    u32 flags = snapshot->config.filter_flags;
    const char *path = context->path;

    if (patterns_match(snapshot->cgroups, MAX_IGNORE_PATTERNS, context->cgroup) ||
        patterns_match(snapshot->paths, MAX_PATH_FILTERS, path))
        return true;
    if ((flags & POLICY_FILTER_SYSTEM_CGROUPS) &&
        (!strcmp(context->cgroup, "/") || !strncmp(context->cgroup, "init.scope", 10)))
        return true;
    if ((flags & POLICY_FILTER_PROC_SYS) && (!strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 5)))
        return true;
    if ((flags & POLICY_FILTER_DEV) && !strncmp(path, "/dev/", 5))
        return true;
    if ((flags & POLICY_FILTER_TMP_FILES) && !strncmp(path, "/tmp/", 5))
        return true;
    if (context->flags & BPFIMA_POLICY_FILE) {
        if ((flags & POLICY_FILTER_SMALL_FILES) && context->file_size < snapshot->config.min_file_size)
            return true;
        if ((flags & POLICY_FILTER_READONLY_FILES) && (context->flags & BPFIMA_POLICY_READONLY))
            return true;
        if ((flags & POLICY_FILTER_NON_EXECUTABLE) && !(context->flags & BPFIMA_POLICY_EXECUTABLE))
            return true;
        if ((flags & POLICY_FILTER_LIBRARIES) && strstr(path, ".so"))
            return true;
    }
    return false;
}

int bpfima_policy_resolve_context(const struct bpfima_policy_context *context,
                                  struct bpfima_policy_result *result)
{
    struct bpf_map *map;
    struct bpfima_policy_state *state;
    const struct bpfima_policy_snapshot *root, *extra = NULL;
    int index, ret = 0;

    if (context->hook >= HOOK_MAX || context->flags & ~7U ||
        !memchr(context->namespace_id, '\0', BPFIMA_NAMESPACE_SIZE) ||
        !memchr(context->cgroup, '\0', BPFIMA_NAMESPACE_SIZE) ||
        !memchr(context->path, '\0', BPFIMA_PATH_SIZE))
        return -EINVAL;
    mutex_lock(&bpfima_policy_namespace_mutex);
    map = rcu_dereference_protected(policy_map, 1);
    if (!map) {
        ret = -ENXIO;
        goto unlock;
    }
    state = active_state(map);
    root = &state->records[0].snapshot;
    index = namespace_index(state, context->namespace_id);
    if (index > 0)
        extra = &state->records[index].snapshot;
    memset(result, 0, sizeof(*result));
    result->generation = state->generation;
    bpfima_policy_merge_config(&root->config, extra ? &extra->config : NULL, &result->config);
    result->hook.flags = root->hooks[context->hook].flags |
                         (extra ? extra->hooks[context->hook].flags : 0);
    result->skip = !result->config.enabled || !(result->hook.flags & HOOK_FLAG_ENABLED) ||
                  ((context->flags & BPFIMA_POLICY_FILE) && !(result->hook.flags & HOOK_FLAG_MEASURE_HASH)) ||
                  (filtered(root, context) && (!extra || filtered(extra, context)));
unlock:
    mutex_unlock(&bpfima_policy_namespace_mutex);
    return ret;
}

bool bpfima_policy_match_root(const char *text, u32 flags, bool path)
{
    struct bpfima_policy_context context = {0};
    struct bpf_map *map;
    struct bpfima_policy_state *state;
    struct bpfima_policy_snapshot *snapshot;
    bool match = false;

    if (path)
        strscpy(context.path, text, sizeof(context.path));
    else
        strscpy(context.cgroup, text, sizeof(context.cgroup));
    mutex_lock(&bpfima_policy_namespace_mutex);
    map = rcu_dereference_protected(policy_map, 1);
    if (map) {
        state = active_state(map);
        snapshot = kmemdup(&state->records[0].snapshot, sizeof(*snapshot), GFP_KERNEL);
        if (snapshot) {
            snapshot->config.filter_flags = flags;
            match = filtered(snapshot, &context);
            kfree(snapshot);
        }
    }
    mutex_unlock(&bpfima_policy_namespace_mutex);
    return match;
}

int bpfima_policy_init(void)
{
    return 0;
}

struct list_head *bpfima_global_policy_get_history(void)
{
    return &global_policy_change_history;
}

spinlock_t *bpfima_global_policy_get_history_lock(void)
{
    return &global_policy_history_lock;
}

void bpfima_global_policy_cleanup_history(void)
{
    struct policy_change_entry *entry, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&global_policy_history_lock, flags);
    list_for_each_entry_safe(entry, tmp, &global_policy_change_history, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&global_policy_history_lock, flags);
}

void bpfima_policy_cleanup(void)
{
    struct bpf_map *map;

    mutex_lock(&bpfima_policy_namespace_mutex);
    map = rcu_dereference_protected(policy_map, 1);
    RCU_INIT_POINTER(policy_map, NULL);
    mutex_unlock(&bpfima_policy_namespace_mutex);
    synchronize_rcu();
    if (map)
        bpf_map_put(map);
    bpfima_global_policy_cleanup_history();
}
