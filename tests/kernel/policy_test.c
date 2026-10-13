#include "policy_test.h"
#include "bpfima_policy.h"
#include "bpfima_policy_defaults.h"
#include "bpfima_merkle.h"
#include <openssl/evp.h>
#include <stdarg.h>
#include <unistd.h>

static struct bpf_map map;
static int allocations, fail_allocation, hash_fail, command_fail, commits;
static struct crypto_shash transform;
static u8 committed[256][32];
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static bool pause_command, entered, release_command;
static _Atomic bool reader_done;

void commit_test_log(const char *format, ...) { (void)format; }
void *commit_test_allocate(size_t size)
{
    if (++allocations == fail_allocation)
        return NULL;
    return calloc(1, size);
}
void commit_test_free(void *pointer) { free(pointer); }
static void *lookup(struct bpf_map *owner, void *key)
{
    u32 index = *(u32 *)key;
    return index < owner->max_entries ? (char *)owner->values + index * owner->value_size : NULL;
}
static const struct bpf_map_ops operations = {.map_lookup_elem = lookup};
struct bpf_map *bpf_map_get(u32 fd)
{
    if (fd != 10)
        return ERR_PTR(-EBADF);
    map.references++;
    return &map;
}
void bpf_map_put(struct bpf_map *owner) { owner->references--; }
int calculate_sha256_hash(const void *data, size_t size, u8 *digest)
{
    unsigned int count;
    if (hash_fail)
        return -EIO;
    return EVP_Digest(data, size, digest, &count, EVP_sha256(), NULL) && count == 32 ? 0 : -EIO;
}
int extend_tpm_pcr_with_root(const u8 *value, const char *source, bool allowed, bool *started)
{
    (void)source;
    assert(allowed);
    *started = true;
    lockdep_assert_held(&bpfima_commit_mutex);
    pthread_mutex_lock(&gate);
    if (pause_command) {
        entered = true;
        pthread_cond_broadcast(&condition);
        while (!release_command)
            pthread_cond_wait(&condition, &gate);
    }
    pthread_mutex_unlock(&gate);
    if (command_fail)
        return -EIO;
    assert(commits < 256);
    memcpy(committed[commits++], value, 32);
    return 0;
}
bool bpfima_tpm_available(void) { return true; }
int bpfima_extend_hash(struct crypto_shash *tfm, const u8 *old, const u8 *value, u8 *result)
{
    (void)tfm;
    u8 bytes[64];
    memcpy(bytes, old, 32);
    memcpy(bytes + 32, value, 32);
    return calculate_sha256_hash(bytes, sizeof(bytes), result);
}
int crypto_shash_final(struct shash_desc *desc, u8 *output)
{
    return calculate_sha256_hash(desc->bytes, desc->size, output);
}
bool hash_exists(const u8 *value, const char *id) { (void)value; (void)id; return false; }
struct hash_entry *bpfima_alloc_hash_entry(const u8 *value, const char *id)
{
    (void)value; (void)id;
    return commit_test_allocate(sizeof(struct hash_entry));
}
void bpfima_publish_hash_entry_locked(struct hash_entry *entry) { commit_test_free(entry); }
struct measurement_entry *create_measurement_entry(const char *name, const char *data,
                                                   const char *dependencies, const u8 *digest, gfp_t flags)
{
    (void)name; (void)data; (void)dependencies; (void)flags;
    struct measurement_entry *entry = commit_test_allocate(sizeof(*entry));
    if (entry)
        memcpy(entry->digest, digest, 32);
    return entry;
}

static void check_committed_history(void)
{
    struct merkle_root_entry *entry;
    u8 root[32] = {0};
    int index = 0;
    list_for_each_entry(entry, &merkle_root_history, list) {
        assert(index < commits && !bpfima_extend_hash(&transform, root, entry->value, root));
        assert(!memcmp(root, committed[index++], 32));
    }
    assert(index == commits && !memcmp(root, system_merkle_root.root_hash, 32));
}

static struct bpfima_policy_state *active(void)
{
    struct bpfima_policy_state *control = map.values;
    return (struct bpfima_policy_state *)map.values + 1 + (control->generation & 1);
}
static struct bpfima_policy_request request(void)
{
    struct bpfima_policy_request value = {.version = BPFIMA_POLICY_VERSION};
    value.record.snapshot = active()->records[0].snapshot;
    return value;
}
static struct bpfima_policy_context context(const char *id, const char *path)
{
    struct bpfima_policy_context value = {.hook = HOOK_LSM_BPRM_CHECK_SECURITY,
        .flags = BPFIMA_POLICY_FILE | BPFIMA_POLICY_EXECUTABLE, .file_size = 500};
    snprintf(value.namespace_id, sizeof(value.namespace_id), "%s", id);
    snprintf(value.cgroup, sizeof(value.cgroup), "%s", id);
    snprintf(value.path, sizeof(value.path), "%s", path);
    return value;
}
static void *update_thread(void *arg)
{
    int *result = arg;
    *result = bpfima_policy_update_field(NULL, "log_level", 3);
    return NULL;
}
static void *read_thread(void *arg)
{
    struct bpfima_policy_config *config = arg;
    assert(!bpfima_policy_read("other", config));
    atomic_store(&reader_done, true);
    return NULL;
}

int main(void)
{
    spin_lock_init(&system_merkle_root.lock);
    system_merkle_root.tfm = &transform;
    bpfima_commit_init();
    map = (struct bpf_map){.id = 10, .ops = &operations, .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32), .value_size = sizeof(struct bpfima_policy_state),
        .max_entries = BPFIMA_POLICY_MAP_ENTRIES, .map_flags = BPFIMA_POLICY_MAP_FLAGS};
    map.values = calloc(map.max_entries, map.value_size);
    assert(map.values);
    map.map_flags = 0;
    assert(bpfima_policy_bind_map(10) == -EINVAL && map.references == 0);
    map.map_flags = BPFIMA_POLICY_MAP_FLAGS;
    assert(bpfima_policy_bind_map(10) == -EPERM && map.references == 0);
    map.frozen = true;
    atomic_store(&map.writecnt, 1);
    assert(bpfima_policy_bind_map(10) == -EBUSY && map.references == 0);
    atomic_store(&map.writecnt, 0);
    /* A pin from a previous epoch must not be adopted or silently reset. */
    for (u32 slot = 0; slot < map.max_entries; slot++) {
        unsigned char *tail = (unsigned char *)map.values + (slot + 1) * map.value_size - 1;
        *tail = 1;
        assert(bpfima_policy_bind_map(10) == -ESTALE && map.references == 0 && commits == 0);
        assert(*tail == 1 && bpfima_policy_generation() == 0);
        *tail = 0;
    }
    puts("PASS: stale policy map slots are rejected without mutation or TPM extension");
    fail_allocation = allocations + 2;
    assert(bpfima_policy_bind_map(10) == -ENOMEM && bpfima_policy_generation() == 0);
    fail_allocation = 0;
    assert(!bpfima_policy_bind_map(10) && map.references == 1 && commits == 1 && bpfima_policy_map_id() == 10);
    assert(!bpfima_policy_bind_map(10) && map.references == 1 && commits == 1 && bpfima_policy_map_id() == 10);
    struct policy_change_entry *initial = list_entry(bpfima_global_policy_get_history()->next, struct policy_change_entry, list);
    assert(strstr(initial->policy_string, "ddba863641f721a846795c580473c17fd1f67ed07f68ef6d33cfdf8a391adf65"));
    struct bpfima_policy_request root = request();
    assert(!bpfima_policy_apply(&root) && commits == 1);
    root.record.snapshot.config.filter_flags = POLICY_FILTER_SMALL_FILES | POLICY_FILTER_TMP_FILES;
    root.record.snapshot.config.min_file_size = 1000;
    assert(!bpfima_policy_apply(&root));
    struct bpfima_policy_request extra = request();
    snprintf(extra.record.namespace_id, sizeof(extra.record.namespace_id), "tenant");
    extra.record.snapshot.config.filter_flags = POLICY_FILTER_SMALL_FILES;
    extra.record.snapshot.config.min_file_size = 100;
    memset(extra.record.snapshot.paths, 0, sizeof(extra.record.snapshot.paths));
    assert(!bpfima_policy_apply(&extra));
    struct bpfima_policy_context input = context("tenant", "/tmp/file");
    struct bpfima_policy_result result;
    assert(!bpfima_policy_resolve_context(&input, &result) && !result.skip);
    input = context("other", "/tmp/file");
    assert(!bpfima_policy_resolve_context(&input, &result) && result.skip);
    int count = commits;
    extra.record.snapshot.config.min_file_size = 2000;
    assert(bpfima_policy_apply(&extra) == -EPERM && commits == count);
    extra.record.snapshot.config.min_file_size = 100;
    extra.record.snapshot.config.filter_flags |= POLICY_FILTER_DEV;
    assert(bpfima_policy_apply(&extra) == -EPERM);
    extra.record.snapshot.config.filter_flags = 0;
    extra.record.snapshot.config.action_flags = POLICY_ACTION_EXTEND_TPM | POLICY_ACTION_LOG_SECURITYFS;
    assert(bpfima_policy_apply(&extra) == -EPERM);
    extra = request();
    snprintf(extra.record.namespace_id, sizeof(extra.record.namespace_id), "tenant");
    snprintf(extra.record.snapshot.paths[0].pattern, MAX_PATTERN_LEN, "/new-exclusion/");
    assert(bpfima_policy_apply(&extra) == -EPERM);
    puts("PASS: map binding, idempotence, root inheritance and rejection of weaker namespace rules");

    /* A later root update cannot allow an old overlay to weaken the new root. */
    root = request();
    root.record.snapshot.config.filter_flags = 0;
    root.record.snapshot.config.min_file_size = 0;
    assert(!bpfima_policy_apply(&root));
    input = context("tenant", "/tmp/file");
    assert(!bpfima_policy_resolve_context(&input, &result) && !result.skip && result.config.min_file_size == 0);
    struct policy_change_entry *prior = list_entry(bpfima_global_policy_get_history()->prev, struct policy_change_entry, list);
    char prior_snapshot_hash[65];
    snprintf(prior_snapshot_hash, sizeof(prior_snapshot_hash), "%s", strrchr(prior->policy_string, ':') + 1);
    root = request();
    snprintf(root.record.snapshot.paths[0].pattern, MAX_PATTERN_LEN, "/changed/");
    count = commits;
    assert(!bpfima_policy_apply(&root) && commits == count + 1);
    assert(memcmp(committed[count], committed[count - 1], 32));
    struct policy_change_entry *latest = list_entry(bpfima_global_policy_get_history()->prev, struct policy_change_entry, list);
    assert(strcmp(prior_snapshot_hash, strrchr(latest->policy_string, ':') + 1));
    root.expected_generation = bpfima_policy_generation() - 1;
    assert(bpfima_policy_apply(&root) == -EAGAIN && commits == count + 1);
    assert(!bpfima_policy_update_field("tenant", "log_level", 3));
    struct bpfima_policy_config rebased;
    assert(!bpfima_policy_read("tenant", &rebased) && !rebased.filter_flags && !rebased.min_file_size);
    root = request();
    prior = list_entry(bpfima_global_policy_get_history()->prev, struct policy_change_entry, list);
    snprintf(prior_snapshot_hash, sizeof(prior_snapshot_hash), "%s", strrchr(prior->policy_string, ':') + 1);
    root.record.snapshot.hooks[HOOK_LSM_INODE_SETATTR].flags &= ~HOOK_FLAG_TRACK_CONTAINERS;
    assert(!bpfima_policy_apply(&root));
    latest = list_entry(bpfima_global_policy_get_history()->prev, struct policy_change_entry, list);
    assert(strcmp(prior_snapshot_hash, strrchr(latest->policy_string, ':') + 1));
    puts("PASS: root changes preserve coverage; patterns and hook configuration are audited");

    u64 generation = bpfima_policy_generation();
    struct bpfima_policy_state *before = malloc(sizeof(*before));
    assert(before);
    memcpy(before, active(), sizeof(*before));
    root = request();
    root.record.snapshot.config.log_level = 3;
    /* Candidate, change-entry and wire allocation each fail before any command. */
    for (int offset = 1; offset <= 4; offset++) {
        fail_allocation = allocations + offset;
        assert(bpfima_policy_apply(&root) == -ENOMEM);
        assert(bpfima_policy_generation() == generation && !memcmp(before, active(), sizeof(*before)));
    }
    fail_allocation = 0;
    hash_fail = 1;
    assert(bpfima_policy_apply(&root) == -EIO && bpfima_policy_generation() == generation);
    hash_fail = 0;
    puts("PASS: allocation/hash failures leave active map, audit history and generation unchanged");

    while (active()->namespace_count < BPFIMA_POLICY_NAMESPACES) {
        struct bpfima_policy_request addition = request();
        snprintf(addition.record.namespace_id, sizeof(addition.record.namespace_id), "quota-%u", active()->namespace_count);
        assert(!bpfima_policy_apply(&addition));
    }
    struct bpfima_policy_request overflow = request();
    snprintf(overflow.record.namespace_id, sizeof(overflow.record.namespace_id), "overflow");
    generation = bpfima_policy_generation();
    count = commits;
    assert(bpfima_policy_apply(&overflow) == -ENOSPC && commits == count && bpfima_policy_generation() == generation);
    memcpy(before, active(), sizeof(*before));
    puts("PASS: namespace capacity is enforced before TPM extension or activation");

    pthread_t writer, reader;
    int update_result = -1;
    struct bpfima_policy_config observed;
    pause_command = true;
    assert(!pthread_create(&writer, NULL, update_thread, &update_result));
    pthread_mutex_lock(&gate);
    while (!entered)
        pthread_cond_wait(&condition, &gate);
    pthread_mutex_unlock(&gate);
    assert(bpfima_policy_generation() == generation && !memcmp(before, active(), sizeof(*before)));
    assert(!pthread_create(&reader, NULL, read_thread, &observed));
    usleep(20000);
    assert(!atomic_load(&reader_done));
    pthread_mutex_lock(&gate);
    release_command = true;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&gate);
    assert(!pthread_join(writer, NULL) && !pthread_join(reader, NULL));
    assert(update_result == 0 && observed.log_level == 3 && bpfima_policy_generation() == generation + 1);
    pause_command = false;
    puts("PASS: policy activation waits for TPM completion and concurrent readers cannot observe partial policy");

    root = request();
    root.record.snapshot.config.log_level = 2;
    generation = bpfima_policy_generation();
    command_fail = 1;
    count = commits;
    assert(bpfima_policy_apply(&root) == -EIO);
    command_fail = 0;
    struct bpfima_policy_request unchanged = request();
    assert(bpfima_policy_apply(&unchanged) == -EIO);
    assert(bpfima_policy_apply(&root) == -EIO && commits == count && bpfima_policy_generation() == generation);
    puts("PASS: TPM failure prevents activation and unsafe changed-policy retries");
    check_committed_history();
    puts("PASS: actual Merkle history/root reproduces every policy TPM extension in order");
    free(before);
    bpfima_policy_namespace_cleanup();
    bpfima_policy_cleanup();
    assert(map.references == 0);
    cleanup_merkle_root_history();
    assert(!pthread_mutex_destroy(&system_merkle_root.lock));
    free(map.values);
    return 0;
}
