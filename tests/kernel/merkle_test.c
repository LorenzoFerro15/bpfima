#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
#include "bpfima_container.h"
#include "bpfima_measurements.h"
#include "bpfima_merkle.h"
#include "bpfima_policy.h"

static struct crypto_shash tfm;
static struct list_head hashes;
static spinlock_t hash_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_t allocations;
static int fail_allocation, fail_hash;
static bool pause_failure, pause_tpm;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static bool paused, released;
static int started, finished;
static u8 tpm_roots[256][MERKLE_HASH_SIZE], tpm_value[MERKLE_HASH_SIZE];
static int tpm_count;
static int tpm_attempts, tpm_error;
static bool tpm_available = true;
static bool fail_after_extend;
static bool tpm_prepare_failure;
static bool sha256_bank = true;

void commit_test_log(const char *format, ...)
{
    (void)format;
}

static void pause_commit(void)
{
    pthread_mutex_lock(&gate);
    paused = true;
    pthread_cond_broadcast(&condition);
    while (!released)
        pthread_cond_wait(&condition, &gate);
    pthread_mutex_unlock(&gate);
}

void *commit_test_allocate(size_t size)
{
    if (fail_allocation && --fail_allocation == 0) {
        if (pause_failure)
            pause_commit();
        return NULL;
    }
    void *pointer = calloc(1, size);
    assert(pointer);
    atomic_inc(&allocations);
    return pointer;
}

void commit_test_free(void *pointer)
{
    if (pointer) {
        atomic_fetch_sub(&allocations, 1);
        free(pointer);
    }
}

static void digest(const void *data, size_t size, u8 *output)
{
    unsigned int length;
    assert(EVP_Digest(data, size, output, &length, EVP_sha256(), NULL) == 1 && length == 32);
}

static void extend(const u8 *old_hash, const u8 *value, u8 *output)
{
    u8 bytes[64];
    memcpy(bytes, old_hash, 32);
    memcpy(bytes + 32, value, 32);
    digest(bytes, sizeof(bytes), output);
}

int bpfima_extend_hash(struct crypto_shash *crypto, const u8 *old_hash, const u8 *value, u8 *output)
{
    (void)crypto;
    if (fail_hash && --fail_hash == 0)
        return -EIO;
    extend(old_hash, value, output);
    return 0;
}

struct measurement_entry *create_measurement_entry(const char *event_name, const char *event_data,
                                                   const char *dependencies, const u8 *value, gfp_t flags)
{
    (void)flags;
    struct measurement_entry *entry = commit_test_allocate(sizeof(*entry));
    if (entry) {
        snprintf(entry->event_name, sizeof(entry->event_name), "%s", event_name);
        snprintf(entry->event_data, sizeof(entry->event_data), "%s", event_data ? event_data : "");
        snprintf(entry->dependencies, sizeof(entry->dependencies), "%s", dependencies ? dependencies : "");
        memcpy(entry->digest, value, 32);
    }
    return entry;
}

bool hash_exists(const u8 *value, const char *namespace_id)
{
    bool found = false;
    spin_lock(&hash_lock);
    for (struct list_head *node = hashes.next; node != &hashes; node = node->next) {
        struct hash_entry *entry = list_entry(node, struct hash_entry, list);
        if (!memcmp(entry->sha256_hash, value, 32) && !strcmp(entry->namespace_id, namespace_id))
            found = true;
    }
    spin_unlock(&hash_lock);
    return found;
}

struct hash_entry *bpfima_alloc_hash_entry(const u8 *value, const char *namespace_id)
{
    struct hash_entry *entry = commit_test_allocate(sizeof(*entry));
    if (entry) {
        memcpy(entry->sha256_hash, value, 32);
        snprintf(entry->namespace_id, sizeof(entry->namespace_id), "%s", namespace_id);
    }
    return entry;
}

void bpfima_publish_hash_entry_locked(struct hash_entry *entry)
{
    lockdep_assert_held(&bpfima_commit_mutex);
    spin_lock(&hash_lock);
    list_add_tail(&entry->list, &hashes);
    spin_unlock(&hash_lock);
}

void bpfima_policy_get_config(struct bpfima_policy_config *config)
{
    memset(config, 0, sizeof(*config));
    config->merkle_history_max_size = 1000;
}

int crypto_shash_final(struct shash_desc *desc, u8 *output)
{
    digest(desc->bytes, desc->size, output);
    return 0;
}

int extend_tpm_pcr_with_root(const u8 *root, const char *event_name, bool hardware_allowed,
                             bool *command_started)
{
    (void)event_name;
    lockdep_assert_held(&bpfima_commit_mutex);
    tpm_attempts++;
    *command_started = false;
    if (!tpm_available)
        return -ENODEV;
    if (!hardware_allowed)
        return -EIO;
    if (!sha256_bank)
        return -EOPNOTSUPP;
    if (tpm_prepare_failure)
        return -ENOMEM;
    *command_started = true;
    if (tpm_error && !fail_after_extend)
        return tpm_error;
    if (pause_tpm)
        pause_commit();
    assert(tpm_count < 256);
    memcpy(tpm_roots[tpm_count++], root, 32);
    extend(tpm_value, root, tpm_value);
    return tpm_error;
}

bool bpfima_tpm_available(void)
{
    return tpm_available;
}

static void init_container(struct container_node *container, const char *name)
{
    memset(container, 0, sizeof(*container));
    snprintf(container->id, sizeof(container->id), "%s", name);
    INIT_LIST_HEAD(&container->measurement_list);
    assert(!pthread_mutex_init(&container->measurement_lock, NULL));
    container->tfm = &tfm;
}

static void check_replay(struct container_node *container)
{
    u8 leaf[32] = {0}, root[32] = {0}, pcr[32] = {0};
    int count = 0, roots = 0;
    for (struct list_head *node = container->measurement_list.next; node != &container->measurement_list; node = node->next) {
        struct measurement_entry *entry = list_entry(node, struct measurement_entry, list);
        extend(leaf, entry->digest, leaf);
        count++;
    }
    assert(count == atomic_read(&container->measurement_count) && !memcmp(leaf, container->leaf_hash, 32));
    for (struct list_head *node = merkle_root_history.next; node != &merkle_root_history; node = node->next) {
        struct merkle_root_entry *entry = list_entry(node, struct merkle_root_entry, list);
        extend(root, entry->value, root);
        assert(roots < tpm_count && !memcmp(root, tpm_roots[roots++], 32));
        extend(pcr, root, pcr);
    }
    assert(roots == tpm_count && !memcmp(root, system_merkle_root.root_hash, 32) && !memcmp(pcr, tpm_value, 32));
}

static void reset(struct container_node *container)
{
    while (container->measurement_list.next != &container->measurement_list) {
        struct list_head *node = container->measurement_list.next;
        container->measurement_list.next = node->next;
        kfree(list_entry(node, struct measurement_entry, list));
    }
    cleanup_merkle_root_history();
    while (hashes.next != &hashes) {
        struct list_head *node = hashes.next;
        hashes.next = node->next;
        kfree(list_entry(node, struct hash_entry, list));
    }
    assert(atomic_read(&allocations) == 0);
    assert(!pthread_mutex_destroy(&container->measurement_lock));
    init_container(container, "test");
    INIT_LIST_HEAD(&merkle_root_history);
    INIT_LIST_HEAD(&hashes);
    memset(system_merkle_root.root_hash, 0, 32);
    memset(tpm_value, 0, 32);
    tpm_count = 0;
    tpm_attempts = tpm_error = 0;
    tpm_available = true;
    fail_after_extend = false;
    tpm_prepare_failure = false;
    sha256_bank = true;
    bpfima_commit_init();
    fail_allocation = fail_hash = 0;
    paused = released = pause_failure = pause_tpm = false;
    started = finished = 0;
}

struct worker { struct container_node *container; int kind, index, result; };

static void *run_worker(void *data)
{
    struct worker *worker = data;
    u8 value[32];
    digest("same", 4, value);
    pthread_mutex_lock(&gate);
    started++;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&gate);
    worker->result = 0;
    for (int i = 0; i < (worker->kind ? 8 : 1); i++) {
        if (worker->kind) {
            char text[64];
            int length = snprintf(text, sizeof(text), "%d-%d", worker->index, i);
            digest(text, length, value);
        }
        if (worker->kind == 2 || worker->kind == 3) {
            mutex_lock(&bpfima_commit_mutex);
            if (worker->kind == 3)
                worker->result = bpfima_commit_root_locked(value, "global_policy");
            else {
                struct measurement_entry *entry = create_measurement_entry("policy_update", "", "", value, GFP_KERNEL);
                assert(entry);
                worker->result = bpfima_commit_measurement_locked(worker->container, entry, false);
                if (worker->result)
                    kfree(entry);
            }
            mutex_unlock(&bpfima_commit_mutex);
        } else
            worker->result = add_container_measurement(worker->container, "test", "same", "", value, GFP_KERNEL);
        if (worker->result)
            break;
    }
    pthread_mutex_lock(&gate);
    finished++;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&gate);
    return NULL;
}

static void test_pending(struct container_node *container, bool fail)
{
    struct worker workers[2] = {{.container = container}, {.container = container}};
    pthread_t threads[2];
    u8 value[32];
    digest("same", 4, value);
    fail_allocation = fail ? 3 : 0;
    pause_failure = fail;
    pause_tpm = !fail;
    assert(!pthread_create(&threads[0], NULL, run_worker, &workers[0]));
    pthread_mutex_lock(&gate);
    while (!paused)
        pthread_cond_wait(&condition, &gate);
    pthread_mutex_unlock(&gate);
    assert(!hash_exists(value, container->id));
    assert(atomic_read(&container->measurement_count) == 0 && tpm_count == 0);
    assert(!pthread_create(&threads[1], NULL, run_worker, &workers[1]));
    pthread_mutex_lock(&gate);
    while (started != 2)
        pthread_cond_wait(&condition, &gate);
    struct timespec deadline;
    assert(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_sec++;
    while (!finished) {
        int ret = pthread_cond_timedwait(&condition, &gate, &deadline);
        if (ret == ETIMEDOUT)
            break;
        assert(!ret);
    }
    assert(finished == 0);
    released = true;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&gate);
    assert(!pthread_join(threads[0], NULL) && !pthread_join(threads[1], NULL));
    assert(workers[0].result == (fail ? -ENOMEM : 0));
    assert(workers[1].result == (fail ? 0 : 1));
    assert(atomic_read(&container->measurement_count) == 1 && hash_exists(value, container->id));
    check_replay(container);
    reset(container);
}

int main(void)
{
    struct container_node container;
    u8 value[32], zero[32] = {0};
    assert(!pthread_mutex_init(&system_merkle_root.lock, NULL));
    system_merkle_root.tfm = &tfm;
    init_container(&container, "test");
    INIT_LIST_HEAD(&merkle_root_history);
    INIT_LIST_HEAD(&hashes);
    digest("same", 4, value);
    bpfima_commit_init();
    for (int i = 1; i <= 3; i++) {
        fail_allocation = i;
        assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -ENOMEM);
        assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && tpm_count == 0);
        assert(!memcmp(container.leaf_hash, zero, 32) && !memcmp(system_merkle_root.root_hash, zero, 32));
        assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == 0);
        check_replay(&container);
        reset(&container);
    }
    for (int i = 1; i <= 2; i++) {
        fail_hash = i;
        assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EIO);
        assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && tpm_count == 0);
        assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == 0);
        check_replay(&container);
        reset(&container);
    }
    puts("PASS: allocation/hash failures leave no committed state or poisoned digest; retries succeed");
    test_pending(&container, false);
    test_pending(&container, true);
    puts("PASS: concurrent duplicate callers wait for completion and retry a failed reservation");
    tpm_error = -ENODEV;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -ENODEV);
    assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && tpm_count == 0);
    assert(bpfima_commit_get_error() == -ENODEV);
    reset(&container);
    sha256_bank = false;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EOPNOTSUPP);
    assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && tpm_count == 0);
    assert(bpfima_commit_get_error() == -EOPNOTSUPP);
    reset(&container);
    tpm_prepare_failure = true;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -ENOMEM);
    assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && bpfima_commit_get_error() == 0);
    tpm_prepare_failure = false;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == 0);
    check_replay(&container);
    reset(&container);
    tpm_error = -EIO;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EIO);
    assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && tpm_count == 0);
    assert(!memcmp(container.leaf_hash, zero, 32) && !memcmp(system_merkle_root.root_hash, zero, 32));
    tpm_error = 0;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EIO);
    assert(bpfima_commit_get_error() == -EIO && tpm_attempts == 1);
    reset(&container);
    tpm_error = -EIO;
    fail_after_extend = true;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EIO);
    assert(!hash_exists(value, container.id) && atomic_read(&allocations) == 0 && tpm_count == 1);
    assert(atomic_read(&container.measurement_count) == 0 && !memcmp(system_merkle_root.root_hash, zero, 32));
    tpm_error = 0;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EIO);
    assert(tpm_attempts == 1);
    reset(&container);
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == 0);
    tpm_available = false;
    value[0] ^= 1;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -ENODEV);
    assert(atomic_read(&container.measurement_count) == 1 && tpm_attempts == 1);
    reset(&container);
    tpm_available = false;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == 0);
    assert(tpm_count == 0 && bpfima_commit_get_error() == 0);
    tpm_available = true;
    value[0] ^= 1;
    assert(add_container_measurement(&container, "test", "same", "", value, GFP_KERNEL) == -EIO);
    assert(atomic_read(&container.measurement_count) == 1 && tpm_attempts == 1);
    reset(&container);
    puts("PASS: TPM failures publish no software state, block unsafe retries, and prevent epoch mode changes");
    for (int round = 0; round < 8; round++) {
        pthread_t threads[8];
        struct worker workers[8];
        for (int i = 0; i < 8; i++) {
            workers[i] = (struct worker){.container = &container, .kind = i % 3 + 1, .index = i};
            assert(!pthread_create(&threads[i], NULL, run_worker, &workers[i]));
        }
        for (int i = 0; i < 8; i++) {
            assert(!pthread_join(threads[i], NULL) && workers[i].result == 0);
        }
        assert(atomic_read(&container.measurement_count) == 48 && tpm_count == 64);
        check_replay(&container);
        reset(&container);
    }
    assert(!pthread_mutex_destroy(&container.measurement_lock));
    puts("PASS: mixed measurement, namespace-policy, and global-policy commits match history/root/TPM order");
    return 0;
}
