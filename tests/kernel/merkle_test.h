#ifndef BPFIMA_MERKLE_TEST_H
#define BPFIMA_MERKLE_TEST_H

/* Supply kernel primitives for the production Merkle implementation's native tests. */
#define BPFIMA_COMMON_H
#define __init
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned int gfp_t;
typedef _Atomic int atomic_t;
typedef pthread_mutex_t spinlock_t;
#define MERKLE_HASH_SIZE 32
#define SHA256_DIGEST_SIZE 32
#define CONTAINER_ID_MAX_LEN 128
#define GFP_KERNEL 1
#define GFP_ATOMIC 2
#define ATOMIC_INIT(value) (value)
#define atomic_sub(amount, value) ((void)atomic_fetch_sub(value, amount))
#define atomic_set(value, amount) atomic_store(value, amount)

struct mutex {
    pthread_mutex_t native;
    pthread_t owner;
    bool held;
};
#define DEFINE_MUTEX(name) struct mutex name = {.native = PTHREAD_MUTEX_INITIALIZER}
#define DEFINE_SPINLOCK(name) spinlock_t name = PTHREAD_MUTEX_INITIALIZER
static inline void mutex_lock(struct mutex *lock)
{
    assert(!pthread_mutex_lock(&lock->native));
    lock->owner = pthread_self();
    lock->held = true;
}
static inline void mutex_unlock(struct mutex *lock)
{
    lock->held = false;
    assert(!pthread_mutex_unlock(&lock->native));
}
#define lockdep_assert_held(lock) assert((lock)->held && pthread_equal((lock)->owner, pthread_self()))
#define spin_lock(lock) assert(!pthread_mutex_lock(lock))
#define spin_unlock(lock) assert(!pthread_mutex_unlock(lock))
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; spin_lock(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); spin_unlock(lock); } while (0)
#define atomic_inc(value) ((void)atomic_fetch_add(value, 1))
#define atomic_read(value) atomic_load(value)
void commit_test_log(const char *format, ...);
#define pr_warn(...) commit_test_log(__VA_ARGS__)
#define pr_err(...) commit_test_log(__VA_ARGS__)
#define pr_info(...) commit_test_log(__VA_ARGS__)
static inline int in_atomic(void) { return 0; }
static inline int irqs_disabled(void) { return 0; }
static inline void memzero_explicit(void *data, size_t size) { memset(data, 0, size); }

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = {&name, &name}
static inline void INIT_LIST_HEAD(struct list_head *head) { head->next = head->prev = head; }
static inline void list_add_tail(struct list_head *entry, struct list_head *head)
{
    entry->prev = head->prev;
    entry->next = head;
    head->prev->next = entry;
    head->prev = entry;
}
#define list_entry(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
static inline void list_add(struct list_head *entry, struct list_head *head)
{
    entry->next = head->next;
    entry->prev = head;
    head->next->prev = entry;
    head->next = entry;
}
static inline void list_del(struct list_head *entry)
{
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
}
static inline void list_splice(struct list_head *source, struct list_head *head)
{
    if (source->next == source)
        return;
    source->next->prev = head;
    source->prev->next = head->next;
    head->next->prev = source->prev;
    head->next = source->next;
}
#define list_for_each_entry(pos, head, member) \
    for (struct list_head *test_node = (head)->next; \
         test_node != (head) && ((pos) = list_entry(test_node, __typeof__(*(pos)), member), true); \
         test_node = test_node->next)
#define list_for_each_entry_safe(pos, tmp, head, member) \
    for (struct list_head *test_node = (head)->next, *test_next; \
         test_node != (head) && ((test_next = test_node->next), \
         (pos) = list_entry(test_node, __typeof__(*(pos)), member), \
         (tmp) = test_next == (head) ? NULL : list_entry(test_next, __typeof__(*(tmp)), member), \
         (void)(tmp), true); test_node = test_next)
struct crypto_shash { int unused; };
struct shash_desc { struct crypto_shash *tfm; u8 bytes[64]; size_t size; };
static inline unsigned int crypto_shash_descsize(struct crypto_shash *tfm) { (void)tfm; return 0; }
static inline int crypto_shash_init(struct shash_desc *desc) { desc->size = 0; return 0; }
static inline int crypto_shash_update(struct shash_desc *desc, const u8 *data, size_t size)
{
    assert(size <= sizeof(desc->bytes) - desc->size);
    memcpy(desc->bytes + desc->size, data, size);
    desc->size += size;
    return 0;
}
int crypto_shash_final(struct shash_desc *desc, u8 *output);
static inline int strscpy(char *dest, const char *src, size_t capacity)
{
    size_t size = strlen(src);
    assert(size < capacity);
    memcpy(dest, src, size + 1);
    return size;
}
struct measurement_entry {
    struct list_head list;
    char event_name[256], event_data[256], dependencies[256];
    u8 digest[MERKLE_HASH_SIZE];
};
struct container_node {
    char id[CONTAINER_ID_MAX_LEN];
    struct list_head measurement_list;
    spinlock_t measurement_lock;
    struct crypto_shash *tfm;
    u8 leaf_hash[MERKLE_HASH_SIZE];
    atomic_t measurement_count;
};
struct hash_entry {
    struct list_head list;
    u8 sha256_hash[MERKLE_HASH_SIZE];
    char namespace_id[CONTAINER_ID_MAX_LEN];
};
struct merkle_root_entry {
    struct list_head list;
    u8 value[MERKLE_HASH_SIZE];
    char source_container_id[CONTAINER_ID_MAX_LEN];
    bool is_aggregate;
    u32 aggregated_count;
};
struct merkle_tree_root {
    u8 root_hash[MERKLE_HASH_SIZE];
    spinlock_t lock;
    struct crypto_shash *tfm;
};

void commit_test_free(void *pointer);
void *commit_test_allocate(size_t size);
static inline void *kzalloc(size_t size, gfp_t flags) { (void)flags; return commit_test_allocate(size); }
#define kfree(pointer) commit_test_free(pointer)
bool hash_exists(const u8 *digest, const char *namespace_id);
struct hash_entry *bpfima_alloc_hash_entry(const u8 *digest, const char *namespace_id);
void bpfima_publish_hash_entry_locked(struct hash_entry *entry);
int bpfima_extend_hash(struct crypto_shash *tfm, const u8 *old_hash, const u8 *value, u8 *output);
int extend_tpm_pcr_with_root(const u8 *root, const char *event_name, bool hardware_allowed,
                             bool *command_started);
bool bpfima_tpm_available(void);
struct bpfima_policy_config;
void bpfima_policy_get_config(struct bpfima_policy_config *config);

#endif /* BPFIMA_MERKLE_TEST_H */
