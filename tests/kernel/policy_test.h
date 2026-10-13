#ifndef BPFIMA_POLICY_TEST_H
#define BPFIMA_POLICY_TEST_H

#include "merkle_test.h"
#include <linux/types.h>
#include <stdio.h>
#include <endian.h>
#define __KERNEL__
#define BPFIMA_POLICY_TEST
#define BPFIMA_KFUNCS_H
#define __bpf_kfunc
#define __rcu
#define __VMLINUX_H__
typedef unsigned long long u64;
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define PTR_ERR(pointer) ((long)(intptr_t)(pointer))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define U64_MAX UINT64_MAX
#define READ_ONCE(value) __atomic_load_n(&(value), __ATOMIC_RELAXED)
#define atomic64_read(value) atomic_load(value)
#define cpu_to_le32(value) htole32(value)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define synchronize_rcu() ((void)0)
#define rcu_dereference(pointer) (pointer)
#define rcu_dereference_protected(pointer, condition) ((void)(condition), (pointer))
#define rcu_assign_pointer(pointer, value) ((pointer) = (value))
#define RCU_INIT_POINTER(pointer, value) ((pointer) = (value))
#define smp_load_acquire(pointer) __atomic_load_n(pointer, __ATOMIC_ACQUIRE)
#define smp_store_release(pointer, value) __atomic_store_n(pointer, value, __ATOMIC_RELEASE)
#define kvmalloc(size, flags) commit_test_allocate(size)
#define kvzalloc(size, flags) commit_test_allocate(size)
#define kvfree(pointer) commit_test_free(pointer)
static inline void *kmemdup(const void *data, size_t size, gfp_t flags)
{
    (void)flags;
    void *copy = commit_test_allocate(size);
    if (copy)
        memcpy(copy, data, size);
    return copy;
}
static inline void *memchr_inv(const void *data, int value, size_t size)
{
    const unsigned char *bytes = data;
    for (size_t i = 0; i < size; i++)
        if (bytes[i] != value)
            return (void *)&bytes[i];
    return NULL;
}
#define spin_lock_init(lock) assert(!pthread_mutex_init(lock, NULL))
#define BPF_MAP_TYPE_ARRAY 2
struct bpf_map;
struct bpf_map_ops { void *(*map_lookup_elem)(struct bpf_map *, void *); };
struct bpf_map {
    const struct bpf_map_ops *ops;
    u32 id, map_type, key_size, value_size, max_entries, map_flags;
    int references;
    bool frozen;
    atomic_t writecnt;
    void *values;
};
struct bpf_map *bpf_map_get(u32 fd);
void bpf_map_put(struct bpf_map *map);
int calculate_sha256_hash(const void *data, size_t size, u8 *digest);

#endif /* BPFIMA_POLICY_TEST_H */
