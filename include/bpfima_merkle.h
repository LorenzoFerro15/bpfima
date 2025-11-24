#ifndef BPFIMA_MERKLE_H
#define BPFIMA_MERKLE_H

#include "bpfima_common.h"
#include "bpfima_container.h"

extern struct list_head merkle_root_history;
extern spinlock_t merkle_root_history_lock;
extern struct merkle_tree_root system_merkle_root;

int compute_container_leaf_hash(struct container_node *container);
int extend_container_leaf_hash(struct container_node *container, const u8 *new_digest);
int extend_merkle_root(const u8 *container_leaf_hash);
int recalculate_merkle_root(void);
int add_merkle_root_history_entry(const u8 *value, const char *container_id);

/* Circular buffer management */
int trim_merkle_root_history(u32 max_size);
int aggregate_merkle_entries(struct list_head *entries_to_aggregate, u8 *aggregate_hash, u32 *count_out);
u32 get_merkle_root_history_count(void);

int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const char *dependencies,
                              const u8 *digest);

void cleanup_merkle_root_history(void);

#endif /* BPFIMA_MERKLE_H */
