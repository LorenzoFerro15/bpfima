#ifndef BPFIMA_MERKLE_H
#define BPFIMA_MERKLE_H

#include "bpfima_common.h"
#include "bpfima_container.h"

/* External declarations for global state */
extern struct list_head merkle_root_history;
extern spinlock_t merkle_root_history_lock;
extern struct merkle_tree_root system_merkle_root;

/* Merkle tree functions */
int compute_container_leaf_hash(struct container_node *container);
int extend_container_leaf_hash(struct container_node *container, const u8 *new_digest);
int extend_merkle_root(const u8 *container_leaf_hash);
int recalculate_merkle_root(void);
int add_merkle_root_history_entry(const u8 *value, const char *container_id);

/* Measurement management functions */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const u8 *digest);


int add_host_measurement(const char *event_name,
                        const char *event_data,
                        const u8 *digest);

/* Cleanup functions */
void cleanup_host_measurements(void);
void cleanup_merkle_root_history(void);

#endif /* BPFIMA_MERKLE_H */
