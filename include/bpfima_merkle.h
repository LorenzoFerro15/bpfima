#ifndef BPFIMA_MERKLE_H
#define BPFIMA_MERKLE_H

#include "bpfima_common.h"

/* External declarations for global state */
extern struct list_head container_list;
extern spinlock_t container_list_lock;
extern struct list_head merkle_root_history;
extern spinlock_t merkle_root_history_lock;
extern struct merkle_tree_root system_merkle_root;
extern atomic_t container_count;

/* Merkle tree functions */
int compute_container_leaf_hash(struct container_node *container);
int recalculate_merkle_root(void);
int add_merkle_root_history_entry(const u8 *value, const char *container_id);

/* Container management functions */
struct container_node *find_container_by_id(const char *container_id);
struct container_node *create_container_node(const char *container_id);
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const u8 *digest);

/* Host measurement functions */
extern struct list_head host_measurement_list;
extern spinlock_t host_measurement_lock;
int add_host_measurement(const char *event_name,
                        const char *event_data,
                        const u8 *digest);

/* Cleanup functions */
void cleanup_container_measurements(struct container_node *container);
void cleanup_all_containers(void);
void cleanup_host_measurements(void);
void cleanup_merkle_root_history(void);

#endif /* BPFIMA_MERKLE_H */
