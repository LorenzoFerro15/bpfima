#ifndef BPFIMA_CONTAINER_H
#define BPFIMA_CONTAINER_H

#include "bpfima_common.h"

/* External declarations for container list state */
extern struct list_head container_list;
extern spinlock_t container_list_lock;
extern atomic_t container_count;

/* Container management functions */
struct container_node *find_container_by_id(const char *container_id);
struct container_node *create_container_node(const char *container_id);
void cleanup_container_measurements(struct container_node *container);
void cleanup_all_containers(void);

/* Measurement functions */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const char *dependencies,
                              const u8 *digest,
                              gfp_t flags);

#endif /* BPFIMA_CONTAINER_H */
