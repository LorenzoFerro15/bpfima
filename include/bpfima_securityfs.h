#ifndef BPFIMA_SECURITYFS_H
#define BPFIMA_SECURITYFS_H

#include "bpfima_common.h"

/* SecurityFS functions */
int bpfima_securityfs_init(void);
void bpfima_securityfs_cleanup(void);

/* Container securityfs functions */
int create_container_securityfs(struct container_node *container);
void remove_container_securityfs(struct container_node *container);

#endif /* BPFIMA_SECURITYFS_H */
