#ifndef BPFIMA_SECURITYFS_H
#define BPFIMA_SECURITYFS_H

#include "bpfima_common.h"

int status_show(struct seq_file *s, void *unused);
int status_open(struct inode *inode, struct file *f);

extern const struct file_operations status_fops;
extern const struct seq_operations merkle_root_history_seq_ops;
extern const struct file_operations merkle_root_history_fops;
extern const struct seq_operations container_measurements_seq_ops;
extern const struct file_operations container_measurements_fops;

extern struct dentry *bpfima_dir;
extern struct dentry *status_file;
extern char bpfima_dir_name[32];
extern struct dentry *containers_dir;
extern struct dentry *merkle_root_history_file;

int merkle_root_history_seq_show(struct seq_file *s, void *v);
void *merkle_root_history_seq_start(struct seq_file *s, loff_t *pos);
void *merkle_root_history_seq_next(struct seq_file *s, void *v, loff_t *pos);
void merkle_root_history_seq_stop(struct seq_file *s, void *v);
int merkle_root_history_open(struct inode *inode, struct file *file);

int container_measurements_seq_show(struct seq_file *s, void *v);
void *container_measurements_seq_start(struct seq_file *s, loff_t *pos);
void *container_measurements_seq_next(struct seq_file *s, void *v, loff_t *pos);
void container_measurements_seq_stop(struct seq_file *s, void *v);
int container_measurements_open(struct inode *inode, struct file *file);

void bpfima_securityfs_cleanup(void);

/* Container securityfs functions */
int create_container_securityfs(struct container_node *container);
void remove_container_securityfs(struct container_node *container);

/* Policy measurement securityfs functions */
int create_measure_policy_securityfs(struct dentry *parent_dir);
void remove_measure_policy_securityfs(void);

#endif /* BPFIMA_SECURITYFS_H */
