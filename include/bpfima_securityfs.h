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
int container_measurements_release(struct inode *inode, struct file *file);

void bpfima_securityfs_cleanup(void);

/* Container securityfs functions */
int create_container_securityfs(struct container_node *container);
void remove_container_securityfs(struct container_node *container);

/* Policy securityfs functions */
struct dentry *create_namespace_policy_securityfs(const char *namespace_id,
                                                   struct dentry *parent_dir);
void remove_namespace_policy_securityfs(struct dentry *policy_file);
struct dentry *create_namespace_policy_changes_securityfs(const char *namespace_id,
                                                          struct dentry *parent_dir);
void remove_namespace_policy_changes_securityfs(struct dentry *policy_changes_file);
int create_global_policy_securityfs(struct dentry *parent_dir);
void remove_global_policy_securityfs(void);
int create_global_policy_changes_securityfs(struct dentry *parent_dir);
void remove_global_policy_changes_securityfs(void);
extern const struct file_operations policy_fops;
extern const struct file_operations global_policy_fops;
extern const struct file_operations policy_changes_fops;
extern const struct file_operations global_policy_changes_fops;

#endif /* BPFIMA_SECURITYFS_H */
