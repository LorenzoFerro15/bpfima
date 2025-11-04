#ifndef BPFIMA_SECURITYFS_H
#define BPFIMA_SECURITYFS_H

#include "bpfima_common.h"
void *measurements_seq_start(struct seq_file *s, loff_t *pos);
void *measurements_seq_next(struct seq_file *s, void *v, loff_t *pos);
void measurements_seq_stop(struct seq_file *s, void *v);
int measurements_seq_show(struct seq_file *s, void *v);
int measurements_open(struct inode *inode, struct file *file);

int host_measurements_seq_show(struct seq_file *s, void *v);
void *host_measurements_seq_start(struct seq_file *s, loff_t *pos);
void *host_measurements_seq_next(struct seq_file *s, void *v, loff_t *pos);
void host_measurements_seq_stop(struct seq_file *s, void *v);
int host_measurements_open(struct inode *inode, struct file *file);

int status_show(struct seq_file *s, void *unused);
int status_open(struct inode *inode, struct file *f);

extern const struct seq_operations measurements_seq_ops;
extern const struct file_operations measurements_fops;
extern const struct file_operations status_fops;
extern const struct seq_operations host_measurements_seq_ops;
extern const struct file_operations host_measurements_fops; 
extern const struct file_operations merkle_root_fops;

extern struct dentry *bpfima_dir;
extern struct dentry *measurements_file;
extern struct dentry *status_file;
extern char bpfima_dir_name[32];
extern struct dentry *containers_dir;
extern struct dentry *host_measurements_file;
extern struct dentry *merkle_root_file;
extern struct dentry *merkle_root_history_file;
extern struct dentry *container_list_file;

int merkle_root_show(struct seq_file *s, void *unused);
int merkle_root_open(struct inode *inode, struct file *file);

void bpfima_securityfs_cleanup(void);

/* Container securityfs functions */
int create_container_securityfs(struct container_node *container);
void remove_container_securityfs(struct container_node *container);

#endif /* BPFIMA_SECURITYFS_H */
