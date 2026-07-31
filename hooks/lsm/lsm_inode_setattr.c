#include "../hook_utils.h"

char LICENSE[] SEC("license") = "GPL";

extern int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;

SEC("lsm/inode_setattr")
int BPF_PROG(bpf_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
    if (!dentry || !attr)
        return 0;

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    char cgroup_name[64] = {0};
    fetch_cgroup_name(cur, cgroup_name, sizeof(cgroup_name));

    struct bpfima_policy_config *policy = bpfima_get_policy();
    if (cgroup_name[0] != '\0' && bpfima_should_ignore_cgroup(cgroup_name, policy))
        return 0;

    char entry_name[16] = {0};
    bpf_core_read_str(entry_name, sizeof(entry_name), dentry->d_name.name);

    char attrs[64] = {0};
    build_attributes(attrs, 64, attr);

    return 0;
}
