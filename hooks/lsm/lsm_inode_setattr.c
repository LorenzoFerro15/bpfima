#include "../hook_utils.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/inode_setattr")
int BPF_PROG(bpf_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr, int previous_ret)
{
    if (previous_ret != 0)
        return previous_ret;

    if (!dentry || !attr)
        return 0;

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    int decision = bpfima_policy_for_hook(HOOK_LSM_INODE_SETATTR, (const char *)name, 0, 0);
    if (decision)
        return decision < 0 ? decision : 0;

    char attrs[64] = {0};
    int attr_len = build_attributes(attrs, sizeof(attrs), attr);
    if (attr_len <= 0)
        return 0;

    char event_name[] = "inode_setattr";
    struct measurement_ctx measurement = {
        .event_name = event_name,
        .namespace_id = bpfima_current_namespace(),
        .additional_data = attrs,
        .additional_data_len = attr_len,
    };
    int ret = bpfima_submit_measurement(&measurement);
    return ret;
}
