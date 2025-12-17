#include "../hook_utils.h"

char LICENSE[] SEC("license") = "GPL";

extern int bpf_ima_extend_measurement(const char *event_name, const char *namespace_id, const char *dependencies, const char *additional_data, u32 additional_data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;

SEC("lsm/inode_setattr")
int BPF_PROG(bpf_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
    char comm[16] = {0};
    u64 pid_tgid;
    u32 pid;
    // int cgroup_id;
    char cgroup_name[64] = {0};
    bpf_get_current_comm(comm, sizeof(comm));
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    // cgroup_id = bpf_get_current_cgroup_id();

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();

    struct css_set *cgroups = BPF_CORE_READ(cur, cgroups);
    if (cgroups)
    {
        struct cgroup *dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
        if (dfl)
        {
            struct kernfs_node *kn = BPF_CORE_READ(dfl, kn);
            if (kn)
            {
                bpf_probe_read_kernel_str(cgroup_name, sizeof(cgroup_name), BPF_CORE_READ(kn, name));
                bpf_printk(" cgroup_name: %s\n", cgroup_name);
            }
        }
    }
    struct bpfima_policy_config *policy = bpfima_get_policy();
    struct bpfima_hook_config *hook_cfg = bpfima_get_hook_config(HOOK_LSM_BPRM_CHECK_SECURITY);

    bool is_container_context = false;
    if (cgroup_name[0] != '\0')
    {
        /* Check if this cgroup should be ignored based on policy */
        if (bpfima_should_ignore_cgroup(cgroup_name, policy))
        {
            if (!policy || policy->log_level >= 3)
            {
                bpf_printk("Ignoring cgroup by policy: %s\n", cgroup_name);
            }
            return 0;
        }

        /* Check if this is actually a container, not just any cgroup */
        if (!hook_cfg || (hook_cfg->flags & HOOK_FLAG_TRACK_CONTAINERS))
        {
            if (bpfima_is_container_cgroup(cgroup_name))
            {
                is_container_context = true;
                if (!policy || policy->log_level >= 2)
                {
                    bpf_printk("Container context detected: %s\n", cgroup_name);
                }
            }
            else
            {
                if (!policy || policy->log_level >= 3)
                {
                    bpf_printk("Non-container cgroup (using host measurement): %s\n", cgroup_name);
                }
            }
        }
    }

    bpf_printk("Container context detected %d: %s\n", is_container_context, cgroup_name);

    char entry_name[16];
    bpf_core_read_str(entry_name, sizeof(entry_name), dentry->d_name.name);

    bpf_printk("LSM inode_setattr: process=%s PID=%u filepath=%s\n", comm, pid, entry_name);
    /*** SIMPLE IF CHECKS FOR ALL FLAGS ***/
    if (attr->ia_valid & ATTR_MODE)
        bpf_printk("ATTR_MODE: chmod -> %hu\n", attr->ia_mode);
    if (attr->ia_valid & ATTR_UID)
        bpf_printk("ATTR_UID: %u\n", attr->ia_uid.val);
    if (attr->ia_valid & ATTR_GID)
        bpf_printk("ATTR_GID: %u\n", attr->ia_gid.val);
    if (attr->ia_valid & ATTR_SIZE)
        bpf_printk("ATTR_SIZE: %lld\n", attr->ia_size);
    if (attr->ia_valid & ATTR_OPEN)
        bpf_printk("ATTR_OPEN (O_TRUNC)\n");
/*
    if (attr->ia_valid & ATTR_ATIME)
        bpf_printk("ATTR_ATIME: %lld.%ld\n", attr->ia_atime.tv_sec, attr->ia_atime.tv_nsec);
    if (attr->ia_valid & ATTR_MTIME)
        bpf_printk("ATTR_MTIME: %lld.%ld\n", attr->ia_mtime.tv_sec, attr->ia_mtime.tv_nsec);
    if (attr->ia_valid & ATTR_CTIME)
        bpf_printk("ATTR_CTIME: %lld.%ld\n", attr->ia_ctime.tv_sec, attr->ia_ctime.tv_nsec);
    if (attr->ia_valid & ATTR_ATIME_SET)
        bpf_printk("ATTR_ATIME_SET: %lld.%ld\n", attr->ia_atime.tv_sec, attr->ia_atime.tv_nsec);
    if (attr->ia_valid & ATTR_MTIME_SET)
        bpf_printk("ATTR_MTIME_SET: %lld.%ld\n", attr->ia_mtime.tv_sec, attr->ia_mtime.tv_nsec);
    if (attr->ia_valid & ATTR_FORCE)
        bpf_printk("ATTR_FORCE\n");
*/
    if (attr->ia_valid & ATTR_KILL_SUID)
        bpf_printk("ATTR_KILL_SUID\n");
    if (attr->ia_valid & ATTR_KILL_SGID)
        bpf_printk("ATTR_KILL_SGID\n");
    if (attr->ia_valid & ATTR_FILE)
        bpf_printk("ATTR_FILE: %p\n", attr->ia_file);
    if (attr->ia_valid & ATTR_KILL_PRIV)
        bpf_printk("ATTR_KILL_PRIV\n");

/*
    if (attr->ia_valid & ATTR_TIMES_SET)
        bpf_printk("ATTR_TIMES_SET\n");
    if (attr->ia_valid & ATTR_TOUCH)
        bpf_printk("ATTR_TOUCH\n");  
    if (attr->ia_valid & ATTR_DELEG)
        bpf_printk("ATTR_DELEG\n");
*/
    //char stack_dependencies_buf[64] = {0};
    //char *deps = stack_dependencies_buf;
    //int deps_max = sizeof(stack_dependencies_buf);

    /* Build dependency chain using the modular utility function */
    //int deps_actual = build_dependencies(deps, deps_max, entry_name, cur);

    char attrs[64] = {0};

    build_attributes(attrs, 64, attr);
    bpf_printk("ATTRS: %s\n", attrs);
/*
    char event_name[] = "inode_setattr";

    u8 hash[32];
    int ret = measure_accessed_file(attr->ia_file,
                                    event_name,
                                    cgroup_name,
                                    is_container_context,
                                    deps,
                                    deps_actual,
                                    deps_max,
                                    hash);
    if (ret < 0)
    {
        bpf_printk("The file measurement failed: %d\n", ret);
        return ret;
    }
    */
    return 0;
}
