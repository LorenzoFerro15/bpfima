#include "../../utils/headers_bpf.h"

#define EACCES_VALUE 13
#define EINVAL_VALUE 22

struct security_test_state
{
    __u32 target_pid;
    __u32 calls;
    __u32 failures;
    struct bpfima_measurement_request request;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct security_test_state);
} security_test_map SEC(".maps");

static __always_inline struct security_test_state *test_state(void)
{
    __u32 key = 0;
    struct security_test_state *state = bpf_map_lookup_elem(&security_test_map, &key);

    if (!state || state->target_pid != bpf_get_current_pid_tgid() >> 32)
        return NULL;
    return state;
}

static __always_inline int deny_target(int previous_ret)
{
    if (previous_ret != 0)
        return previous_ret;
    return test_state() ? -EACCES_VALUE : 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(deny_bprm, struct linux_binprm *bprm, int previous_ret)
{
    return deny_target(previous_ret);
}

SEC("lsm.s/file_post_open")
int BPF_PROG(deny_post_open, struct file *file, int mask, int previous_ret)
{
    return deny_target(previous_ret);
}

SEC("lsm.s/inode_setattr")
int BPF_PROG(deny_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int previous_ret)
{
    return deny_target(previous_ret);
}

SEC("lsm.s/mmap_file")
int BPF_PROG(deny_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int previous_ret)
{
    return deny_target(previous_ret);
}

SEC("lsm.s/socket_connect")
int BPF_PROG(deny_connect, struct socket *sock, struct sockaddr *address,
             int addrlen, int previous_ret)
{
    return deny_target(previous_ret);
}

/* These programs must be rejected before they can ever be attached. */
SEC("lsm.s/file_open")
int BPF_PROG(reject_root, struct file *file, int previous_ret)
{
    __u8 buffer[1] = {0};
    return bpfima_merkle_get_root(buffer, 32) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_measurement, struct file *file, int previous_ret)
{
    char buffer[1] = {0};
    return bpfima_measurement_extend(buffer, sizeof(struct bpfima_measurement_request)) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_container, struct file *file, int previous_ret)
{
    char id[1] = {0};
    return bpfima_container_exists(id, BPFIMA_NAMESPACE_SIZE) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_leaf, struct file *file, int previous_ret)
{
    char id[] = "test";
    __u8 buffer[1] = {0};
    return bpfima_container_get_leaf_hash(id, sizeof(id), buffer, 32) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_pcr, struct file *file, int previous_ret)
{
    char buffer[1] = {0};
    return bpfima_tpm_get_pcr_value(buffer, BPFIMA_PCR_BUFFER_SIZE) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_policy_hash, struct file *file, int previous_ret)
{
    char id[] = "test";
    __u8 buffer[1] = {0};
    return bpfima_policy_get_changes_hash(id, sizeof(id), buffer, 32) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_policy_config, struct file *file, int previous_ret)
{
    char id[] = "test";
    char buffer[1] = {0};
    return bpfima_policy_namespace_get_config(id, sizeof(id), buffer,
                                             sizeof(struct bpfima_policy_config)) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_policy_update, struct file *file, int previous_ret)
{
    char id[1] = {0};
    return bpfima_policy_update_filter_flags(id, BPFIMA_NAMESPACE_SIZE, 0) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_cgroup, struct file *file, int previous_ret)
{
    char name[1] = {0};
    return bpfima_policy_should_ignore_cgroup(name, BPFIMA_NAMESPACE_SIZE, 0) ? 0 : -EACCES_VALUE;
}

SEC("lsm.s/file_open")
int BPF_PROG(reject_path, struct file *file, int previous_ret)
{
    char path[1] = {0};
    return bpfima_policy_should_ignore_path(path, BPFIMA_PATH_SIZE, 0) ? 0 : -EACCES_VALUE;
}

SEC("lsm/file_open")
int BPF_PROG(reject_nonsleepable, struct file *file, int previous_ret)
{
    __u32 key = 0;
    struct security_test_state *state = bpf_map_lookup_elem(&security_test_map, &key);

    if (!state)
        return 0;
    return bpfima_measurement_extend(&state->request, sizeof(state->request)) ? -EACCES_VALUE : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(check_buffers, struct file *file, int previous_ret)
{
    struct security_test_state *state;
    char id[] = "test";
    char empty[] = "";
    char invalid[] = "/";
    char unterminated[] = {'x'};
    char pcr_buffer[BPFIMA_PCR_BUFFER_SIZE] = {0};
    __u8 output[33] = {0};
    struct bpfima_policy_config config = {0};

    if (previous_ret != 0)
        return previous_ret;
    state = test_state();
    if (!state)
        return 0;

    state->calls++;
    if (bpfima_measurement_extend(&state->request, sizeof(state->request)) != -EINVAL_VALUE)
        state->failures++;
    if (bpfima_container_exists(unterminated, sizeof(unterminated)) != -EINVAL_VALUE ||
        bpfima_container_get_measurement_count(empty, sizeof(empty)) != -EINVAL_VALUE ||
        bpfima_container_get_or_create(invalid, sizeof(invalid)) != -EINVAL_VALUE)
        state->failures++;
    if (bpfima_merkle_get_root(output, 31) != -EINVAL_VALUE ||
        bpfima_merkle_get_root(output, sizeof(output)) != -EINVAL_VALUE ||
        bpfima_container_get_leaf_hash(id, sizeof(id), output, 31) != -EINVAL_VALUE ||
        bpfima_container_get_leaf_hash(id, sizeof(id), output, sizeof(output)) != -EINVAL_VALUE ||
        bpfima_policy_get_changes_hash(id, sizeof(id), output, 31) != -EINVAL_VALUE ||
        bpfima_policy_get_changes_hash(id, sizeof(id), output, sizeof(output)) != -EINVAL_VALUE ||
        bpfima_tpm_get_pcr_value(pcr_buffer, BPFIMA_PCR_BUFFER_SIZE - 1) != -EINVAL_VALUE ||
        bpfima_policy_namespace_get_config(id, sizeof(id), &config,
                                           sizeof(config) - 1) != -EINVAL_VALUE)
        state->failures++;
    if (bpfima_policy_update_filter_flags(invalid, sizeof(invalid), 0) != -EINVAL_VALUE ||
        bpfima_policy_update_action_flags(invalid, sizeof(invalid), 0) != -EINVAL_VALUE ||
        bpfima_policy_update_min_file_size(invalid, sizeof(invalid), 0) != -EINVAL_VALUE ||
        bpfima_policy_update_log_level(invalid, sizeof(invalid), 0) != -EINVAL_VALUE)
        state->failures++;
    if (bpfima_policy_should_ignore_cgroup(NULL, 0, 0) ||
        bpfima_policy_should_ignore_path(NULL, 0, 0) ||
        bpfima_policy_should_ignore_cgroup(unterminated, sizeof(unterminated), 0) ||
        bpfima_policy_should_ignore_path(unterminated, sizeof(unterminated), 0))
        state->failures++;

    output[32] = 0xa5;
    if (bpfima_merkle_get_root(output, 32) != 0 || output[32] != 0xa5)
        state->failures++;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
