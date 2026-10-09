#ifndef BPFIMA_MODULE_INTERACTIONS_H
#define BPFIMA_MODULE_INTERACTIONS_H

#include "../../include/bpfima_kfunc_types.h"

#define TEST_HASH_SIZE 32
#define TEST_CANARY 0xa5
#define TEST_POLICY_CANARY 0xa5a5a5a5U
#define TEST_MAX_WORKERS 8
#define TEST_STRESS_EVENTS 8

enum module_test_command
{
    TEST_IDLE,
    TEST_SNAPSHOT,
    TEST_CREATE,
    TEST_MEASURE,
    TEST_UPDATE_FILTER,
    TEST_UPDATE_ACTION,
    TEST_UPDATE_MIN_SIZE,
    TEST_UPDATE_LOG_LEVEL,
    TEST_FILTERS,
    TEST_PCR,
    TEST_GLOBAL_POLICY, /* Userspace stress worker writes the SecurityFS policy. */
};

/* The hash-map key is a thread ID, so concurrent callers have private state. */
struct module_test_state
{
    __u32 target_pid;
    __u32 command;
    __u32 calls;
    int result;
    int exists;
    int measurement_count;
    int container_count;
    int leaf_result;
    int root_result;
    int policy_result;
    int changes_result;
    int tpm_available;
    __u32 ignore_cgroup;
    __u32 ignore_path;
    char namespace_id[BPFIMA_NAMESPACE_SIZE];
    struct bpfima_measurement_request request;
    struct bpfima_policy_config policy;
    __u32 policy_canary;
    __u8 leaf[TEST_HASH_SIZE + 1];
    __u8 root[TEST_HASH_SIZE + 1];
    __u8 changes[TEST_HASH_SIZE + 1];
    char pcr[BPFIMA_PCR_BUFFER_SIZE + 1];
};

#endif /* BPFIMA_MODULE_INTERACTIONS_H */
