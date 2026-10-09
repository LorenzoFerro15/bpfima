#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <openssl/evp.h>

#include "module_interactions.h"
#include "check_kfunc_abi.h"

#define REQUIRE(condition, ...) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: "); \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        return 1; \
    } \
} while (0)

struct test_context
{
    int map_fd;
    const char *securityfs;
    char file_path[PATH_MAX];
    char prefix[64];
};

static volatile sig_atomic_t interrupted;
static char verifier_log[1024 * 1024];

static void handle_signal(int signal_number)
{
    interrupted = signal_number;
}

static void init_state(struct test_context *ctx, struct module_test_state *state,
                       enum module_test_command command, const char *suffix)
{
    memset(state, 0, sizeof(*state));
    state->command = command;
    snprintf(state->namespace_id, sizeof(state->namespace_id), "%s-%s", ctx->prefix, suffix);
    snprintf(state->request.namespace_id, sizeof(state->request.namespace_id), "%s", state->namespace_id);
    strcpy(state->request.event_name, "kernel_test");
    state->policy_canary = TEST_POLICY_CANARY;
    state->leaf[TEST_HASH_SIZE] = TEST_CANARY;
    state->root[TEST_HASH_SIZE] = TEST_CANARY;
    state->changes[TEST_HASH_SIZE] = TEST_CANARY;
    state->pcr[BPFIMA_PCR_BUFFER_SIZE] = TEST_CANARY;
}

static int submit(struct test_context *ctx, struct module_test_state *state)
{
    __u32 tid = syscall(SYS_gettid);
    __u32 command = state->command;
    int fd;
    int ret;

    REQUIRE(!interrupted, "test interrupted by signal %d", interrupted);
    state->target_pid = getpid();
    state->calls = 0;
    REQUIRE(!bpf_map_update_elem(ctx->map_fd, &tid, state, BPF_ANY), "arm command %u: %s",
            command, strerror(errno));
    fd = open(ctx->file_path, O_RDONLY | O_CLOEXEC);
    ret = fd < 0;
    if (ret)
        fprintf(stderr, "FAIL: trigger command %u: %s\n", command, strerror(errno));
    else
        close(fd);
    if (bpf_map_lookup_elem(ctx->map_fd, &tid, state))
    {
        fprintf(stderr, "FAIL: read command %u result: %s\n", command, strerror(errno));
        ret = 1;
    }
    if (bpf_map_delete_elem(ctx->map_fd, &tid))
    {
        fprintf(stderr, "FAIL: disarm command %u: %s\n", command, strerror(errno));
        ret = 1;
    }
    if (ret)
        return ret;
    REQUIRE(state->calls == 1 && state->command == TEST_IDLE,
            "command %u ran %u times (expected exactly once)", command, state->calls);
    REQUIRE(state->policy_canary == TEST_POLICY_CANARY &&
            state->leaf[TEST_HASH_SIZE] == TEST_CANARY &&
            state->root[TEST_HASH_SIZE] == TEST_CANARY &&
            state->changes[TEST_HASH_SIZE] == TEST_CANARY &&
            (unsigned char)state->pcr[BPFIMA_PCR_BUFFER_SIZE] == TEST_CANARY,
            "command %u overwrote an output buffer guard", command);
    return 0;
}

static int sha256(const void *data, size_t length, unsigned char *hash)
{
    unsigned int output_length = 0;

    REQUIRE(EVP_Digest(data, length, hash, &output_length, EVP_sha256(), NULL) == 1 &&
            output_length == TEST_HASH_SIZE, "independent SHA-256 calculation failed");
    return 0;
}

static int extend_hash(const unsigned char *old_hash, const unsigned char *digest,
                       unsigned char *new_hash)
{
    unsigned char data[TEST_HASH_SIZE * 2];

    memcpy(data, old_hash, TEST_HASH_SIZE);
    memcpy(data + TEST_HASH_SIZE, digest, TEST_HASH_SIZE);
    return sha256(data, sizeof(data), new_hash);
}

static int decode_hash(const char *text, unsigned char *hash)
{
    REQUIRE(strlen(text) == TEST_HASH_SIZE * 2, "hash has incorrect length");
    for (size_t i = 0; i < TEST_HASH_SIZE; i++)
    {
        char digits[] = {text[i * 2], text[i * 2 + 1], '\0'};
        char *end;
        unsigned long value = strtoul(digits, &end, 16);
        REQUIRE(isxdigit((unsigned char)digits[0]) && isxdigit((unsigned char)digits[1]) &&
                end == digits + 2, "invalid hex digest");
        hash[i] = value;
    }
    return 0;
}

static int namespace_path(struct test_context *ctx, const char *suffix, const char *file,
                          char *path, size_t size)
{
    int written = snprintf(path, size, "%s/namespaces/%s-%s/%s", ctx->securityfs, ctx->prefix, suffix, file);

    REQUIRE(written >= 0 && (size_t)written < size, "SecurityFS path too long");
    return 0;
}

static int read_text(const char *path, char *buffer, size_t size)
{
    FILE *file = fopen(path, "r");
    size_t length;
    int failed;

    REQUIRE(file, "open %s: %s", path, strerror(errno));
    length = fread(buffer, 1, size - 1, file);
    failed = ferror(file) || !feof(file);
    fclose(file);
    REQUIRE(!failed, "read %s failed or exceeded %zu bytes", path, size - 1);
    buffer[length] = '\0';
    return 0;
}

/* Replay the public measurement/history stream, independently of the kfuncs. */
static int replay_log(const char *path, bool history, unsigned char *hash, unsigned int *count)
{
    FILE *file = fopen(path, "r");
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    int ret = 0;

    REQUIRE(file, "open %s: %s", path, strerror(errno));
    memset(hash, 0, TEST_HASH_SIZE);
    *count = 0;
    while ((length = getline(&line, &capacity, file)) >= 0)
    {
        unsigned char digest[TEST_HASH_SIZE];
        unsigned char next[TEST_HASH_SIZE];

        if (interrupted || length < TEST_HASH_SIZE * 2 + 1 ||
            (history ? line[64] != '\n' : line[64] != ' '))
        {
            fprintf(stderr, "FAIL: malformed or aggregated record in %s; use a fresh module\n", path);
            ret = 1;
            break;
        }
        line[64] = '\0';
        if (decode_hash(line, digest) || extend_hash(hash, digest, next))
        {
            ret = 1;
            break;
        }
        memcpy(hash, next, TEST_HASH_SIZE);
        (*count)++;
    }
    if (ferror(file))
    {
        fprintf(stderr, "FAIL: reading %s: %s\n", path, strerror(errno));
        ret = 1;
    }
    free(line);
    fclose(file);
    return ret;
}

static int check_replay(struct test_context *ctx, const char *suffix, int expected_count)
{
    struct module_test_state state;
    unsigned char replayed[TEST_HASH_SIZE];
    unsigned int count;
    char path[PATH_MAX];

    init_state(ctx, &state, TEST_SNAPSHOT, suffix);
    if (submit(ctx, &state) || namespace_path(ctx, suffix, "measurements", path, sizeof(path)) ||
        replay_log(path, false, replayed, &count))
        return 1;
    REQUIRE(state.leaf_result == 0 && state.measurement_count == expected_count &&
            count == (unsigned int)expected_count,
            "%s has kfunc count %d and log count %u, expected %d", suffix,
            state.measurement_count, count, expected_count);
    REQUIRE(memcmp(replayed, state.leaf, TEST_HASH_SIZE) == 0,
            "%s measurement order does not reproduce the leaf hash", suffix);
    snprintf(path, sizeof(path), "%s/merkle_root_history", ctx->securityfs);
    if (replay_log(path, true, replayed, &count))
        return 1;
    REQUIRE(state.root_result == 0 && memcmp(replayed, state.root, TEST_HASH_SIZE) == 0,
            "history order does not reproduce the global root; stop other measuring programs");
    return 0;
}

static int test_namespaces(struct test_context *ctx)
{
    struct module_test_state state;
    unsigned char zero[TEST_HASH_SIZE] = {0};
    unsigned char initial_root[TEST_HASH_SIZE];
    int initial_count;

    init_state(ctx, &state, TEST_SNAPSHOT, "measure");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.exists == 0 && state.measurement_count == -ENOENT && state.leaf_result == -ENOENT &&
            state.policy_result == -ENOENT && state.changes_result == -ENOENT && state.root_result == 0,
            "missing namespace results do not match the API");
    initial_count = state.container_count;
    memcpy(initial_root, state.root, sizeof(initial_root));
    for (int i = 0; i < 2; i++)
    {
        init_state(ctx, &state, TEST_CREATE, "measure");
        if (submit(ctx, &state))
            return 1;
        REQUIRE(state.result == 0 && state.exists == 1 && state.measurement_count == 0 &&
                state.container_count == initial_count + 1 && state.leaf_result == 0 &&
                state.policy_result == 0 && state.changes_result == 0,
                "namespace creation/idempotence failed (result=%d)", state.result);
        REQUIRE(!memcmp(zero, state.leaf, sizeof(zero)) && !memcmp(initial_root, state.root, sizeof(initial_root)),
                "creating an empty namespace changed the leaf/root hash");
    }
    puts("PASS: missing namespace errors, creation, idempotence, and output guards");
    return 0;
}

static int read_pcr(struct test_context *ctx, struct module_test_state *state)
{
    char parameter[32];
    char expected[32];
    if (read_text("/sys/module/bpfima/parameters/tpm_pcr_index", parameter, sizeof(parameter)))
        return 1;
    int pcr_index = atoi(parameter);
    REQUIRE(pcr_index >= 0 && pcr_index <= 23, "invalid configured PCR index");
    init_state(ctx, state, TEST_PCR, "measure");
    if (submit(ctx, state))
        return 1;
    REQUIRE(state->result == 0 && (state->tpm_available == 0 || state->tpm_available == 1) &&
            memchr(state->pcr, '\0', BPFIMA_PCR_BUFFER_SIZE), "TPM/PCR API failed (result=%d)", state->result);
    if (state->tpm_available)
    {
        unsigned char digest[TEST_HASH_SIZE];
        snprintf(expected, sizeof(expected), "PCR%d_REAL:", pcr_index);
        REQUIRE(strncmp(state->pcr, expected, strlen(expected)) == 0,
                "unexpected hardware PCR output: %s", state->pcr);
        return decode_hash(state->pcr + strlen(expected), digest);
    }
    snprintf(expected, sizeof(expected), "PCR%d_HASH_SIMULATION", pcr_index);
    REQUIRE(strcmp(state->pcr, expected) == 0,
            "unexpected no-TPM simulation output: %s", state->pcr);
    return 0;
}

static int test_measurements(struct test_context *ctx)
{
    struct module_test_state before;
    struct module_test_state state;
    struct module_test_state pcr_before;
    struct module_test_state pcr_after;
    unsigned char digest[TEST_HASH_SIZE];
    unsigned char expected_leaf[TEST_HASH_SIZE];
    unsigned char expected_root[TEST_HASH_SIZE];
    unsigned char previous_leaf[TEST_HASH_SIZE];
    unsigned char previous_root[TEST_HASH_SIZE];
    char template_data[BPFIMA_EVENT_DATA_SIZE + BPFIMA_DEPENDENCIES_SIZE];
    char log[8192];
    char path[PATH_MAX];

    if (read_pcr(ctx, &pcr_before))
        return 1;
    puts("PASS: TPM availability and bounded hardware/simulation PCR read");
    for (int i = 0; i < 4; i++)
    {
        init_state(ctx, &before, TEST_SNAPSHOT, "measure");
        if (submit(ctx, &before))
            return 1;
        init_state(ctx, &state, TEST_MEASURE, "measure");
        switch (i)
        {
        case 0:
            strcpy(state.request.additional_data, "payload-one");
            state.request.additional_data_len = strlen(state.request.additional_data);
            strcpy(template_data, "payload-one");
            break;
        case 1:
            strcpy(state.request.additional_data, "payload-two");
            strcpy(state.request.dependencies, "parent-chain");
            state.request.additional_data_len = strlen(state.request.additional_data);
            state.request.flags = BPFIMA_MEASUREMENT_HAS_DEPENDENCIES;
            strcpy(template_data, "payload-two parent-chain");
            break;
        case 2:
            strcpy(state.request.dependencies, "dependencies-only");
            state.request.flags = BPFIMA_MEASUREMENT_HAS_DEPENDENCIES;
            strcpy(template_data, "dependencies-only");
            break;
        default:
            memset(state.request.additional_data, 'a', BPFIMA_EVENT_DATA_SIZE - 1);
            memset(state.request.dependencies, 'd', BPFIMA_DEPENDENCIES_SIZE - 1);
            state.request.additional_data_len = BPFIMA_EVENT_DATA_SIZE - 1;
            state.request.flags = BPFIMA_MEASUREMENT_HAS_DEPENDENCIES;
            snprintf(template_data, sizeof(template_data), "%s %s",
                     state.request.additional_data, state.request.dependencies);
            break;
        }
        if (sha256(template_data, strlen(template_data), digest) ||
            extend_hash(before.leaf, digest, expected_leaf) ||
            extend_hash(before.root, expected_leaf, expected_root) || submit(ctx, &state))
            return 1;
        REQUIRE(state.result == 0 && state.measurement_count == i + 1 &&
                state.leaf_result == 0 && state.root_result == 0 &&
                !memcmp(state.leaf, expected_leaf, TEST_HASH_SIZE) &&
                !memcmp(state.root, expected_root, TEST_HASH_SIZE),
                "measurement case %d failed (result=%d, count=%d)", i, state.result, state.measurement_count);
        if (i == 0 && pcr_before.tpm_available)
        {
            unsigned char old_pcr[TEST_HASH_SIZE];
            unsigned char new_pcr[TEST_HASH_SIZE];
            unsigned char expected_pcr[TEST_HASH_SIZE];
            char parameter[32];

            if (read_pcr(ctx, &pcr_after) ||
                read_text("/sys/module/bpfima/parameters/tpm_pcr_index", parameter, sizeof(parameter)))
                return 1;
            if (strcmp(parameter, "23\n") == 0)
            {
                if (decode_hash(pcr_before.pcr + 11, old_pcr) || decode_hash(pcr_after.pcr + 11, new_pcr) ||
                    extend_hash(old_pcr, expected_root, expected_pcr))
                    return 1;
                REQUIRE(!memcmp(new_pcr, expected_pcr, TEST_HASH_SIZE), "TPM PCR23 did not extend the new root");
                puts("PASS: physical TPM PCR23 extension matches SHA-256(previous PCR || root)");
            }
            else
                puts("SKIP: physical PCR extension check requires tpm_pcr_index=23");
        }
        memcpy(previous_leaf, state.leaf, TEST_HASH_SIZE);
        memcpy(previous_root, state.root, TEST_HASH_SIZE);
        state.command = TEST_MEASURE;
        if (submit(ctx, &state))
            return 1;
        REQUIRE(state.result == 0 && state.measurement_count == i + 1 &&
                !memcmp(previous_leaf, state.leaf, TEST_HASH_SIZE) && !memcmp(previous_root, state.root, TEST_HASH_SIZE),
                "duplicate measurement case %d changed count, leaf, or root", i);
    }
    if (!pcr_before.tpm_available)
        puts("SKIP: physical PCR extension check (no TPM; simulation read was tested)");
    if (namespace_path(ctx, "measure", "measurements", path, sizeof(path)) || read_text(path, log, sizeof(log)))
        return 1;
    REQUIRE(strstr(log, " kernel_test payload-one\n") &&
            strstr(log, " kernel_test payload-two parent-chain\n") &&
            strstr(log, " kernel_test dependencies-only\n"), "SecurityFS lost event names, data, or dependencies");
    if (check_replay(ctx, "measure", 4))
        return 1;
    puts("PASS: payload, dependencies, maximum lengths, duplicate suppression, and SecurityFS/hash replay");

    init_state(ctx, &state, TEST_MEASURE, "isolated");
    strcpy(state.request.additional_data, "payload-one");
    state.request.additional_data_len = strlen(state.request.additional_data);
    memset(previous_leaf, 0, sizeof(previous_leaf));
    if (sha256("payload-one", 11, digest) || extend_hash(previous_leaf, digest, expected_leaf) || submit(ctx, &state))
        return 1;
    REQUIRE(state.result == 0 && state.measurement_count == 1 && !memcmp(expected_leaf, state.leaf, TEST_HASH_SIZE),
            "the same digest was suppressed in a different namespace");
    if (check_replay(ctx, "isolated", 1) || check_replay(ctx, "measure", 4))
        return 1;
    puts("PASS: automatic namespace creation and namespace-scoped deduplication");
    return 0;
}

static int test_policy(struct test_context *ctx)
{
    struct module_test_state state;
    const enum module_test_command commands[] = {
        TEST_UPDATE_FILTER, TEST_UPDATE_ACTION, TEST_UPDATE_MIN_SIZE, TEST_UPDATE_LOG_LEVEL,
    };
    const char *changes = "initialized,filter_flags=0x2,action_flags=0x40,min_file_size=0x1000,log_level=0x3,";
    char global_before[8192];
    char global_after[8192];
    char text[8192];
    char path[PATH_MAX];
    unsigned char expected_hash[TEST_HASH_SIZE];
    unsigned char previous_leaf[TEST_HASH_SIZE];
    unsigned char previous_root[TEST_HASH_SIZE];
    unsigned char previous_changes[TEST_HASH_SIZE];
    struct bpfima_policy_config previous_policy;
    int fd;
    ssize_t written;
    int saved_errno;

    snprintf(path, sizeof(path), "%s/policy", ctx->securityfs);
    if (read_text(path, global_before, sizeof(global_before)))
        return 1;
    init_state(ctx, &state, TEST_CREATE, "policy");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.result == 0, "create policy namespace returned %d", state.result);
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
    {
        init_state(ctx, &state, commands[i], "policy");
        state.policy.filter_flags = 2;
        state.policy.action_flags = 64;
        state.policy.min_file_size = 4096;
        state.policy.log_level = 3;
        if (submit(ctx, &state))
            return 1;
        REQUIRE(state.result == 0 && state.policy_result == 0 && state.changes_result == 0 &&
                state.measurement_count == (int)i + 1, "policy command %u failed (result=%d)", commands[i], state.result);
    }
    REQUIRE(state.policy.filter_flags == 2 && state.policy.action_flags == 64 &&
            state.policy.min_file_size == 4096 && state.policy.log_level == 3, "policy ABI round-trip lost fields");
    if (sha256(changes, strlen(changes), expected_hash))
        return 1;
    REQUIRE(!memcmp(expected_hash, state.changes, TEST_HASH_SIZE), "policy changes hash does not match the update log");
    if (namespace_path(ctx, "policy", "policy", path, sizeof(path)) || read_text(path, text, sizeof(text)))
        return 1;
    REQUIRE(strstr(text, "filter_flags=0x2\n") && strstr(text, "action_flags=0x40\n") &&
            strstr(text, "min_file_size=4096\n") && strstr(text, "log_level=3\n") && strstr(text, changes),
            "SecurityFS does not reflect kfunc policy updates");
    fd = open(path, O_WRONLY | O_CLOEXEC);
    REQUIRE(fd >= 0, "open namespace policy for write: %s", strerror(errno));
    written = write(fd, "min_file_size=8192\n", sizeof("min_file_size=8192\n") - 1);
    saved_errno = errno;
    close(fd);
    REQUIRE(written == (ssize_t)sizeof("min_file_size=8192\n") - 1,
            "SecurityFS policy write failed: %s", strerror(saved_errno));
    init_state(ctx, &state, TEST_SNAPSHOT, "policy");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.policy_result == 0 && state.policy.min_file_size == 8192 && state.measurement_count == 5,
            "kfunc did not observe the SecurityFS policy update");
    snprintf(text, sizeof(text), "%smin_file_size=0x2000,", changes);
    if (sha256(text, strlen(text), expected_hash))
        return 1;
    REQUIRE(state.changes_result == 0 && !memcmp(expected_hash, state.changes, TEST_HASH_SIZE),
            "SecurityFS write did not update the policy changes hash");
    memcpy(previous_leaf, state.leaf, TEST_HASH_SIZE);
    memcpy(previous_root, state.root, TEST_HASH_SIZE);
    memcpy(previous_changes, state.changes, TEST_HASH_SIZE);
    memcpy(&previous_policy, &state.policy, sizeof(previous_policy));
    const char *invalid_writes[] = {"unknown_field=1\n", "log_level=4\n", "min_file_size=4294967296\n"};
    for (size_t i = 0; i < sizeof(invalid_writes) / sizeof(invalid_writes[0]); i++) {
        fd = open(path, O_WRONLY | O_CLOEXEC);
        REQUIRE(fd >= 0, "open namespace policy for invalid write: %s", strerror(errno));
        written = write(fd, invalid_writes[i], strlen(invalid_writes[i]));
        saved_errno = errno;
        close(fd);
        REQUIRE(written == -1 && saved_errno == (i == 2 ? ERANGE : EINVAL),
                "invalid SecurityFS field/value was accepted: %s", invalid_writes[i]);
    }
    init_state(ctx, &state, TEST_SNAPSHOT, "policy");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.policy_result == 0 && state.changes_result == 0 && state.measurement_count == 5 &&
            !memcmp(&previous_policy, &state.policy, sizeof(previous_policy)) &&
            !memcmp(previous_changes, state.changes, TEST_HASH_SIZE) &&
            !memcmp(previous_leaf, state.leaf, TEST_HASH_SIZE) && !memcmp(previous_root, state.root, TEST_HASH_SIZE),
            "rejected policy write modified committed state");
    snprintf(path, sizeof(path), "%s/policy", ctx->securityfs);
    if (read_text(path, global_after, sizeof(global_after)) || check_replay(ctx, "policy", 5))
        return 1;
    REQUIRE(!strcmp(global_before, global_after), "namespace policy update changed the global policy");
    puts("PASS: all policy setters, change hash, SecurityFS round-trip, invalid writes, and namespace isolation");
    return 0;
}

static int test_filters(struct test_context *ctx)
{
    struct module_test_state state;

    init_state(ctx, &state, TEST_FILTERS, "filters");
    strcpy(state.namespace_id, "/");
    strcpy(state.request.additional_data, "/tmp/bpfima-kernel-test");
    state.policy.filter_flags = 1U << 7;
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.ignore_cgroup && state.ignore_path, "root cgroup or temporary path filter failed");
    init_state(ctx, &state, TEST_FILTERS, "filters");
    strcpy(state.namespace_id, "init.scope");
    strcpy(state.request.additional_data, "/bpfima-kernel-test-file");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.ignore_cgroup && !state.ignore_path, "init.scope or ordinary path filter failed");
    init_state(ctx, &state, TEST_FILTERS, "filters");
    strcpy(state.request.additional_data, "/proc/self/status");
    state.policy.filter_flags = 1U << 1;
    if (submit(ctx, &state))
        return 1;
    REQUIRE(!state.ignore_cgroup && state.ignore_path, "ordinary cgroup or proc path filter failed");
    puts("PASS: positive and negative cgroup/path filtering through module kfuncs");
    return 0;
}

struct stress_gate
{
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool released;
    bool aborted;
};

struct stress_worker
{
    struct test_context *ctx;
    struct stress_gate *gate;
    const char *suffix;
    unsigned int index;
    enum module_test_command command;
    bool duplicate;
    int result;
};

static int write_global_log_level(struct test_context *ctx, unsigned int level)
{
    char path[PATH_MAX];
    char value[32];
    snprintf(path, sizeof(path), "%s/policy", ctx->securityfs);
    int length = snprintf(value, sizeof(value), "log_level=%u\n", level);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    REQUIRE(fd >= 0, "open global policy: %s", strerror(errno));
    ssize_t written = write(fd, value, length);
    int saved_errno = errno;
    close(fd);
    REQUIRE(written == length, "write global policy: %s", strerror(saved_errno));
    return 0;
}

static void *stress_thread(void *data)
{
    struct stress_worker *worker = data;
    struct module_test_state state;

    pthread_mutex_lock(&worker->gate->mutex);
    while (!worker->gate->released)
        pthread_cond_wait(&worker->gate->condition, &worker->gate->mutex);
    bool aborted = worker->gate->aborted;
    pthread_mutex_unlock(&worker->gate->mutex);
    if (aborted)
        return NULL;
    for (unsigned int i = 0; i < (worker->command == TEST_CREATE || worker->duplicate ? 1U : TEST_STRESS_EVENTS); i++)
    {
        if (worker->command == TEST_GLOBAL_POLICY) {
            if (write_global_log_level(worker->ctx, (worker->index + i) % 4)) {
                worker->result = 1;
                break;
            }
            continue;
        }
        init_state(worker->ctx, &state, worker->command, worker->suffix);
        if (worker->command == TEST_MEASURE)
        {
            snprintf(state.request.additional_data, sizeof(state.request.additional_data), "worker-%u-event-%u",
                     worker->duplicate ? 0 : worker->index, i);
            state.request.additional_data_len = strlen(state.request.additional_data);
        }
        if (worker->command == TEST_UPDATE_MIN_SIZE)
            state.policy.min_file_size = 10000 + worker->index * TEST_STRESS_EVENTS + i;
        if (submit(worker->ctx, &state) || state.result != 0)
        {
            fprintf(stderr, "FAIL: concurrent command %u for worker %u returned %d\n",
                    worker->command, worker->index, state.result);
            worker->result = 1;
            break;
        }
    }
    return NULL;
}

static int parallel_calls(struct test_context *ctx, const char *suffix,
                          enum module_test_command command, bool duplicate, bool mixed)
{
    struct stress_worker workers[TEST_MAX_WORKERS];
    pthread_t threads[TEST_MAX_WORKERS];
    struct stress_gate gate = {0};
    unsigned int started = 0;
    int ret = 0;

    REQUIRE(!pthread_mutex_init(&gate.mutex, NULL), "initialize concurrency mutex");
    if (pthread_cond_init(&gate.condition, NULL))
    {
        pthread_mutex_destroy(&gate.mutex);
        fprintf(stderr, "FAIL: initialize concurrency condition\n");
        return 1;
    }
    for (; started < TEST_MAX_WORKERS; started++)
    {
        workers[started] = (struct stress_worker){
            .ctx = ctx, .gate = &gate, .suffix = suffix, .index = started,
            .command = mixed ? (started % 3 == 2 ? TEST_GLOBAL_POLICY :
                                  started % 3 == 1 ? TEST_UPDATE_MIN_SIZE : TEST_MEASURE) : command,
            .duplicate = duplicate,
        };
        int error = pthread_create(&threads[started], NULL, stress_thread, &workers[started]);
        if (error)
        {
            fprintf(stderr, "FAIL: create worker: %s\n", strerror(error));
            ret = 1;
            break;
        }
    }
    pthread_mutex_lock(&gate.mutex);
    gate.aborted = ret != 0;
    gate.released = true;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    for (unsigned int i = 0; i < started; i++)
    {
        if (pthread_join(threads[i], NULL) || workers[i].result)
            ret = 1;
    }
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    return ret;
}

/* Replay only the new physical extensions, using the PCR captured before workers start. */
static int check_concurrent_pcr(struct test_context *ctx, const struct module_test_state *before,
                                unsigned int initial_history_count)
{
    struct module_test_state after;
    unsigned char root[TEST_HASH_SIZE] = {0};
    unsigned char expected[TEST_HASH_SIZE];
    unsigned char actual[TEST_HASH_SIZE];
    unsigned int count = 0;
    char path[PATH_MAX];
    char *line = NULL;
    size_t capacity = 0;
    int ret = 0;

    if (!before->tpm_available || strncmp(before->pcr, "PCR23_REAL:", 11)) {
        puts("SKIP: concurrent physical PCR replay requires TPM SHA-256 PCR23");
        return 0;
    }
    if (decode_hash(before->pcr + 11, expected))
        return 1;
    snprintf(path, sizeof(path), "%s/merkle_root_history", ctx->securityfs);
    FILE *file = fopen(path, "r");
    REQUIRE(file, "open concurrent history: %s", strerror(errno));
    ssize_t length;
    while ((length = getline(&line, &capacity, file)) >= 0) {
        unsigned char value[TEST_HASH_SIZE];
        if (length != 65 || line[64] != '\n') {
            ret = 1;
            break;
        }
        line[64] = '\0';
        if (decode_hash(line, value) || extend_hash(root, value, root) ||
            (count >= initial_history_count && extend_hash(expected, root, expected))) {
            ret = 1;
            break;
        }
        count++;
    }
    if (ferror(file) || count < initial_history_count)
        ret = 1;
    free(line);
    fclose(file);
    if (ret || read_pcr(ctx, &after))
        return 1;
    REQUIRE(after.tpm_available && !strncmp(after.pcr, "PCR23_REAL:", 11), "TPM availability changed during stress");
    if (decode_hash(after.pcr + 11, actual))
        return 1;
    REQUIRE(!memcmp(expected, actual, TEST_HASH_SIZE), "concurrent history order does not reproduce physical PCR23");
    puts("PASS: concurrent history/root order reproduces physical TPM PCR23");
    return 0;
}

static int test_concurrency(struct test_context *ctx)
{
    struct module_test_state state;
    int before_count;
    int ret = 0;

    init_state(ctx, &state, TEST_SNAPSHOT, "race-create");
    if (submit(ctx, &state))
        return 1;
    before_count = state.container_count;
    if (parallel_calls(ctx, "race-create", TEST_CREATE, false, false))
        ret = 1;
    init_state(ctx, &state, TEST_SNAPSHOT, "race-create");
    if (submit(ctx, &state))
        return 1;
    if (state.exists != 1 || state.container_count != before_count + 1 || state.measurement_count != 0)
    {
        fprintf(stderr, "FAIL: concurrent creation did not publish exactly one container\n");
        ret = 1;
    }
    if (!ret)
        puts("PASS: concurrent creation of one namespace");
    init_state(ctx, &state, TEST_CREATE, "race-unique");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.result == 0, "create unique-race namespace returned %d", state.result);
    if (parallel_calls(ctx, "race-unique", TEST_MEASURE, false, false) ||
        check_replay(ctx, "race-unique", TEST_MAX_WORKERS * TEST_STRESS_EVENTS))
        ret = 1;
    else
        puts("PASS: concurrent unique measurements, counts, leaf replay, and global history order");
    init_state(ctx, &state, TEST_CREATE, "race-duplicate");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.result == 0, "create duplicate-race namespace returned %d", state.result);
    if (parallel_calls(ctx, "race-duplicate", TEST_MEASURE, true, false) || check_replay(ctx, "race-duplicate", 1))
        ret = 1;
    else
        puts("PASS: concurrent duplicate measurements commit exactly once");

    init_state(ctx, &state, TEST_CREATE, "race-mixed");
    if (submit(ctx, &state))
        return 1;
    REQUIRE(state.result == 0, "create mixed-race namespace returned %d", state.result);
    char path[PATH_MAX], policy[8192];
    unsigned char initial_root[TEST_HASH_SIZE];
    unsigned int initial_history_count;
    struct module_test_state pcr_before;
    snprintf(path, sizeof(path), "%s/policy", ctx->securityfs);
    if (read_text(path, policy, sizeof(policy)))
        return 1;
    const char *level = strstr(policy, "log_level=");
    REQUIRE(level, "global policy has no log level");
    unsigned int original_level = strtoul(level + strlen("log_level="), NULL, 10);
    snprintf(path, sizeof(path), "%s/merkle_root_history", ctx->securityfs);
    if (replay_log(path, true, initial_root, &initial_history_count) || read_pcr(ctx, &pcr_before))
        return 1;
    int mixed_result = parallel_calls(ctx, "race-mixed", TEST_MEASURE, false, true);
    /* Restore the global setting even when a worker fails. The restoration is an event too. */
    if (write_global_log_level(ctx, original_level))
        return 1;
    if (mixed_result || check_replay(ctx, "race-mixed",
                                   (TEST_MAX_WORKERS - TEST_MAX_WORKERS / 3) * TEST_STRESS_EVENTS) ||
        check_concurrent_pcr(ctx, &pcr_before, initial_history_count))
        ret = 1;
    else
        puts("PASS: mixed measurement/namespace-policy/global-policy commits preserve replay order");
    return ret;
}

int main(int argc, char **argv)
{
    struct test_context ctx = {0};
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct sigaction action = {.sa_handler = handle_signal};
    const char *temporary_root = getenv("TMPDIR");
    char directory[PATH_MAX];
    char status_path[PATH_MAX];
    char status[512];
    int fd = -1;
    int ret = 1;
    bool created_directory = false;
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf = verifier_log,
        .kernel_log_size = sizeof(verifier_log),
        .kernel_log_level = 1);

    if (argc == 2 && !strcmp(argv[1], "--check-abi"))
        return bpfima_test_check_kfunc_abi();
    if ((argc != 3 && argc != 4) || (argc == 4 && strcmp(argv[3], "--stress")))
    {
        fprintf(stderr, "Usage: %s fixture.bpf.o securityfs-directory [--stress]\n", argv[0]);
        return 2;
    }
    if (geteuid() != 0 || access("/sys/kernel/btf/bpfima", R_OK))
    {
        fprintf(stderr, "Requires root and the updated bpfima module loaded with BTF.\n");
        return 2;
    }
    if (bpfima_test_check_kfunc_abi())
        return 1;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    ctx.securityfs = argv[2];
    int written = snprintf(status_path, sizeof(status_path), "%s/status", ctx.securityfs);
    if (written < 0 || (size_t)written >= sizeof(status_path))
    {
        fprintf(stderr, "FAIL: SecurityFS status path is too long\n");
        goto cleanup;
    }
    if (read_text(status_path, status, sizeof(status)))
        goto cleanup;
    if (!strstr(status, "module=bpfima\n") || !strstr(status, "digest_algorithm=sha256\n"))
    {
        fprintf(stderr, "FAIL: SecurityFS status identifies the wrong module/algorithm\n");
        goto cleanup;
    }
    puts("PASS: loaded module SecurityFS status and SHA-256 algorithm");
    written = snprintf(directory, sizeof(directory), "%s/bpfima-kernel-XXXXXX",
                       temporary_root ? temporary_root : "/tmp");
    if (written < 0 || (size_t)written >= sizeof(directory))
    {
        fprintf(stderr, "FAIL: temporary directory path is too long\n");
        goto cleanup;
    }
    if (!mkdtemp(directory))
    {
        fprintf(stderr, "FAIL: create temporary directory: %s\n", strerror(errno));
        goto cleanup;
    }
    created_directory = true;
    snprintf(ctx.prefix, sizeof(ctx.prefix), "%s", strrchr(directory, '/') + 1);
    written = snprintf(ctx.file_path, sizeof(ctx.file_path), "%s/trigger", directory);
    if (written < 0 || (size_t)written >= sizeof(ctx.file_path))
    {
        fprintf(stderr, "FAIL: trigger file path is too long\n");
        goto cleanup;
    }
    fd = open(ctx.file_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        fprintf(stderr, "FAIL: create trigger file: %s\n", strerror(errno));
        goto cleanup;
    }
    close(fd);
    fd = -1;
    obj = bpf_object__open_file(argv[1], &opts);
    if (!obj || libbpf_get_error(obj))
    {
        obj = NULL;
        fprintf(stderr, "FAIL: could not open BPF fixture %s\n", argv[1]);
        goto cleanup;
    }
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "FAIL: interaction fixture did not load:\n%s\n", verifier_log);
        goto cleanup;
    }
    ctx.map_fd = bpf_object__find_map_fd_by_name(obj, "module_test_map");
    link = bpf_program__attach(bpf_object__find_program_by_name(obj, "module_interactions"));
    if (!link || libbpf_get_error(link))
    {
        link = NULL;
        fprintf(stderr, "FAIL: could not attach BPF interaction fixture\n");
        goto cleanup;
    }
    ret = test_namespaces(&ctx);
    if (!ret)
        ret = test_measurements(&ctx);
    if (!ret)
        ret = test_policy(&ctx);
    if (!ret)
        ret = test_filters(&ctx);
    if (!ret && argc == 4)
        ret = test_concurrency(&ctx);
    if (!ret)
        puts("PASS: module interaction suite completed");

cleanup:
    if (interrupted)
        ret = 1;
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (fd >= 0)
        close(fd);
    if (created_directory)
    {
        if (ctx.file_path[0])
            unlink(ctx.file_path);
        rmdir(directory);
    }
    return ret;
}
