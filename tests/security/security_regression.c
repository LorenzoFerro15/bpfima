#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpfima_kfunc_types.h"
#include "../kernel/check_kfunc_abi.h"

struct security_test_state
{
    __u32 target_pid;
    __u32 calls;
    __u32 failures;
    struct bpfima_measurement_request request;
    __u32 attribute_case;
    __s32 attribute_length;
    char attributes[64];
};

static char verifier_log[1024 * 1024];
static volatile sig_atomic_t interrupted;

static void handle_signal(int signal_number)
{
    interrupted = signal_number;
}

static struct bpf_object *load_program(const char *path, const char *name)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf = verifier_log,
        .kernel_log_size = sizeof(verifier_log),
        .kernel_log_level = 1);

    verifier_log[0] = '\0';
    obj = bpf_object__open_file(path, &opts);
    if (!obj || libbpf_get_error(obj))
        return NULL;

    bpf_object__for_each_map(map, obj)
        bpf_map__set_pin_path(map, NULL);
    bpf_object__for_each_program(prog, obj)
        bpf_program__set_autoload(prog, !name || strcmp(bpf_program__name(prog), name) == 0);

    if (bpf_object__load(obj))
    {
        bpf_object__close(obj);
        return NULL;
    }
    return obj;
}

static int write_state(int fd, const struct security_test_state *state)
{
    __u32 key = 0;
    return bpf_map_update_elem(fd, &key, state, BPF_ANY);
}

static struct bpf_object *load_rejected_program(const char *path, const char *name)
{
    libbpf_print_fn_t previous = libbpf_set_print(NULL);
    struct bpf_object *obj = load_program(path, name);

    libbpf_set_print(previous);
    return obj;
}

static int test_attributes(const char *fixture, const char *file_path)
{
    const char *names[] = {"empty", "combined", "truncated", "negative offset",
                           "full buffer", "exact fit", "one-byte overflow", "privilege flags"};
    const int lengths[] = {0, sizeof("mode=384,uid=1000,gid=1001,size=4096") - 1,
                            -1, -1, -1, 63, -1,
                            sizeof("kill_priv=1,kill_suid=1,kill_sgid=1") - 1};
    struct bpf_object *obj = load_program(fixture, "check_attributes");
    struct bpf_link *link;
    __u32 key = 0;
    int ret = 1;

    if (!obj)
    {
        fprintf(stderr, "Unable to load the attribute formatter test:\n%s\n", verifier_log);
        return 1;
    }
    int map_fd = bpf_object__find_map_fd_by_name(obj, "security_test_map");
    link = bpf_program__attach(bpf_object__find_program_by_name(obj, "check_attributes"));
    if (!link || libbpf_get_error(link))
        goto cleanup_object;

    for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        struct security_test_state state = {.target_pid = getpid(), .attribute_case = i};
        char expected[64] = {0};

        if (interrupted || write_state(map_fd, &state))
            goto cleanup_link;
        int fd = open(file_path, O_RDONLY);
        if (fd < 0)
            goto cleanup_link;
        close(fd);
        if (i == 1)
            strcpy(expected, "mode=384,uid=1000,gid=1001,size=4096");
        else if (i == 2)
            strcpy(expected, "mode=65535,uid=4294967295,gid=4294967295,");
        else if (i == 5)
            strcpy(expected + 56, "mode=7,");
        else if (i == 7)
            strcpy(expected, "kill_priv=1,kill_suid=1,kill_sgid=1");
        if (bpf_map_lookup_elem(map_fd, &key, &state) || !state.calls || state.failures ||
            state.attribute_length != lengths[i] ||
            memcmp(state.attributes, expected, sizeof(expected)))
        {
            fprintf(stderr, "FAIL: attribute formatter %s case\n", names[i]);
            goto cleanup_link;
        }
        printf("PASS: attribute formatter %s case\n", names[i]);
    }
    ret = 0;

cleanup_link:
    bpf_link__destroy(link);
cleanup_object:
    bpf_object__close(obj);
    return ret;
}

static int test_registration(const char *fixture)
{
    const char *programs[] = {"check_registration_kprobe", "check_registration_tracepoint",
                              "check_registration_raw_tracepoint"};
    int failed = 0;

    for (unsigned int i = 0; i < sizeof(programs) / sizeof(programs[0]); i++)
    {
        if (interrupted)
            return 1;
        struct bpf_object *obj = load_program(fixture, programs[i]);
        if (!obj)
        {
            fprintf(stderr, "FAIL: %s cannot call module kfuncs:\n%s\n", programs[i], verifier_log);
            failed = 1;
            continue;
        }
        printf("PASS: %s can call module kfuncs\n", programs[i]);
        bpf_object__close(obj);
    }
    return failed;
}

static int test_buffers(const char *fixture, const char *file_path)
{
    const char *rejected[] = {
        "reject_root", "reject_measurement", "reject_container", "reject_leaf",
        "reject_pcr", "reject_policy_hash", "reject_policy_config",
        "reject_policy_update", "reject_cgroup", "reject_path",
    };
    struct bpf_object *obj = load_program(fixture, "check_buffers");
    struct bpf_link *link;
    struct security_test_state state = {0};
    __u32 key = 0;
    int map_fd;
    int ret = 1;

    if (!obj)
    {
        fprintf(stderr, "Unable to load the valid buffer test:\n%s\n", verifier_log);
        return 1;
    }
    map_fd = bpf_object__find_map_fd_by_name(obj, "security_test_map");
    link = bpf_program__attach(bpf_object__find_program_by_name(obj, "check_buffers"));
    if (!link || libbpf_get_error(link))
        goto cleanup_object;

    for (unsigned int i = 0; i < 8; i++)
    {
        if (interrupted)
            goto cleanup_link;
        memset(&state, 0, sizeof(state));
        state.target_pid = getpid();
        strcpy(state.request.event_name, "test");
        strcpy(state.request.additional_data, "data");
        state.request.additional_data_len = 4;
        switch (i)
        {
        case 0: state.request.additional_data_len = UINT_MAX; break;
        case 1: state.request.additional_data_len = BPFIMA_EVENT_DATA_SIZE; break;
        case 2: memset(state.request.event_name, 'x', sizeof(state.request.event_name)); break;
        case 3: memset(state.request.namespace_id, 'x', sizeof(state.request.namespace_id)); break;
        case 4: memset(state.request.dependencies, 'x', sizeof(state.request.dependencies)); break;
        case 5: state.request.event_name[0] = '\0'; break;
        case 6: state.request.flags = UINT_MAX; break;
        case 7: state.request.additional_data_len = 0; break;
        }
        if (write_state(map_fd, &state))
            goto cleanup_link;
        int fd = open(file_path, O_RDONLY);
        if (fd < 0)
            goto cleanup_link;
        close(fd);
        if (bpf_map_lookup_elem(map_fd, &key, &state) || !state.calls || state.failures)
        {
            fprintf(stderr, "Runtime buffer case %u failed\n", i);
            goto cleanup_link;
        }
    }
    puts("PASS: runtime buffer and malformed request checks");
    ret = 0;

cleanup_link:
    bpf_link__destroy(link);
cleanup_object:
    bpf_object__close(obj);
    if (ret)
        return ret;

    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
    {
        if (interrupted)
            return 1;
        obj = load_rejected_program(fixture, rejected[i]);
        if (obj)
        {
            fprintf(stderr, "FAIL: verifier accepted %s\n", rejected[i]);
            bpf_object__close(obj);
            return 1;
        }
        if (!strstr(verifier_log, "invalid access") &&
            !strstr(verifier_log, "access beyond") &&
            !strstr(verifier_log, "memory size") &&
            !strstr(verifier_log, "invalid read from stack") &&
            !strstr(verifier_log, "invalid write to stack"))
        {
            fprintf(stderr, "Unexpected rejection for %s:\n%s\n", rejected[i], verifier_log);
            return 1;
        }
        printf("PASS: verifier rejects %s\n", rejected[i]);
    }

    obj = load_rejected_program(fixture, "reject_nonsleepable");
    if (obj)
    {
        fprintf(stderr, "FAIL: verifier accepted a sleepable kfunc in an atomic program\n");
        bpf_object__close(obj);
        return 1;
    }
    if (!strstr(verifier_log, "sleepable"))
    {
        fprintf(stderr, "Unexpected sleepability rejection:\n%s\n", verifier_log);
        return 1;
    }
    puts("PASS: verifier restricts the measurement kfunc to sleepable programs");
    return 0;
}

static int trigger_hook(unsigned int hook, const char *path, int file_fd,
                        const struct sockaddr_un *address, int map_fd,
                        bool expect_denial)
{
    struct security_test_state state = {0};
    int result = -1;
    int saved_errno;

    if (hook == 0)
    {
        pid_t child = fork();
        int status;
        if (child < 0)
            return 1;
        if (child == 0)
        {
            char *args[] = {"/bin/false", NULL};
            char *env[] = {NULL};
            state.target_pid = getpid();
            if (write_state(map_fd, &state))
                _exit(2);
            execve(args[0], args, env);
            _exit(expect_denial && errno == EACCES ? 0 : 2);
        }
        pid_t waited;
        do
        {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != child)
            return 1;
        return !WIFEXITED(status) || WEXITSTATUS(status) != (expect_denial ? 0 : 1);
    }

    state.target_pid = getpid();
    if (write_state(map_fd, &state))
        return 1;
    switch (hook)
    {
    case 1:
        result = open(path, O_RDONLY);
        saved_errno = errno;
        if (result >= 0)
            close(result);
        break;
    case 2:
        result = chmod(path, 0600);
        saved_errno = errno;
        break;
    case 3:
    {
        void *mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, file_fd, 0);
        saved_errno = errno;
        result = mapping == MAP_FAILED ? -1 : 0;
        if (mapping != MAP_FAILED)
            munmap(mapping, 4096);
        break;
    }
    case 4:
    {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return 1;
        result = connect(fd, (const struct sockaddr *)address, sizeof(*address));
        saved_errno = errno;
        close(fd);
        break;
    }
    default:
        return 1;
    }
    state.target_pid = 0;
    if (write_state(map_fd, &state))
        return 1;
    return expect_denial ? result >= 0 || saved_errno != EACCES : result < 0;
}

static int test_denials(const char *fixture, const char *build_dir,
                       const char *path, int file_fd, const struct sockaddr_un *address)
{
    const char *deny_names[] = {"deny_bprm", "deny_post_open", "deny_setattr", "deny_mmap", "deny_connect"};
    const char *objects[] = {"lsm_bprm_check_security", "lsm_file_post_open", "lsm_inode_setattr",
                            "lsm_mmap_file", "lsm_socket_connect"};
    int failed = 0;

    for (unsigned int i = 0; i < sizeof(objects) / sizeof(objects[0]); i++)
    {
        if (interrupted)
            return 1;
        struct bpf_object *gate = load_program(fixture, deny_names[i]);
        struct bpf_object *production = NULL;
        struct bpf_link *gate_link = NULL;
        struct bpf_link *production_link = NULL;
        struct security_test_state state = {0};
        char object_path[PATH_MAX];
        int map_fd;
        int ret = 1;

        if (!gate)
        {
            fprintf(stderr, "Unable to load %s:\n%s\n", deny_names[i], verifier_log);
            failed = 1;
            continue;
        }
        map_fd = bpf_object__find_map_fd_by_name(gate, "security_test_map");
        if (trigger_hook(i, path, file_fd, address, map_fd, false))
        {
            fprintf(stderr, "Baseline operation failed for %s\n", objects[i]);
            goto cleanup;
        }
        if (write_state(map_fd, &state))
            goto cleanup;
        gate_link = bpf_program__attach(bpf_object__find_program_by_name(gate, deny_names[i]));
        if (!gate_link || libbpf_get_error(gate_link))
        {
            gate_link = NULL;
            goto cleanup;
        }
        if (trigger_hook(i, path, file_fd, address, map_fd, true))
        {
            fprintf(stderr, "Denying control failed for %s\n", objects[i]);
            goto cleanup;
        }
        if (write_state(map_fd, &state))
            goto cleanup;
        snprintf(object_path, sizeof(object_path), "%s/%s.o", build_dir, objects[i]);
        production = load_program(object_path, NULL);
        if (!production)
        {
            fprintf(stderr, "Unable to load %s:\n%s\n", objects[i], verifier_log);
            goto cleanup;
        }
        production_link = bpf_program__attach(bpf_object__next_program(production, NULL));
        if (!production_link || libbpf_get_error(production_link))
        {
            production_link = NULL;
            goto cleanup;
        }
        if (trigger_hook(i, path, file_fd, address, map_fd, true))
        {
            fprintf(stderr, "FAIL: %s erased an earlier denial\n", objects[i]);
            goto cleanup;
        }
        printf("PASS: %s preserves an earlier denial\n", objects[i]);
        ret = 0;

cleanup:
        bpf_link__destroy(production_link);
        bpf_link__destroy(gate_link);
        bpf_object__close(production);
        bpf_object__close(gate);
        if (ret)
            failed = 1;
    }
    return failed;
}

int main(int argc, char **argv)
{
    char directory[PATH_MAX];
    char file_path[PATH_MAX];
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int file_fd = -1;
    int listener = -1;
    int ret = 1;
    const char *temporary_root = getenv("TMPDIR");
    struct sigaction action = {.sa_handler = handle_signal};

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 3 || geteuid() != 0 || access("/sys/kernel/btf/bpfima", R_OK))
    {
        fprintf(stderr, "Requires root and an already loaded bpfima module with BTF.\n");
        return 1;
    }
    if (bpfima_test_check_kfunc_abi())
        return 1;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    int written = snprintf(directory, sizeof(directory), "%s/bpfima-security-XXXXXX",
                           temporary_root ? temporary_root : "/tmp");
    if (written < 0 || (size_t)written >= sizeof(directory) || !mkdtemp(directory))
        return 1;
    written = snprintf(file_path, sizeof(file_path), "%s/file", directory);
    if (written < 0 || (size_t)written >= sizeof(file_path))
    {
        rmdir(directory);
        return 1;
    }
    written = snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory);
    if (written < 0 || (size_t)written >= sizeof(address.sun_path))
    {
        rmdir(directory);
        return 1;
    }
    file_fd = open(file_path, O_CREAT | O_RDWR, 0600);
    if (file_fd < 0 || ftruncate(file_fd, 8192))
        goto cleanup;
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 16))
        goto cleanup;

    ret = test_registration(argv[1]);
    if (!interrupted)
        ret |= test_buffers(argv[1], file_path);
    if (!interrupted)
        ret |= test_attributes(argv[1], file_path);
    if (!interrupted)
        ret |= test_denials(argv[1], argv[2], file_path, file_fd, &address);
    if (interrupted)
        ret = 1;

cleanup:
    if (listener >= 0)
        close(listener);
    if (file_fd >= 0)
        close(file_fd);
    unlink(address.sun_path);
    unlink(file_path);
    rmdir(directory);
    return ret;
}
