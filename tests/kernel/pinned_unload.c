#include <limits.h>

static char test_map_dir[128];
static char test_pin_dir[128];
static char test_pid_file[128];

/* Exercise the production unload path using only this test's private paths. */
#define BPF_MAP_DIR test_map_dir
#define BPF_PIN_DIR test_pin_dir
#define PID_FILE test_pid_file
#define main bpfima_tool_main
#include "../../tools/bpfima_tool.c"
#undef main

static char verifier_log[1024 * 1024];

static int test_pid_file_security(void)
{
    struct stat st;
    mode_t previous_mask = umask(0);
    int ret = 1;
    char target[256];

    snprintf(target, sizeof(target), "%s-target", test_pid_file);
    if (write_pid_file() || stat(test_pid_file, &st) || (st.st_mode & 0777) != 0600 ||
        read_pid_file() != getpid())
        goto cleanup;
    if (chmod(test_pid_file, 0666) || read_pid_file() >= 0 || errno != EPERM || cmd_unload() == 0)
        goto cleanup;
    if (write_pid_file() || stat(test_pid_file, &st) || (st.st_mode & 0777) != 0600)
        goto cleanup;
    unlink(test_pid_file);
    int fd = open(target, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0)
        goto cleanup;
    close(fd);
    if (symlink(target, test_pid_file) || write_pid_file() == 0 ||
        read_pid_file() >= 0 || errno != ELOOP || cmd_unload() == 0)
        goto cleanup;
    ret = 0;
    puts("PASS: PID files are private, unsafe modes are rejected, and symlinks are not followed");

cleanup:
    umask(previous_mask);
    unlink(test_pid_file);
    unlink(target);
    return ret;
}

static int create_fixture(const char *fixture, __u32 *program_id)
{
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    char path[PATH_MAX];
    int ret = 1;
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf = verifier_log,
        .kernel_log_size = sizeof(verifier_log),
        .kernel_log_level = 1);

    *program_id = 0;
    if (mkdir(test_pin_dir, 0700))
        return 1;
    if (!fixture) {
        const char *names[] = {"test_link", "test_program"};
        for (unsigned int i = 0; i < 2; i++) {
            snprintf(path, sizeof(path), "%s/%s", test_pin_dir, names[i]);
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
            if (fd < 0)
                return 1;
            close(fd);
        }
        snprintf(path, sizeof(path), "%s/bpfima_policy_map", test_map_dir);
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0)
            return 1;
        close(fd);
        snprintf(path, sizeof(path), "%s/scratch_buf_map", test_map_dir);
        fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0)
            return 1;
        close(fd);
        return 0;
    }

    verifier_log[0] = '\0';
    obj = bpf_object__open_file(fixture, &opts);
    if (!obj || libbpf_get_error(obj)) {
        obj = NULL;
        goto cleanup;
    }
    bpf_object__for_each_map(map, obj)
        bpf_map__set_pin_path(map, NULL);
    if (bpf_object__load(obj)) {
        fprintf(stderr, "FAIL: load pinned fixture:\n%s\n", verifier_log);
        goto cleanup;
    }
    prog = bpf_object__find_program_by_name(obj, "module_interactions");
    if (!prog)
        goto cleanup;
    struct bpf_prog_info info = {0};
    __u32 info_size = sizeof(info);
    if (bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_size))
        goto cleanup;
    *program_id = info.id;
    link = bpf_program__attach(prog);
    if (!link || libbpf_get_error(link)) {
        link = NULL;
        goto cleanup;
    }
    snprintf(path, sizeof(path), "%s/test_link", test_pin_dir);
    if (bpf_link__pin(link, path))
        goto cleanup;
    snprintf(path, sizeof(path), "%s/test_program", test_pin_dir);
    if (bpf_obj_pin(bpf_program__fd(prog), path))
        goto cleanup;
    snprintf(path, sizeof(path), "%s/bpfima_policy_map", test_map_dir);
    if (bpf_obj_pin(bpf_object__find_map_fd_by_name(obj, "module_test_map"), path))
        goto cleanup;
    snprintf(path, sizeof(path), "%s/scratch_buf_map", test_map_dir);
    if (bpf_obj_pin(bpf_object__find_map_fd_by_name(obj, "module_test_map"), path))
        goto cleanup;
    ret = 0;

cleanup:
    /* Pins must retain the program after every original userspace handle closes. */
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return ret;
}

static int test_unload(const char *fixture, const char *pid_text, const char *name)
{
    __u32 program_id;
    char path[PATH_MAX];

    if (create_fixture(fixture, &program_id)) {
        fprintf(stderr, "FAIL: create pinned fixture for %s\n", name);
        return 1;
    }
    if (pid_text) {
        FILE *file = fopen(test_pid_file, "w");
        if (!file)
            return 1;
        fputs(pid_text, file);
        fclose(file);
    }
    if (fixture) {
        int fd = bpf_prog_get_fd_by_id(program_id);
        if (fd < 0) {
            fprintf(stderr, "FAIL: pins did not retain the kfunc-calling program\n");
            return 1;
        }
        close(fd);
    }
    if (cmd_unload() || access(test_pin_dir, F_OK) == 0 || access(test_pid_file, F_OK) == 0) {
        fprintf(stderr, "FAIL: unload did not remove links/PID file for %s\n", name);
        return 1;
    }
    snprintf(path, sizeof(path), "%s/bpfima_policy_map", test_map_dir);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "FAIL: unload left a map pin for %s\n", name);
        return 1;
    }
    snprintf(path, sizeof(path), "%s/scratch_buf_map", test_map_dir);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "FAIL: unload left a scratch map pin for %s\n", name);
        return 1;
    }
    if (fixture) {
        bool released = false;
        for (int i = 0; i < 100 && !g_exiting; i++) {
            int fd = bpf_prog_get_fd_by_id(program_id);
            if (fd < 0) {
                released = errno == ENOENT;
                break;
            }
            close(fd);
            usleep(100000);
        }
        if (!released) {
            fprintf(stderr, "FAIL: program %u still holds its module kfunc reference\n", program_id);
            return 1;
        }
    }
    printf("PASS: pinned unload with %s\n", name);
    return 0;
}

int main(int argc, char **argv)
{
    const char *fixture = NULL;
    char root[96];
    char pid_root[96];
    char blocked[PATH_MAX] = {0};
    bool blocked_created = false;
    bool pid_root_created = false;
    int ret = 1;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2 || argc > 3 || (argc == 3 && !strcmp(argv[1], "--filesystem"))) {
        fprintf(stderr, "Usage: %s <module-interactions.bpf.o|--filesystem> [private-bpffs-directory]\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "--filesystem")) {
        strcpy(root, "/tmp/bpfima-unload-XXXXXX");
        if (!mkdtemp(root))
            return 1;
    } else {
        if (geteuid() || access("/sys/kernel/btf/bpfima", R_OK)) {
            fprintf(stderr, "Requires root and bpfima module BTF\n");
            return 2;
        }
        fixture = argv[1];
        int written;
        if (argc == 3)
            written = snprintf(root, sizeof(root), "%s/fixture", argv[2]);
        else
            written = snprintf(root, sizeof(root), "/sys/fs/bpf/bpfima-unload-test-%d", getpid());
        if (written < 0 || (size_t)written >= sizeof(root))
            return 2;
        if (mkdir(root, 0700))
            return 1;
    }
    snprintf(test_map_dir, sizeof(test_map_dir), "%s/maps", root);
    snprintf(test_pin_dir, sizeof(test_pin_dir), "%s/links", root);
    /* PID files use an ordinary filesystem, while BPF pins require bpffs. */
    const char *tmpdir = getenv("TMPDIR");
    int written = snprintf(pid_root, sizeof(pid_root), "%s/bpfima-unload-pid-XXXXXX",
                           tmpdir ? tmpdir : "/tmp");
    if (written < 0 || (size_t)written >= sizeof(pid_root))
        goto cleanup;
    if (!mkdtemp(pid_root))
        goto cleanup;
    pid_root_created = true;
    snprintf(test_pid_file, sizeof(test_pid_file), "%s/daemon.pid", pid_root);
    if (mkdir(test_map_dir, 0700))
        goto cleanup;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    if (test_pid_file_security())
        goto cleanup;
    setenv("BPFIMA_PERSIST_STATE", "1", 1);
    if (kill(INT_MAX, 0) == 0 || errno != ESRCH)
        goto cleanup;
    if (test_unload(fixture, NULL, "missing PID file") ||
        test_unload(fixture, "2147483647\n", "stale PID file") ||
        test_unload(fixture, "0\n", "zero PID") ||
        test_unload(fixture, "1\n", "init PID") ||
        test_unload(fixture, "not-a-pid\n", "malformed PID file") || cmd_unload() || g_exiting)
        goto cleanup;
    puts("PASS: explicit unload is idempotent and overrides persistence mode");

    if (mkdir(test_pin_dir, 0700))
        goto cleanup;
    snprintf(blocked, sizeof(blocked), "%s/nested", test_pin_dir);
    if (mkdir(blocked, 0700))
        goto cleanup;
    blocked_created = true;
    if (cmd_unload() == 0 || access(blocked, F_OK))
        goto cleanup;
    if (rmdir(blocked))
        goto cleanup;
    blocked_created = false;
    puts("PASS: failed pin removal is reported and nested directories are preserved");
    ret = 0;

cleanup:
    if (blocked_created)
        rmdir(blocked);
    cleanup_pinned_links();
    cleanup_pinned_maps();
    unlink(test_pid_file);
    rmdir(test_map_dir);
    rmdir(root);
    if (pid_root_created)
        rmdir(pid_root);
    return ret;
}
