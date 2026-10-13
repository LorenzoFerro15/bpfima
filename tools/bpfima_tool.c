#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <yaml.h>
#include <fcntl.h>
#include <limits.h>

#include "include/bpfima_policy_user.h"
#include "include/bpfima_policy_defaults.h"
#include "yaml_parser.h"

/* Global state */
static volatile bool g_exiting = false;

#define NUMBER_HOOKS 8
#define MAX_LOADED_OBJECTS 8
#define MAX_ATTACHED_LINKS 8

static struct bpf_object *g_objs[MAX_LOADED_OBJECTS];
static int g_obj_count = 0;

static struct bpf_link *g_links[MAX_ATTACHED_LINKS];
static int g_link_count = 0;

/* Map paths */
#define POLICY_MAP_PATH "/sys/fs/bpf/bpfima_policy_map"

#ifndef BPF_MAP_DIR
#define BPF_MAP_DIR "/sys/fs/bpf"
#endif
#ifndef BPF_PIN_DIR
#define BPF_PIN_DIR "/sys/fs/bpf/bpfima"
#endif

/* PID file for daemon tracking */
#ifndef PID_FILE
#define PID_FILE "/var/run/bpfima.pid"
#endif

/**
 * @brief Signal handler for graceful shutdown
 */
static void sig_handler(int signo)
{
    g_exiting = true;
}

/**
 * @brief Daemonize the process
 */
static int daemonize(void)
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        return -1;

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        return -1;

    /* Catch, ignore and handle signals */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        return -1;

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(077);

    /* Close all open file descriptors */
    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect stdin/stdout/stderr to /dev/null
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);

    return 0;
}

/**
 * @brief Write PID to file for tracking
 */
static int write_pid_file(void)
{
    struct stat st;
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        st.st_nlink != 1 || fchmod(fd, 0600) || ftruncate(fd, 0)) {
        close(fd);
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return -1;
    }
    int ret = fprintf(fp, "%d\n", getpid()) < 0 ? -1 : 0;
    if (fclose(fp))
        ret = -1;
    return ret;
}

/**
 * @brief Remove PID file
 */
static void remove_pid_file(void)
{
    unlink(PID_FILE);
}

/**
 * @brief Read PID from file
 */
static int read_pid_file(void)
{
    struct stat st;
    int fd = open(PID_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 022) || st.st_nlink != 1) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    char text[64];
    char *end;
    long pid = -1;
    if (fgets(text, sizeof(text), fp)) {
        errno = 0;
        pid = strtol(text, &end, 10);
        if (*end == '\n')
            end++;
        if (errno || *end || pid <= 1 || pid > INT_MAX)
            pid = -1;
    }
    fclose(fp);
    if (pid < 0)
        errno = EINVAL;
    return (int)pid;
}



/**
 * @brief Check if a process is running
 */
static bool is_process_running(int pid)
{
    return (kill(pid, 0) == 0);
}

/**
 * @brief Open all BPF policy maps
 * @param policy_fd: Pointer to store policy map FD
 * @param cgroup_fd: Pointer to store cgroup patterns map FD
 * @param path_fd: Pointer to store path patterns map FD
 * @param hook_fd: Pointer to store hook config map FD
 * @return 0 on success, -1 on failure
 *
 * Opens all policy-related BPF maps and stores their file descriptors.
 * On error, closes any successfully opened maps and returns -1.
 */
static bool is_policy_map(const struct bpf_map *map)
{
    return bpf_map__type(map) == BPF_MAP_TYPE_ARRAY && bpf_map__key_size(map) == sizeof(__u32) &&
           bpf_map__value_size(map) == sizeof(struct bpfima_policy_state) &&
           bpf_map__max_entries(map) == BPFIMA_POLICY_MAP_ENTRIES &&
           bpf_map__map_flags(map) == BPFIMA_POLICY_MAP_FLAGS;
}

/* The module owns its authority for the epoch; hook cleanup must not orphan it. */
static bool preserve_policy_pin(const char *pin)
{
    struct bpf_map_info info = {0};
    __u32 size = sizeof(info), bound_id = 0;
    char path[PATH_MAX], line[256];
    const char *directory = getenv("BPFIMA_SECURITYFS_DIR");
    int fd = bpf_obj_get(pin);
    if (fd < 0)
        return false;
    int ret = bpf_map_get_info_by_fd(fd, &info, &size);
    close(fd);
    if (ret || info.value_size != sizeof(struct bpfima_policy_state) || info.map_flags != BPFIMA_POLICY_MAP_FLAGS)
        return false;
    snprintf(path, sizeof(path), "%s/status", directory ? directory : "/sys/kernel/security/bpfima");
    FILE *file = fopen(path, "r");
    if (!file)
        return false;
    while (fgets(line, sizeof(line), file))
        if (sscanf(line, "policy_map_id=%u", &bound_id) == 1)
            break;
    fclose(file);
    return bound_id && bound_id == info.id;
}

/* Bind one protected map before any hook becomes active. */
static int ensure_policy_map(void)
{
    char map_path[PATH_MAX];
    snprintf(map_path, sizeof(map_path), "%s/bpfima_policy_map", BPF_MAP_DIR);
    int fd = bpf_obj_get(map_path);
    struct bpf_map_info info = {0};
    __u32 size = sizeof(info);
    char path[PATH_MAX], text[32];
    const char *directory = getenv("BPFIMA_SECURITYFS_DIR");
    int endpoint, ret = -1, error;

    if (fd < 0 && errno == ENOENT) {
        LIBBPF_OPTS(bpf_map_create_opts, options, .map_flags = BPFIMA_POLICY_MAP_FLAGS);
        fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "bpfima_policy_m", sizeof(__u32),
                             sizeof(struct bpfima_policy_state), BPFIMA_POLICY_MAP_ENTRIES, &options);
        if (fd >= 0 && bpf_map_freeze(fd)) {
            int error = errno;
            close(fd);
            errno = error;
            return -1;
        }
        if (fd >= 0 && bpf_obj_pin(fd, map_path)) {
            int error = errno;
            close(fd);
            if (error != EEXIST)
                return -1;
            fd = bpf_obj_get(map_path);
        }
    }
    if (fd < 0)
        return -1;
    if (bpf_map_get_info_by_fd(fd, &info, &size) || info.type != BPF_MAP_TYPE_ARRAY ||
        info.key_size != sizeof(__u32) || info.value_size != sizeof(struct bpfima_policy_state) ||
        info.max_entries != BPFIMA_POLICY_MAP_ENTRIES || info.map_flags != BPFIMA_POLICY_MAP_FLAGS) {
        errno = EINVAL;
        fprintf(stderr, "Policy map ABI changed; unload old hooks/maps before loading this version.\n");
        goto cleanup;
    }
    snprintf(path, sizeof(path), "%s/policy_map", directory ? directory : "/sys/kernel/security/bpfima");
    endpoint = open(path, O_WRONLY | O_CLOEXEC);
    if (endpoint < 0)
        goto cleanup;
    int length = snprintf(text, sizeof(text), "%d\n", fd);
    ssize_t written = write(endpoint, text, length);
    if (written == length)
        ret = 0;
    error = written < 0 ? errno : EIO;
    close(endpoint);
    if (ret)
        errno = error;
cleanup:
    error = errno;
    if (fd >= 0)
        close(fd);
    if (ret) {
        fprintf(stderr, "Cannot bind the audited policy map: %s\n", strerror(error));
        if (error == ESTALE)
            fprintf(stderr, "The pinned policy map belongs to an earlier module epoch. Detach hooks with\n"
                            "bpfima-tool unload, remove the module, then run bpfima-tool unload again\n"
                            "before loading a fresh module and hooks.\n");
    }
    errno = error;
    return ret;
}

/**
 * @brief Increase RLIMIT_MEMLOCK for BPF
 */
static int set_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Helper to copy file content
 */
/*
 * Structure to track open file definitions for monitoring
 */
struct monitored_file {
    char src_path[512];
    char dst_path[512];
    int fd;
    bool active;
    struct monitored_file *next;
};

static struct monitored_file *g_monitored_files = NULL;

/*
 * Helper to get or create a monitored file entry
 */
static struct monitored_file *get_monitored_file(const char *src_path, const char *dst_path) {
    struct monitored_file *mf = g_monitored_files;
    while (mf) {
        if (strcmp(mf->src_path, src_path) == 0) {
            mf->active = true;
            return mf;
        }
        mf = mf->next;
    }

    // Create new entry
    mf = malloc(sizeof(struct monitored_file));
    if (!mf) return NULL;

    snprintf(mf->src_path, sizeof(mf->src_path), "%s", src_path);
    snprintf(mf->dst_path, sizeof(mf->dst_path), "%s", dst_path);
    mf->fd = -1;
    mf->active = true;
    mf->next = g_monitored_files;
    g_monitored_files = mf;

    return mf;
}

/*
 * Helper to append new content from source FD to destination file
 */
static void append_new_content(struct monitored_file *mf) {
    if (mf->fd < 0) {
        mf->fd = open(mf->src_path, O_RDONLY);
        if (mf->fd < 0) return; // File might not exist yet
    }

    char buffer[4096];
    ssize_t bytes;

    // Read from current position
    while ((bytes = read(mf->fd, buffer, sizeof(buffer))) > 0) {
        FILE *dst = fopen(mf->dst_path, "a");
        if (dst) {
            fwrite(buffer, 1, bytes, dst);
            fclose(dst);
        }
    }
}

/*
 * Dump all securityfs data to persistent files
 * This maintains persistent FDs to read only new data
 */
static void dump_securityfs_to_files(void) {
    struct stat st = {0};

    // Mark all existing entries as inactive for garbage collection
    struct monitored_file *cur = g_monitored_files;
    while (cur) {
        cur->active = false;
        cur = cur->next;
    }

    // Create root directory
    if (mkdir("build", 0755) && errno != EEXIST)
        return;
    if (mkdir("build/namespaces", 0755) && errno != EEXIST)
        return;
    if (stat("build/namespaces/root", &st) == -1) {
        mkdir("build/namespaces/root", 0755);
    }

    // Monitor global files
    struct monitored_file *mf;

    mf = get_monitored_file("/sys/kernel/security/bpfima/policy", "build/namespaces/root/policy");
    if (mf) append_new_content(mf);

    mf = get_monitored_file("/sys/kernel/security/bpfima/policy_changes", "build/namespaces/root/policy_changes");
    if (mf) append_new_content(mf);

    mf = get_monitored_file("/sys/kernel/security/bpfima/merkle_root_history", "build/namespaces/root/merkle_root_history");
    if (mf) append_new_content(mf);

    // Dump namespace-specific data
    DIR *dir = opendir("/sys/kernel/security/bpfima/namespaces");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char src_path[1024];
                char dst_dir[512];
                char dst_path[1024];

                snprintf(dst_dir, sizeof(dst_dir), "build/namespaces/%s", entry->d_name);
                if (stat(dst_dir, &st) == -1) {
                    mkdir(dst_dir, 0755);
                }

                snprintf(src_path, sizeof(src_path), "/sys/kernel/security/bpfima/namespaces/%s/measurements", entry->d_name);
                snprintf(dst_path, sizeof(dst_path), "%s/measurements", dst_dir);
                mf = get_monitored_file(src_path, dst_path);
                if (mf) append_new_content(mf);

                snprintf(src_path, sizeof(src_path), "/sys/kernel/security/bpfima/namespaces/%s/policy", entry->d_name);
                snprintf(dst_path, sizeof(dst_path), "%s/policy", dst_dir);
                mf = get_monitored_file(src_path, dst_path);
                if (mf) append_new_content(mf);

                snprintf(src_path, sizeof(src_path), "/sys/kernel/security/bpfima/namespaces/%s/policy_changes", entry->d_name);
                snprintf(dst_path, sizeof(dst_path), "%s/policy_changes", dst_dir);
                mf = get_monitored_file(src_path, dst_path);
                if (mf) append_new_content(mf);
            }
        }
        closedir(dir);
    }

    // Sweep phase: Prune files that no longer exist (e.g. terminated containers)
    struct monitored_file **pp = &g_monitored_files;
    while (*pp) {
        struct monitored_file *entry = *pp;
        if (!entry->active) {
            if (entry->fd >= 0) {
                close(entry->fd);
            }
            *pp = entry->next;
            free(entry);
        } else {
            pp = &entry->next;
        }
    }
}

/**
 * @brief Destroy all runtime state created by this process
 * (destroy links and close objects)
 */
static void destroy_runtime_state(void)
{
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i]) {
            bpf_link__destroy(g_links[i]);
            g_links[i] = NULL;
        }
    }
    g_link_count = 0;

    for (int i = 0; i < g_obj_count; i++) {
        if (g_objs[i]) {
            bpf_object__close(g_objs[i]);
            g_objs[i] = NULL;
        }
    }
    g_obj_count = 0;
}

/**
 * @brief Unpin maps created by the loaded objects.
 */
static void unpin_maps_from_loaded_objects(void)
{
    struct bpf_map *map;
    for (int i = 0; i < g_obj_count; i++) {
        if (!g_objs[i]) {
            continue;
        }
        bpf_object__for_each_map(map, g_objs[i]) {
            if (is_policy_map(map))
                continue;
            const char *map_name = bpf_map__name(map);
            char pin_path[256];
            snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
            bpf_map__unpin(map, pin_path);
        }
    }
}

/**
 * @brief Unpin links created by the loaded objects.
 */
static void unpin_links_from_loaded_objects(void)
{
    struct bpf_program *prog;
    for (int i = 0; i < g_obj_count; i++) {
        if (!g_objs[i]) {
            continue;
        }
        bpf_object__for_each_program(prog, g_objs[i]) {
            const char *prog_name = bpf_program__name(prog);
            char pin_path[256];
            snprintf(pin_path, sizeof(pin_path), "%s/%s", BPF_PIN_DIR, prog_name);
            if (access(pin_path, F_OK) == 0) {
                unlink(pin_path);
            }
        }
    }
}

static int remove_pin(const char *path)
{
    if (unlink(path) == 0 || errno == ENOENT)
        return 0;
    fprintf(stderr, "Failed to remove %s: %s\n", path, strerror(errno));
    return 1;
}

static int cleanup_pinned_links(void)
{
    int fd = open(BPF_PIN_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int ret = 0;
    DIR *dir;
    struct dirent *entry;

    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        fprintf(stderr, "Failed to open %s: %s\n", BPF_PIN_DIR, strerror(errno));
        return 1;
    }
    dir = fdopendir(fd);
    if (!dir) {
        fprintf(stderr, "Failed to read %s: %s\n", BPF_PIN_DIR, strerror(errno));
        close(fd);
        return 1;
    }
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (unlinkat(fd, entry->d_name, 0) && errno != ENOENT) {
            fprintf(stderr, "Failed to unpin %s/%s: %s\n", BPF_PIN_DIR,
                    entry->d_name, strerror(errno));
            ret = 1;
        }
        errno = 0;
    }
    if (errno) {
        fprintf(stderr, "Failed to read %s: %s\n", BPF_PIN_DIR, strerror(errno));
        ret = 1;
    }
    if (closedir(dir)) {
        fprintf(stderr, "Failed to close %s: %s\n", BPF_PIN_DIR, strerror(errno));
        ret = 1;
    }
    if (rmdir(BPF_PIN_DIR) && errno != ENOENT) {
        fprintf(stderr, "Failed to remove %s: %s\n", BPF_PIN_DIR, strerror(errno));
        ret = 1;
    }
    return ret;
}

static int cleanup_pinned_maps(void)
{
    const char *names[] = {"bpfima_policy_map", "bpfima_cgroup_patterns_map",
                           "bpfima_path_patterns_map", "bpfima_hook_config_map",
                           "bpf_timing_stats", "bpf_timing_stats_bprm",
                           "bpf_timing_stats_socket", "bpf_timing_stats_count", "scratch_buf_map"};
    int ret = 0;

    for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[512];
        int written = snprintf(path, sizeof(path), "%s/%s", BPF_MAP_DIR, names[i]);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            ret = 1;
            continue;
        }
        if (i == 0 && preserve_policy_pin(path)) {
            printf("Preserving the module epoch policy authority: %s\n", path);
            continue;
        }
        ret |= remove_pin(path);
    }
    return ret;
}

/**
 * @brief Load one object file, reuse pinned maps if they already exist,
 * then attach and pin every program contained in that object.
 */
static int load_and_attach_one_object(const char *filename)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct stat st;
    int err = 0;
    int attached_in_obj = 0;

    if (g_obj_count >= MAX_LOADED_OBJECTS) {
        fprintf(stderr, "Too many loaded objects (max %d)\n", MAX_LOADED_OBJECTS);
        return 1;
    }

    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Error: File not found: %s\n", filename);
        return 1;
    }

    printf("Loading BPF object: %s\n", filename);

    // Open the object
    obj = bpf_object__open_file(filename, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        return 1;
    }

    // Add immediately the new object
    // In case of errors, it will be closed by the cleanup function
    g_objs[g_obj_count++] = obj;

    /// Set the path attribute that tells where the BPF map should be pinned.
    bpf_object__for_each_map(map, obj) {
        bpf_map__set_pin_path(map, NULL);
    }

    // LSM programs must be marked sleepable.
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_LSM) {
            bpf_program__set_flags(prog, BPF_F_SLEEPABLE);
        }
    }

    // Verify if a map was already pinned
    bpf_object__for_each_map(map, obj) {
        // Skip maps automatically generated by libbpf
        if (bpf_map__is_internal(map)) {
            continue;
        }

        char path[256];
        if (!strcmp(bpf_map__name(map), "bpfima_policy_map")) {
            if (!is_policy_map(map)) {
                fprintf(stderr, "Hook has a legacy policy ABI; rebuild it before loading.\n");
                return 1;
            }
            snprintf(path, sizeof(path), "%s/bpfima_policy_map", BPF_MAP_DIR);
            int fd = bpf_obj_get(path);
            if (fd < 0)
                return 1;
            int result = bpf_map__reuse_fd(map, fd);
            close(fd);
            if (result)
                return 1;
            continue;
        }
        snprintf(path, sizeof(path), "/sys/fs/bpf/%s", bpf_map__name(map));

        if (access(path, F_OK) == 0) {
            // The map exists already: try to reuse the file descriptor
            int fd = bpf_obj_get(path);
            if (fd < 0) {
                fprintf(stderr, "Warning: cannot reuse map %s, recreating\n", bpf_map__name(map));
                unlink(path);
                continue;
            }

            err = bpf_map__reuse_fd(map, fd);
            if (err) {
                fprintf(stderr, "Warning: cannot reuse map %s: %s, recreating\n",
                        bpf_map__name(map), strerror(-err));
                close(fd);
                unlink(path);
                continue;
            }

            printf("  Reused pinned map: %s\n", bpf_map__name(map));
            close(fd);
        }
    }

    // Load the object into the kernel before attaching any programs.
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object %s: %s\n", filename, strerror(-err));
        return 1;
    }

    // Pin newly created maps so policy tools can update them later.
    bpf_object__for_each_map(map, obj) {
        // Skip maps automatically generated by libbpf
        if (bpf_map__is_internal(map) || is_policy_map(map)) {
            continue;
        }

        const char *map_name = bpf_map__name(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);

        // Do not try to pin an already pinned map, reuse the old fd
        if (access(pin_path, F_OK) == 0) {
            continue;
        }

        err = bpf_map__pin(map, pin_path);
        if (err && err != -EEXIST) {
            if (strstr(map_name, ".rodata") == NULL &&
                strstr(map_name, ".bss") == NULL &&
                strstr(map_name, ".data") == NULL) {
                fprintf(stderr, "Warning: failed pinning map %s: %s\n", map_name, strerror(-err));
            }
        } else if (err != -EEXIST) {
            printf("  Pinned map: %s\n", map_name);
        }
    }

    // Attach every program in this object and keep every link alive.
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "%s/%s", BPF_PIN_DIR, prog_name);

        // If the program was already pinned try to atomically substitute it with the new version
        if (access(pin_path, F_OK) == 0) {
            int existing_link_fd = bpf_obj_get(pin_path);
            if (existing_link_fd >= 0) {
                int new_prog_fd = bpf_program__fd(prog);

                // Atomically swap the program
                err = bpf_link_update(existing_link_fd, new_prog_fd, NULL);
                close(existing_link_fd);
                if (err == 0) {
                    printf("  Atomically updated: %s\n", prog_name);
                    attached_in_obj++;
                    continue;
                }
                // Something went wrong, unlink, reattach and link the program
                fprintf(stderr, "Atomic update failed for %s (%s). Falling back to fresh attach. \n",
                        prog_name, strerror(-err));
            } else {
                fprintf(stderr, "Failed to retrieve FD for pinned link %s. Falling back to fresh attach...\n",
                        prog_name);
            }
            unlink(pin_path);
        }

        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "Failed to attach program %s from %s: %s\n",
                    bpf_program__name(prog), filename, strerror(errno));
            return 1;
        }

        if (g_link_count >= MAX_ATTACHED_LINKS) {
            fprintf(stderr, "Too many attached links (max %d)\n", MAX_ATTACHED_LINKS);
            bpf_link__destroy(link);
            return 1;
        }

        // Pin the link so it persists after this process exits
        int err = bpf_link__pin(link, pin_path);
        if (err) {
            fprintf(stderr, "Warning: failed pinning link %s: %s\n", prog_name, strerror(-err));
        } else {
            printf("  Pinned link: %s\n", prog_name);
        }

        g_links[g_link_count++] = link;
        attached_in_obj++;
        printf("  Attached: %s\n", bpf_program__name(prog));
    }

    if (attached_in_obj == 0) {
        fprintf(stderr, "Error: no programs attached from %s\n", filename);
        return 1;
    }

    return 0;
}

static int ensure_single_instance(void) {
    int pid = read_pid_file();
    if (pid < 0 && (errno == EPERM || errno == ELOOP)) {
        fprintf(stderr, "Refusing unsafe PID file %s\n", PID_FILE);
        return -1;
    }
    if (pid > 0 && is_process_running(pid)) {
        fprintf(stderr, "Error: BPF IMA is already running (PID: %d)\n", pid);
        fprintf(stderr, "Run 'bpfima-tool unload' first\n");
        return -1;
    }
    return 0;
}

static int load_all_bpf_objects(const char **filenames, int file_count) {
    // Directory to which pin the eBPF programs
    if (mkdir(BPF_PIN_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: Failed to create %s: %s\n", BPF_PIN_DIR, strerror(errno));
        return -1;
    }

    for (int i = 0; i < file_count; i++) {
        if (load_and_attach_one_object(filenames[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int run_daemon_loop(void) {
    printf("\nStarting daemon...\n");
    fflush(NULL);
    if (daemonize() < 0) {
        fprintf(stderr, "Error: Failed to daemonize\n");
        return -1;
    }

    if (write_pid_file())
        return -1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!g_exiting) {
        sleep(1);
        dump_securityfs_to_files();
    }

    printf("\nShutting down...\n");
    dump_securityfs_to_files();
    return 0;
}

/**
 * @brief Load and attach a list of eBPF programs
 */
static int cmd_load(const char **filenames, int file_count, bool daemon_mode)
{
    int err = 0;

    if (ensure_single_instance() < 0)
        return 1;

    if (set_rlimit() < 0)
        return 1;

    if (ensure_policy_map() < 0 || load_all_bpf_objects(filenames, file_count) < 0) {
        err = 1;
        goto cleanup;
    }

    printf("\n  BPF program loaded successfully\n");
    printf("\nNext steps:\n");
    printf("  1. Initialize policy: sudo bpfima-tool policy-init\n");
    printf("  2. View status: sudo bpfima-tool status\n");
    printf("  3. Check measurements: sudo cat /sys/kernel/security/bpfima/status\n");

    if (daemon_mode) {
        if (run_daemon_loop() < 0) {
            err = 1;
            goto cleanup;
        }
    }

cleanup:
    {
        // The env variable is set in the manifest of the bpfima_tool container
        // to indicate that we are in a k8s environment
        bool persist_state = (getenv("BPFIMA_PERSIST_STATE") != NULL);

        if (persist_state && !err) {
            printf("Persisting pinned BPF links for atomic reload...\n");
        }
        else {
            unpin_maps_from_loaded_objects();
            unpin_links_from_loaded_objects();
        }
        destroy_runtime_state();
        remove_pid_file();
    }

    return err;
}

/**
 * @brief Unload currently running BPF program
 */
static int cmd_unload(void)
{
    int pid = read_pid_file();
    int ret = 0;

    if (pid < 0 && (errno == EPERM || errno == ELOOP)) {
        fprintf(stderr, "Refusing unsafe PID file %s\n", PID_FILE);
        return 1;
    }

    if (pid < 0 || !is_process_running(pid))
    {
        printf("No running BPF IMA daemon; cleaning up retained pins\n");
    }
    else
    {
        printf("Stopping BPF IMA (PID: %d)...\n", pid);

        if (kill(pid, SIGTERM) < 0 && errno != ESRCH)
        {
            fprintf(stderr, "Failed to send signal: %s\n", strerror(errno));
            return 1;
        }

        int attempts = 0;
        while (is_process_running(pid) && attempts < 10)
        {
            usleep(100000);
            attempts++;
        }

        if (is_process_running(pid))
        {
            fprintf(stderr, "Process did not exit gracefully, forcing...\n");
            if (kill(pid, SIGKILL) < 0 && errno != ESRCH) {
                fprintf(stderr, "Failed to stop process %d: %s\n", pid, strerror(errno));
                return 1;
            }
            for (int i = 0; i < 30 && is_process_running(pid); i++)
                usleep(100000);
            if (is_process_running(pid)) {
                fprintf(stderr, "Process %d still holds BPF handles\n", pid);
                return 1;
            }
        }
        // Final dump of securityfs data before cleanup
        printf("Performing final securityfs dump...\n");
        dump_securityfs_to_files();
    }

    printf("Cleaning up pinned maps and links...\n");
    ret |= cleanup_pinned_links();
    ret |= cleanup_pinned_maps();
    ret |= remove_pin(PID_FILE);

    if (!ret)
        printf("  BPF IMA unloaded successfully\n");
    return ret;
}

/**
 * @brief Initialize policy maps with default values
 */
static int cmd_policy_init(void)
{
    struct bpfima_policy_snapshot snapshot;
    int ret;

    if (ensure_policy_map())
        return 1;
    bpfima_init_default_snapshot(&snapshot);
    ret = apply_policy_snapshot(NULL, &snapshot);
    if (ret)
        fprintf(stderr, "Policy initialization failed: %s\n", strerror(-ret));
    return ret ? 1 : 0;
}

static int cmd_policy_update(const char *config_file, const char *namespace_id)
{
    struct yaml_policy policy;
    struct bpfima_policy_snapshot snapshot;
    char cgroups[MAX_CGROUP_PATTERNS][256], paths[MAX_PATH_PATTERNS][256];
    struct yaml_hook_config hooks[MAX_HOOK_CONFIGS];
    int ret;

    ret = parse_yaml_policy(config_file, &policy, cgroups, MAX_CGROUP_PATTERNS,
                            paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS);
    if (!ret)
        ret = build_policy_from_yaml(&snapshot, &policy, cgroups, MAX_CGROUP_PATTERNS,
                                      paths, MAX_PATH_PATTERNS, hooks, MAX_HOOK_CONFIGS);
    if (!ret && ensure_policy_map())
        return 1;
    if (!ret)
        ret = apply_policy_snapshot(namespace_id, &snapshot);
    if (ret)
        fprintf(stderr, "Policy update failed: %s\n", strerror(ret < 0 ? -ret : EINVAL));
    else
        printf("Policy configuration recorded and activated atomically.\n");
    return ret ? 1 : 0;
}

/**
 * @brief Show system status
 */
static int cmd_status(void)
{
    int pid = read_pid_file();

    printf("BPF IMA Status\n");
    printf("==============\n\n");

    /* Check if running */
    if (pid > 0 && is_process_running(pid))
    {
        printf("Status: Running (PID: %d)\n", pid);
    }
    else
    {
        printf("Status: Not running\n");
        if (pid > 0)
        {
            printf("  (Stale PID file found)\n");
        }
    }

    printf("\nBPF Maps:\n");
    const char *maps[] = {
        POLICY_MAP_PATH};

    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++)
    {
        int fd = bpf_obj_get(maps[i]);
        if (fd >= 0)
        {
            printf("    %s\n", strrchr(maps[i], '/') + 1);
            close(fd);
        }
        else
        {
            printf("     %s (not found)\n", strrchr(maps[i], '/') + 1);
        }
    }

    printf("\nSecurityFS:\n");
    struct stat st;
    if (stat("/sys/kernel/security/bpfima", &st) == 0)
    {
        printf("    /sys/kernel/security/bpfima/\n");
    }
    else
    {
        printf("     /sys/kernel/security/bpfima/ (module not loaded)\n");
    }

    printf("\nKernel Module:\n");
    FILE *fp = fopen("/proc/modules", "r");
    bool found = false;
    if (fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, "bpfima ", 7) == 0)
            {
                printf("    bpfima module loaded\n");
                found = true;
                break;
            }
        }
        fclose(fp);
    }
    if (!found)
    {
        printf("     bpfima module not loaded\n");
        printf("    Run: sudo insmod build/bpfima.ko\n");
    }

    return 0;
}

/**
 * @brief Show usage information
 */
static void usage(const char *prog)
{
    printf("BPF IMA Management Tool\n");
    printf("=======================\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  load <bpf_obj>... [-d]  Load and attach eBPF program\n");
    printf("                       -d: Run as daemon (background)\n");
    printf("  unload               Unload currently running program\n");
    printf("  policy-init          Initialize policy maps with defaults\n");
    printf("  policy-update <file> [namespace] Apply a complete audited policy\n");
    printf("  status               Show system status\n");
    printf("  help                 Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s load build/lsm_bprm_check_security.o -d\n", prog);
    printf("  %s policy-init\n", prog);
    printf("  %s policy-update config/policy.yaml\n", prog);
    printf("  %s status\n", prog);
    printf("  %s unload\n\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") != 0 && strcmp(cmd, "--help") != 0 &&
        strcmp(cmd, "-h") != 0 && geteuid() != 0)
    {
        fprintf(stderr, "Error: Must run as root\n");
        return 1;
    }

    if (strcmp(cmd, "load") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing BPF object file\n");
            usage(argv[0]);
            return 1;
        }

        const char *files[NUMBER_HOOKS];
        int file_count = 0;
        bool daemon = false;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0) {
                daemon = true;
                continue;
            }

            if (file_count >= NUMBER_HOOKS) {
                fprintf(stderr, "Error: the number of object files is higher than the number of hooks supported (max %d)\n", NUMBER_HOOKS);
                return 1;
            }

            files[file_count++] = argv[i];
        }

        if (file_count == 0) {
            fprintf(stderr, "Error: Missing BPF object file(s)\n");
            usage(argv[0]);
            return 1;
        }

        return cmd_load(files, file_count, daemon);
    }
    else if (strcmp(cmd, "unload") == 0)
    {
        return cmd_unload();
    }
    else if (strcmp(cmd, "policy-init") == 0)
    {
        return cmd_policy_init();
    }
    else if (strcmp(cmd, "policy-update") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing config file\n");
            usage(argv[0]);
            return 1;
        }
        return cmd_policy_update(argv[2], argc > 3 ? argv[3] : NULL);
    }
    else if (strcmp(cmd, "status") == 0)
    {
        return cmd_status();
    }
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
             strcmp(cmd, "-h") == 0)
    {
        usage(argv[0]);
        return 0;
    }
    else
    {
        fprintf(stderr, "Error: Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
