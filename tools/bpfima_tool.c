#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <yaml.h>

#include "include/bpfima_policy_user.h"
#include "yaml_parser.h"

/* Global state */
static volatile bool g_exiting = false;
static struct bpf_object *g_obj = NULL;
static struct bpf_link *g_link = NULL;

/* Map paths */
#define POLICY_MAP_PATH "/sys/fs/bpf/bpfima_policy_map"
#define CGROUP_PATTERNS_MAP_PATH "/sys/fs/bpf/bpfima_cgroup_patterns_map"
#define PATH_PATTERNS_MAP_PATH "/sys/fs/bpf/bpfima_path_patterns_map"
#define HOOK_CONFIG_MAP_PATH "/sys/fs/bpf/bpfima_hook_config_map"

/* PID file for daemon tracking */
#define PID_FILE "/var/run/bpfima.pid"

/**
 * @brief Signal handler for graceful shutdown
 */
static void sig_handler(int signo)
{
    g_exiting = true;
}

/**
 * @brief Write PID to file for tracking
 */
static int write_pid_file(void)
{
    FILE *fp = fopen(PID_FILE, "w");
    if (!fp) {
        fprintf(stderr, "Warning: Could not create PID file: %s\n", strerror(errno));
        return -1;
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return 0;
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
    FILE *fp = fopen(PID_FILE, "r");
    if (!fp)
        return -1;
    
    int pid = -1;
    if (fscanf(fp, "%d", &pid) != 1)
        pid = -1;
    
    fclose(fp);
    return pid;
}

/**
 * @brief Check if a process is running
 */
static bool is_process_running(int pid)
{
    return (kill(pid, 0) == 0);
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

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * @brief Load and attach eBPF program
 */
static int cmd_load(const char *filename, bool daemon_mode)
{
    struct bpf_program *prog;
    struct bpf_map *map;
    int err = 0;

    /* Check if already running */
    int pid = read_pid_file();
    if (pid > 0 && is_process_running(pid)) {
        fprintf(stderr, "Error: BPF IMA is already running (PID: %d)\n", pid);
        fprintf(stderr, "Run 'bpfima-tool unload' first\n");
        return 1;
    }

    if (set_rlimit() < 0)
        return 1;

    /* Check file exists */
    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Error: File not found: %s\n", filename);
        return 1;
    }

    printf("Loading BPF program: %s\n", filename);

    /* Open BPF object */
    g_obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(g_obj)) {
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        return 1;
    }

    /* Set pin path for maps */
    bpf_object__for_each_map(map, g_obj) {
        bpf_map__set_pin_path(map, NULL);
    }

    /* Set LSM programs as sleepable */
    bpf_object__for_each_program(prog, g_obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_LSM) {
            bpf_program__set_flags(prog, BPF_F_SLEEPABLE);
        }
    }

    /* Load BPF program */
    err = bpf_object__load(g_obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    /* Pin all maps */
    bpf_object__for_each_map(map, g_obj) {
        const char *map_name = bpf_map__name(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
        
        err = bpf_map__pin(map, pin_path);
        if (err && err != -EEXIST) {
            if (strstr(map_name, ".rodata") == NULL && 
                strstr(map_name, ".bss") == NULL &&
                strstr(map_name, ".data") == NULL) {
                fprintf(stderr, "Warning: Failed to pin map %s: %s\n", 
                        map_name, strerror(-err));
            }
        } else if (err != -EEXIST) {
            printf("✓ Pinned map: %s\n", map_name);
        }
    }

    /* Attach all programs */
    bpf_object__for_each_program(prog, g_obj) {
        g_link = bpf_program__attach(prog);
        if (libbpf_get_error(g_link)) {
            fprintf(stderr, "Failed to attach program %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            err = 1;
            goto cleanup;
        }
        printf("✓ Attached: %s\n", bpf_program__name(prog));
        break; /* Only attach first program */
    }

    if (!g_link) {
        fprintf(stderr, "Error: No programs attached\n");
        err = 1;
        goto cleanup;
    }

    printf("\n✓ BPF program loaded successfully\n");
    printf("\nNext steps:\n");
    printf("  1. Initialize policy: sudo bpfima-tool policy-init\n");
    printf("  2. View status: sudo bpfima-tool status\n");
    printf("  3. Check measurements: sudo cat /sys/kernel/security/bpfima/status\n");

    if (daemon_mode) {
        write_pid_file();
        printf("\nRunning in background (PID: %d)\n", getpid());
        printf("To stop: sudo bpfima-tool unload\n");

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);

        while (!g_exiting) {
            sleep(1);
        }

        printf("\nShutting down...\n");
    }

cleanup:
    if (err || !daemon_mode) {
        /* Unpin maps */
        if (g_obj) {
            bpf_object__for_each_map(map, g_obj) {
                const char *map_name = bpf_map__name(map);
                char pin_path[256];
                snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
                bpf_map__unpin(map, pin_path);
            }
        }

        if (g_link)
            bpf_link__destroy(g_link);
        if (g_obj)
            bpf_object__close(g_obj);
        
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
    
    if (pid < 0) {
        fprintf(stderr, "No running BPF IMA process found\n");
        return 1;
    }

    if (!is_process_running(pid)) {
        fprintf(stderr, "Stale PID file found (process %d not running)\n", pid);
        remove_pid_file();
        return 1;
    }

    printf("Stopping BPF IMA (PID: %d)...\n", pid);
    
    if (kill(pid, SIGTERM) < 0) {
        fprintf(stderr, "Failed to send signal: %s\n", strerror(errno));
        return 1;
    }

    /* Wait for process to exit */
    int attempts = 0;
    while (is_process_running(pid) && attempts < 10) {
        usleep(100000); /* 100ms */
        attempts++;
    }

    if (is_process_running(pid)) {
        fprintf(stderr, "Process did not exit gracefully, forcing...\n");
        kill(pid, SIGKILL);
        sleep(1);
    }

    remove_pid_file();
    
    /* Clean up pinned maps */
    printf("Cleaning up pinned maps...\n");
    unlink(POLICY_MAP_PATH);
    unlink(CGROUP_PATTERNS_MAP_PATH);
    unlink(PATH_PATTERNS_MAP_PATH);
    unlink(HOOK_CONFIG_MAP_PATH);
    
    printf("✓ BPF IMA unloaded successfully\n");
    return 0;
}

/**
 * @brief Initialize policy maps with default values
 */
static int cmd_policy_init(void)
{
    int policy_fd, cgroup_fd, path_fd, hook_fd;
    int ret = 0;
    u32 key;

    printf("Initializing policy maps with defaults...\n");

    /* Open maps */
    policy_fd = bpf_obj_get(POLICY_MAP_PATH);
    if (policy_fd < 0) {
        fprintf(stderr, "Failed to open policy map: %s\n", strerror(errno));
        fprintf(stderr, "Did you load the BPF program first?\n");
        return 1;
    }

    cgroup_fd = bpf_obj_get(CGROUP_PATTERNS_MAP_PATH);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup patterns map: %s\n", strerror(errno));
        close(policy_fd);
        return 1;
    }

    path_fd = bpf_obj_get(PATH_PATTERNS_MAP_PATH);
    if (path_fd < 0) {
        fprintf(stderr, "Failed to open path patterns map: %s\n", strerror(errno));
        close(policy_fd);
        close(cgroup_fd);
        return 1;
    }

    hook_fd = bpf_obj_get(HOOK_CONFIG_MAP_PATH);
    if (hook_fd < 0) {
        fprintf(stderr, "Failed to open hook config map: %s\n", strerror(errno));
        close(policy_fd);
        close(cgroup_fd);
        close(path_fd);
        return 1;
    }

    /* Main policy */
    struct bpfima_policy_config policy = {
        .enabled = 1,
        .filter_flags = 0,
        .action_flags = POLICY_ACTION_EXTEND_TPM |
                        POLICY_ACTION_LOG_SECURITYFS |
                        POLICY_ACTION_LOG_KERNEL |
                        POLICY_ACTION_TRACK_CONTAINER |
                        POLICY_ACTION_BUILD_DEPS,
        .min_file_size = 0,
        .max_path_depth = 32,
        .log_level = 2,
    };

    key = 0;
    ret = bpf_map_update_elem(policy_fd, &key, &policy, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to update policy map: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("✓ Main policy configuration\n");

    /* Cgroup patterns */
    const char *cgroup_patterns[] = {"/", "init.scope"};
    for (int i = 0; i < 2; i++) {
        struct bpfima_pattern_entry pattern = {0};
        strncpy(pattern.pattern, cgroup_patterns[i], MAX_PATTERN_LEN - 1);
        pattern.enabled = 1;
        pattern.match_type = 0;

        key = i;
        ret = bpf_map_update_elem(cgroup_fd, &key, &pattern, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Failed to update cgroup pattern: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    
    /* Clear remaining cgroup slots */
    struct bpfima_pattern_entry empty = {0};
    for (int i = 2; i < MAX_IGNORE_PATTERNS; i++) {
        key = i;
        bpf_map_update_elem(cgroup_fd, &key, &empty, BPF_ANY);
    }
    printf("✓ Cgroup patterns (2 patterns)\n");

    /* Path patterns */
    const char *path_patterns[] = {"/proc/", "/sys/"};
    for (int i = 0; i < 2; i++) {
        struct bpfima_pattern_entry pattern = {0};
        strncpy(pattern.pattern, path_patterns[i], MAX_PATTERN_LEN - 1);
        pattern.enabled = 1;
        pattern.match_type = 1; /* prefix */

        key = i;
        ret = bpf_map_update_elem(path_fd, &key, &pattern, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Failed to update path pattern: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    
    /* Clear remaining path slots */
    for (int i = 2; i < MAX_PATH_FILTERS; i++) {
        key = i;
        bpf_map_update_elem(path_fd, &key, &empty, BPF_ANY);
    }
    printf("✓ Path patterns (2 patterns)\n");

    /* Hook configurations */
    for (int i = 0; i < HOOK_MAX; i++) {
        struct bpfima_hook_config hook_cfg = {
            .flags = HOOK_FLAG_ENABLED | HOOK_FLAG_TRACK_CONTAINERS | HOOK_FLAG_MEASURE_HASH,
            .filter_override = 0,
            .action_override = 0,
        };

        /* Disable socket and kprobe hooks by default */
        if (i == HOOK_LSM_SOCKET_CONNECT || i == HOOK_KPROBE_FILE_OPEN) {
            hook_cfg.flags = 0;
        }

        key = i;
        ret = bpf_map_update_elem(hook_fd, &key, &hook_cfg, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Failed to update hook config: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    printf("✓ Hook configurations (%d hooks)\n", HOOK_MAX);

    printf("\n✓ Policy initialized successfully!\n");
    printf("\nPolicy summary:\n");
    printf("  - Enabled: Yes\n");
    printf("  - Filter flags: 0x%x (no filtering)\n", policy.filter_flags);
    printf("  - Action flags: 0x%x (TPM, logging, containers, deps)\n", policy.action_flags);
    printf("  - Log level: %u (Info)\n", policy.log_level);
    printf("\nTo customize policy, edit config/policy.yaml and run:\n");
    printf("  sudo bpfima-tool policy-update config/policy.yaml\n");

cleanup:
    close(policy_fd);
    close(cgroup_fd);
    close(path_fd);
    close(hook_fd);
    return ret;
}

/**
 * @brief Parse YAML policy file and update maps
 */
static int cmd_policy_update(const char *config_file)
{
    struct yaml_policy policy;
    char cgroup_filters[MAX_CGROUP_PATTERNS][256];
    char path_filters[MAX_PATH_PATTERNS][256];
    struct yaml_hook_config hook_configs[MAX_HOOK_CONFIGS];
    int ret = 1;

    printf("Loading policy from '%s'...\n", config_file);

    /* Parse the YAML file */
    if (parse_yaml_policy(config_file, &policy,
                         cgroup_filters, MAX_CGROUP_PATTERNS,
                         path_filters, MAX_PATH_PATTERNS,
                         hook_configs, MAX_HOOK_CONFIGS) < 0) {
        fprintf(stderr, "Error: Failed to parse YAML policy file\n");
        return 1;
    }

    /* Open the BPF maps */
    int policy_fd = bpf_obj_get(POLICY_MAP_PATH);
    if (policy_fd < 0) {
        fprintf(stderr, "Error: Cannot open policy map at %s: %s\n",
                POLICY_MAP_PATH, strerror(errno));
        fprintf(stderr, "Is the BPF IMA module loaded? Try 'bpfima-tool load' first\n");
        return 1;
    }

    int cgroup_fd = bpf_obj_get(CGROUP_PATTERNS_MAP_PATH);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Error: Cannot open cgroup patterns map: %s\n", strerror(errno));
        close(policy_fd);
        return 1;
    }

    int path_fd = bpf_obj_get(PATH_PATTERNS_MAP_PATH);
    if (path_fd < 0) {
        fprintf(stderr, "Error: Cannot open path patterns map: %s\n", strerror(errno));
        close(policy_fd);
        close(cgroup_fd);
        return 1;
    }

    int hook_fd = bpf_obj_get(HOOK_CONFIG_MAP_PATH);
    if (hook_fd < 0) {
        fprintf(stderr, "Error: Cannot open hook config map: %s\n", strerror(errno));
        close(policy_fd);
        close(cgroup_fd);
        close(path_fd);
        return 1;
    }

    /* Update the maps with parsed data */
    printf("\nUpdating BPF maps...\n");
    if (update_maps_from_policy(policy_fd, cgroup_fd, path_fd, hook_fd,
                                &policy,
                                cgroup_filters, MAX_CGROUP_PATTERNS,
                                path_filters, MAX_PATH_PATTERNS,
                                hook_configs, MAX_HOOK_CONFIGS) < 0) {
        fprintf(stderr, "Error: Failed to update BPF maps\n");
        goto cleanup;
    }

    printf("\n✓ Policy successfully updated from '%s'\n", config_file);
    ret = 0;

cleanup:
    close(policy_fd);
    close(cgroup_fd);
    close(path_fd);
    close(hook_fd);
    return ret;
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
    if (pid > 0 && is_process_running(pid)) {
        printf("Status: Running (PID: %d)\n", pid);
    } else {
        printf("Status: Not running\n");
        if (pid > 0) {
            printf("  (Stale PID file found)\n");
        }
    }

    /* Check maps */
    printf("\nBPF Maps:\n");
    const char *maps[] = {
        POLICY_MAP_PATH,
        CGROUP_PATTERNS_MAP_PATH,
        PATH_PATTERNS_MAP_PATH,
        HOOK_CONFIG_MAP_PATH
    };

    for (int i = 0; i < 4; i++) {
        int fd = bpf_obj_get(maps[i]);
        if (fd >= 0) {
            printf("  ✓ %s\n", strrchr(maps[i], '/') + 1);
            close(fd);
        } else {
            printf("  ✗ %s (not found)\n", strrchr(maps[i], '/') + 1);
        }
    }

    /* Check securityfs */
    printf("\nSecurityFS:\n");
    struct stat st;
    if (stat("/sys/kernel/security/bpfima", &st) == 0) {
        printf("  ✓ /sys/kernel/security/bpfima/\n");
    } else {
        printf("  ✗ /sys/kernel/security/bpfima/ (module not loaded)\n");
    }

    /* Check kernel module */
    printf("\nKernel Module:\n");
    FILE *fp = fopen("/proc/modules", "r");
    bool found = false;
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "bpfima ", 7) == 0) {
                printf("  ✓ bpfima module loaded\n");
                found = true;
                break;
            }
        }
        fclose(fp);
    }
    if (!found) {
        printf("  ✗ bpfima module not loaded\n");
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
    printf("  load <bpf_obj> [-d]  Load and attach eBPF program\n");
    printf("                       -d: Run as daemon (background)\n");
    printf("  unload               Unload currently running program\n");
    printf("  policy-init          Initialize policy maps with defaults\n");
    printf("  policy-update <file> Update policy from YAML configuration file\n");
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
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    /* Check root for most commands */
    if (strcmp(cmd, "help") != 0 && strcmp(cmd, "--help") != 0 && 
        strcmp(cmd, "-h") != 0 && geteuid() != 0) {
        fprintf(stderr, "Error: Must run as root\n");
        return 1;
    }

    if (strcmp(cmd, "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing BPF object file\n");
            usage(argv[0]);
            return 1;
        }
        bool daemon = (argc > 3 && strcmp(argv[3], "-d") == 0);
        return cmd_load(argv[2], daemon);
    }
    else if (strcmp(cmd, "unload") == 0) {
        return cmd_unload();
    }
    else if (strcmp(cmd, "policy-init") == 0) {
        return cmd_policy_init();
    }
    else if (strcmp(cmd, "policy-update") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing config file\n");
            usage(argv[0]);
            return 1;
        }
        return cmd_policy_update(argv[2]);
    }
    else if (strcmp(cmd, "status") == 0) {
        return cmd_status();
    }
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || 
             strcmp(cmd, "-h") == 0) {
        usage(argv[0]);
        return 0;
    }
    else {
        fprintf(stderr, "Error: Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
