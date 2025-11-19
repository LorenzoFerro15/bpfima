// SPDX-License-Identifier: GPL-2.0
/*
 * BPF Policy Map Initializer
 * 
 * This tool initializes the pinned BPF policy maps with default values.
 * Run this after loading the BPF programs to enable proper policy enforcement.
 * 
 * Usage: ./policy_init
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Define types compatible with kernel types */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

/* Policy constants - must match bpfima_policy.h */
#define MAX_IGNORE_PATTERNS 32
#define MAX_PATTERN_LEN 64
#define MAX_PATH_FILTERS 64

/* Policy filter flags */
#define POLICY_FILTER_SYSTEM_CGROUPS    (1 << 0)
#define POLICY_FILTER_PROC_SYS          (1 << 1)
#define POLICY_FILTER_DEV               (1 << 2)
#define POLICY_FILTER_READONLY_FILES    (1 << 3)
#define POLICY_FILTER_SMALL_FILES       (1 << 4)
#define POLICY_FILTER_NON_EXECUTABLE    (1 << 5)
#define POLICY_FILTER_LIBRARIES         (1 << 6)
#define POLICY_FILTER_TMP_FILES         (1 << 7)

/* Policy action flags */
#define POLICY_ACTION_EXTEND_TPM        (1 << 0)
#define POLICY_ACTION_LOG_SECURITYFS    (1 << 1)
#define POLICY_ACTION_LOG_KERNEL        (1 << 2)
#define POLICY_ACTION_ALERT_SUSPICIOUS  (1 << 3)
#define POLICY_ACTION_BLOCK             (1 << 4)
#define POLICY_ACTION_TRACK_CONTAINER   (1 << 5)
#define POLICY_ACTION_BUILD_DEPS        (1 << 6)

/* Hook flags */
#define HOOK_FLAG_ENABLED               (1 << 0)
#define HOOK_FLAG_TRACK_CONTAINERS      (1 << 1)
#define HOOK_FLAG_MEASURE_HASH          (1 << 2)

/* Hook identifiers */
enum bpfima_hook_id {
    HOOK_LSM_BPRM_CHECK_SECURITY = 0,
    HOOK_LSM_FILE_OPEN,
    HOOK_LSM_FILE_POST_OPEN,
    HOOK_LSM_MMAP_FILE,
    HOOK_LSM_SOCKET_CONNECT,
    HOOK_LSM_CONTAINER_EVENTS,
    HOOK_KPROBE_FILE_OPEN,
    HOOK_MAX
};

/* Policy structures - must match kernel definitions */
struct bpfima_policy_config {
    u8 enabled;
    u32 filter_flags;
    u32 action_flags;
    u32 min_file_size;
    u32 max_path_depth;
    u32 log_level;
    u32 reserved[2];
};

struct bpfima_pattern_entry {
    char pattern[MAX_PATTERN_LEN];
    u8 enabled;
    u8 match_type;
    u16 reserved;
};

struct bpfima_hook_config {
    u32 flags;
    u32 filter_override;
    u32 action_override;
    u32 reserved[1];
};

#define POLICY_MAP_PATH "/sys/fs/bpf/bpfima_policy_map"
#define CGROUP_PATTERNS_MAP_PATH "/sys/fs/bpf/bpfima_cgroup_patterns_map"
#define PATH_PATTERNS_MAP_PATH "/sys/fs/bpf/bpfima_path_patterns_map"
#define HOOK_CONFIG_MAP_PATH "/sys/fs/bpf/bpfima_hook_config_map"

int main(int argc, char **argv)
{
    int policy_fd, cgroup_fd, path_fd, hook_fd;
    int ret = 0;
    __u32 key;

    /* Open pinned BPF maps */
    policy_fd = bpf_obj_get(POLICY_MAP_PATH);
    if (policy_fd < 0) {
        fprintf(stderr, "Failed to open policy map: %s\n", strerror(errno));
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

    printf("Successfully opened all policy maps\n");

    /* Initialize main policy configuration */
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
        .log_level = 2,  /* Info level */
    };

    key = 0;
    ret = bpf_map_update_elem(policy_fd, &key, &policy, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to update policy map: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("✓ Initialized main policy configuration\n");

    /* Initialize cgroup ignore patterns - only filter root and system management cgroups */
    const char *cgroup_patterns[] = {"/", "init.scope"};
    for (int i = 0; i < 2; i++) {
        struct bpfima_pattern_entry pattern = {0};
        strncpy(pattern.pattern, cgroup_patterns[i], MAX_PATTERN_LEN - 1);
        pattern.enabled = 1;
        pattern.match_type = 0;  /* Exact match */

        key = i;
        ret = bpf_map_update_elem(cgroup_fd, &key, &pattern, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Failed to update cgroup pattern %d: %s\n", i, strerror(errno));
            goto cleanup;
        }
    }
    printf("✓ Initialized %d cgroup ignore patterns\n", 2);

    /* Initialize remaining cgroup pattern entries as empty (best effort) */
    struct bpfima_pattern_entry empty_pattern = {0};
    for (int i = 2; i < MAX_IGNORE_PATTERNS; i++) {
        key = i;
        ret = bpf_map_update_elem(cgroup_fd, &key, &empty_pattern, BPF_ANY);
        if (ret < 0) {
            /* Non-fatal - map might be smaller than MAX_IGNORE_PATTERNS */
            if (i < 10) {
                fprintf(stderr, "Warning: Failed to clear cgroup pattern %d: %s\n", i, strerror(errno));
            }
            break;  /* Stop trying if we hit an error */
        }
    }

    /* Initialize path ignore patterns - only filter /proc and /sys */
    const char *path_patterns[] = {"/proc/", "/sys/"};
    for (int i = 0; i < 2; i++) {
        struct bpfima_pattern_entry pattern = {0};
        strncpy(pattern.pattern, path_patterns[i], MAX_PATTERN_LEN - 1);
        pattern.enabled = 1;
        pattern.match_type = 1;  /* Prefix match */

        key = i;
        ret = bpf_map_update_elem(path_fd, &key, &pattern, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Failed to update path pattern %d: %s\n", i, strerror(errno));
            goto cleanup;
        }
    }
    printf("✓ Initialized %d path ignore patterns\n", 2);

    /* Initialize remaining path pattern entries as empty (best effort) */
    for (int i = 2; i < MAX_PATH_FILTERS; i++) {
        key = i;
        ret = bpf_map_update_elem(path_fd, &key, &empty_pattern, BPF_ANY);
        if (ret < 0) {
            /* Non-fatal - map might be smaller than MAX_PATH_FILTERS */
            if (i < 10) {
                fprintf(stderr, "Warning: Failed to clear path pattern %d: %s\n", i, strerror(errno));
            }
            break;  /* Stop trying if we hit an error */
        }
    }

    /* Initialize hook configurations */
    for (int i = 0; i < HOOK_MAX; i++) {
        struct bpfima_hook_config hook_cfg = {
            .flags = HOOK_FLAG_ENABLED | HOOK_FLAG_TRACK_CONTAINERS | HOOK_FLAG_MEASURE_HASH,
            .filter_override = 0,
            .action_override = 0,
        };

        /* Disable some hooks by default */
        if (i == HOOK_LSM_SOCKET_CONNECT || i == HOOK_KPROBE_FILE_OPEN) {
            hook_cfg.flags = 0;
        }

        key = i;
        ret = bpf_map_update_elem(hook_fd, &key, &hook_cfg, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Failed to update hook config %d: %s\n", i, strerror(errno));
            goto cleanup;
        }
    }
    printf("✓ Initialized %d hook configurations\n", HOOK_MAX);

    printf("\n✓ Policy initialization complete!\n");
    printf("  Policy enabled: Yes\n");
    printf("  Filter flags: 0x%x (NO filtering - tracks all user processes, containers, etc.)\n", policy.filter_flags);
    printf("  Action flags: 0x%x (TPM extend, log to securityfs+kernel, track containers, build deps)\n", policy.action_flags);
    printf("  Log level: %u (Info)\n", policy.log_level);
    printf("\n  What gets measured:\n");
    printf("    - All user processes (user.slice)\n");
    printf("    - All containers (Docker, Podman, etc.)\n");
    printf("    - System services (system.slice)\n");
    printf("    - Files in /dev/, /tmp/\n");
    printf("    - Everything except: /, init.scope (minimal system overhead)\n");

cleanup:
    close(policy_fd);
    close(cgroup_fd);
    close(path_fd);
    close(hook_fd);
    return ret;
}
