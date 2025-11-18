// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Minimal eBPF Program Loader
 * Loads and attaches a single eBPF object file
 * Usage: ./loader <bpf_object_file.o>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool exiting = false;

static void sig_handler(int signo)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct bpf_map *map;
    const char *filename;
    int err = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file.o>\n", argv[0]);
        return 1;
    }

    filename = argv[1];

    /* Increase RLIMIT_MEMLOCK for BPF */
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
        return 1;
    }

    /* Open BPF object */
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s\n", filename);
        return 1;
    }

    /* Set pin path for maps before loading */
    bpf_object__for_each_map(map, obj) {
        bpf_map__set_pin_path(map, NULL); /* Use default /sys/fs/bpf/<map_name> */
    }

    /* Set LSM programs as sleepable */
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_LSM) {
            bpf_program__set_flags(prog, BPF_F_SLEEPABLE);
        }
    }

    /* Load BPF program */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    /* Pin all maps after loading */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
        
        err = bpf_map__pin(map, pin_path);
        if (err && err != -EEXIST) {
            /* Skip warnings for read-only data maps - they can't be pinned */
            if (strstr(map_name, ".rodata") == NULL && strstr(map_name, ".bss") == NULL) {
                fprintf(stderr, "Warning: Failed to pin map %s: %d\n", map_name, err);
            }
        } else {
            printf("Pinned map %s to %s\n", map_name, pin_path);
        }
    }

    /* Attach all programs in the object */
    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach program\n");
            err = 1;
            goto cleanup;
        }
        printf("Attached %s\n", bpf_program__name(prog));
        break; /* Only attach first program */
    }

    if (!link) {
        fprintf(stderr, "No programs attached\n");
        err = 1;
        goto cleanup;
    }

    printf("Running. Press Ctrl-C to stop.\n");

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Main loop */
    while (!exiting) {
        sleep(1);
    }

    printf("Cleaning up...\n");

    /* Unpin all maps before cleanup */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
        
        if (bpf_map__unpin(map, pin_path) == 0) {
            printf("Unpinned map %s\n", map_name);
        }
    }

cleanup:
    if (link) {
        bpf_link__destroy(link);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    return err;
}
