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

cleanup:
    if (link) {
        bpf_link__destroy(link);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    return err;
}
