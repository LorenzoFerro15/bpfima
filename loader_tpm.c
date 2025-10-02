// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_int(int signo)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct bpf_link *file_open_link = NULL;
    struct bpf_program *file_open_prog;
    struct bpf_object *obj;
    int err;
    const char *filename = "lsm_file_open.o"; /* default filename */

    if (argc > 1) {
        filename = argv[1];
    }

    libbpf_set_print(libbpf_print_fn);

    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }

    /* Open BPF application */
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }


    file_open_prog = bpf_object__find_program_by_name(obj, "handle_lsm_file_post_open_tpm");
    if (file_open_prog) {
        file_open_link = bpf_program__attach(file_open_prog);
        if (!libbpf_get_error(file_open_link)) {
            printf("Successfully attached file_post_open program\n");
        } else {
            fprintf(stderr, "ERROR: failed to attach file_open LSM program\n");
            file_open_link = NULL;
        }
    }

    if (!file_open_link) {
        fprintf(stderr, "ERROR: failed to attach any programs\n");
        goto cleanup;
    }

    printf("LSM monitoring programs are running!\n");
    printf("Check /sys/kernel/debug/tracing/trace_pipe for output.\n");

    /* Set up signal handler */
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Main loop */
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching BPF programs...\n");

cleanup:
    if (file_open_link) {
        bpf_link__destroy(file_open_link);
    }
    bpf_object__close(obj);
    return 0;
}