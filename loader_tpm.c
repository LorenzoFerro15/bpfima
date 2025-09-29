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
    struct bpf_link *tracepoint_link = NULL;
    struct bpf_link *kprobe_link = NULL;
    struct bpf_program *tracepoint_prog, *kprobe_prog;
    struct bpf_object *obj;
    int err;
    const char *filename = "kfunc_tpm.o"; /* default filename */

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

    /* Find the tracepoint program */
    tracepoint_prog = bpf_object__find_program_by_name(obj, "handle_unlinkat_tpm");
    if (tracepoint_prog) {
        tracepoint_link = bpf_program__attach(tracepoint_prog);
        if (!libbpf_get_error(tracepoint_link)) {
            printf("Successfully attached tracepoint program!\n");
        } else {
            fprintf(stderr, "ERROR: failed to attach tracepoint program\n");
            tracepoint_link = NULL;
        }
    }

    /* Find the kprobe program */
    kprobe_prog = bpf_object__find_program_by_name(obj, "handle_vfs_unlink_tpm");
    if (kprobe_prog) {
        kprobe_link = bpf_program__attach(kprobe_prog);
        if (!libbpf_get_error(kprobe_link)) {
            printf("Successfully attached kprobe program!\n");
        } else {
            fprintf(stderr, "ERROR: failed to attach kprobe program\n");
            kprobe_link = NULL;
        }
    }

    if (!tracepoint_link && !kprobe_link) {
        fprintf(stderr, "ERROR: failed to attach any programs\n");
        goto cleanup;
    }

    printf("TPM monitoring programs are running!\n");
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
    if (tracepoint_link) {
        bpf_link__destroy(tracepoint_link);
    }
    if (kprobe_link) {
        bpf_link__destroy(kprobe_link);
    }
    bpf_object__close(obj);
    return 0;
}