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
    struct bpf_link *kretprobe_link = NULL;
    struct bpf_program *kretprobe_prog;
    struct bpf_object *obj;
    int err;
    const char *filename = "kprobe_file_open.o"; /* default filename */

    if (argc > 1) {
        filename = argv[1];
    }

    libbpf_set_print(libbpf_print_fn);

    /* Increase RLIMIT_MEMLOCK for BPF */
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

    /* Find the kretprobe program */
    kretprobe_prog = bpf_object__find_program_by_name(obj, "kretprobe_file_open");
    if (!kretprobe_prog) {
        fprintf(stderr, "ERROR: finding kretprobe program failed\n");
        goto cleanup;
    }

    /* Set program as sleepable */
    bpf_program__set_flags(kretprobe_prog, BPF_F_SLEEPABLE);

    /* Attach kretprobe */
    kretprobe_link = bpf_program__attach(kretprobe_prog);
    if (libbpf_get_error(kretprobe_link)) {
        fprintf(stderr, "ERROR: bpf_program__attach kretprobe failed\n");
        kretprobe_link = NULL;
        goto cleanup;
    }

    printf("Successfully attached kretprobe program (SLEEPABLE)\n");
    printf("Kretprobe monitoring file opens with IMA file hash support!\n");
    printf("Check /sys/kernel/debug/tracing/trace_pipe for output.\n");

    /* Set up signal handler */
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    printf("Press Ctrl-C to exit...\n");

    /* Main loop */
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching programs...\n");

cleanup:
    /* Clean up */
    if (kretprobe_link)
        bpf_link__destroy(kretprobe_link);

    bpf_object__close(obj);
    
    printf("Cleanup completed.\n");
    return err;
}