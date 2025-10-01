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
    struct bpf_link *link = NULL;
    struct bpf_program *prog;
    struct bpf_object *obj;
    int err;
    const char *filename = "kfunc.o"; 

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

    /* Find the BPF program by section name */
    prog = bpf_object__find_program_by_name(obj, "handle_kprobe");
    if (!prog) {
        fprintf(stderr, "ERROR: finding BPF program 'handle_kprobe' failed\n");
        goto cleanup;
    }

    /* Attach kprobe */
    link = bpf_program__attach_kprobe(prog, false, "do_unlinkat");
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_program__attach_kprobe failed\n");
        link = NULL;
        goto cleanup;
    }

    printf("Successfully loaded and attached BPF program!\n");
    printf("Monitoring do_unlinkat() calls... Press Ctrl-C to stop.\n");

    /* Set up signal handler */
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Main loop */
    printf("BPF program is running. Check /sys/kernel/debug/tracing/trace_pipe for output.\n");
    printf("You can also run: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching BPF program...\n");

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return err < 0 ? -err : 0;
}