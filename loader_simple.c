/*
 * Simple eBPF loader that doesn't require custom kernel module
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <errno.h>
#include <string.h>

static struct bpf_object *obj = NULL;
static struct bpf_link *tracepoint_link = NULL;
static struct bpf_link *kprobe_link = NULL;

void cleanup(void)
{
    if (tracepoint_link) {
        bpf_link__destroy(tracepoint_link);
        tracepoint_link = NULL;
    }
    if (kprobe_link) {
        bpf_link__destroy(kprobe_link);
        kprobe_link = NULL;
    }
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
}

void signal_handler(int sig)
{
    printf("\nReceived signal %d, cleaning up...\n", sig);
    cleanup();
    exit(0);
}

int main(int argc, char **argv)
{
    int err;
    struct bpf_program *tracepoint_prog, *kprobe_prog;

    /* Set up proper memory limits for BPF */
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return 1;
    }

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Set libbpf error and debug info callback */
    libbpf_set_print(NULL);

    /* Load the BPF object file */
    obj = bpf_object__open("kfunc_simple.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    /* Load BPF program */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("BPF program loaded successfully\n");

    /* Find the tracepoint program */
    tracepoint_prog = bpf_object__find_program_by_name(obj, "handle_unlinkat");
    if (!tracepoint_prog) {
        fprintf(stderr, "ERROR: finding tracepoint program failed\n");
        err = -1;
        goto cleanup;
    }

    /* Attach tracepoint */
    tracepoint_link = bpf_program__attach(tracepoint_prog);
    if (libbpf_get_error(tracepoint_link)) {
        fprintf(stderr, "ERROR: attaching tracepoint failed\n");
        tracepoint_link = NULL;
        err = -1;
        goto cleanup;
    }

    printf("Tracepoint attached successfully\n");

    /* Find the kprobe program */
    kprobe_prog = bpf_object__find_program_by_name(obj, "handle_vfs_unlink");
    if (!kprobe_prog) {
        fprintf(stderr, "WARNING: kprobe program not found, continuing with tracepoint only\n");
    } else {
        /* Attach kprobe */
        kprobe_link = bpf_program__attach(kprobe_prog);
        if (libbpf_get_error(kprobe_link)) {
            fprintf(stderr, "WARNING: attaching kprobe failed, continuing with tracepoint only\n");
            kprobe_link = NULL;
        } else {
            printf("Kprobe attached successfully\n");
        }
    }

    printf("\n=== File Monitoring Active ===\n");
    printf("Monitoring file unlink operations...\n");
    printf("Check /sys/kernel/debug/tracing/trace_pipe for events\n");
    printf("Press Ctrl+C to exit\n\n");

    /* Keep the program running */
    while (1) {
        sleep(1);
    }

cleanup:
    cleanup();
    return err;
}