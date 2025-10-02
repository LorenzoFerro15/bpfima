#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool should_exit = false;

static void sig_handler(int sig) {
    should_exit = true;
}

static int cleanup() {
    printf("Cleanup completed.\n");
    return 0;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

    printf("Starting LSM IMA Test Loader...\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load BPF object */
    obj = bpf_object__open_file("lsm_file_open.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    /* Get the LSM program and set it as sleepable BEFORE loading */
    prog = bpf_object__find_program_by_name(obj, "lsm_file_open");
    if (!prog) {
        fprintf(stderr, "ERROR: finding LSM program failed\n");
        err = -1;
        goto cleanup;
    }

    /* Set the program as sleepable to allow bpf_ima_file_hash */
    bpf_program__set_flags(prog, BPF_F_SLEEPABLE);
    printf("✓ Set LSM program as sleepable for IMA helper\n");

    /* Load BPF program */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    /* Attach the LSM program */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching LSM program failed\n");
        err = -1;
        goto cleanup;
    }

    printf("✓ LSM IMA test program attached successfully\n");
    printf("✓ Testing bpf_ima_file_hash in LSM context\n");
    printf("Press Ctrl+C to exit...\n");

    /* Keep running */
    while (!should_exit) {
        sleep(1);
    }

cleanup:
    if (link) {
        bpf_link__destroy(link);
    }
    bpf_object__close(obj);
    return cleanup();
}