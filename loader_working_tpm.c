#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

static struct bpf_object *obj = NULL;
static struct bpf_link *link1 = NULL;
static struct bpf_link *link2 = NULL;

void cleanup(void) {
    if (link1) bpf_link__destroy(link1);
    if (link2) bpf_link__destroy(link2);
    if (obj) bpf_object__close(obj);
}

void signal_handler(int sig) {
    printf("\n=== Stopping TPM simulation ===\n");
    cleanup();
    exit(0);
}

int main() {
    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    obj = bpf_object__open("kfunc_tpm_sim.o");
    if (libbpf_get_error(obj)) {
        printf("Failed to open BPF object\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        goto cleanup;
    }
    
    struct bpf_program *prog1 = bpf_object__find_program_by_name(obj, "handle_unlinkat_tpm_sim");
    if (prog1) {
        link1 = bpf_program__attach(prog1);
        if (!libbpf_get_error(link1)) {
            printf("✓ TPM tracepoint attached\n");
        }
    }
    
    struct bpf_program *prog2 = bpf_object__find_program_by_name(obj, "handle_vfs_unlink_tmp_sim");
    if (prog2) {
        link2 = bpf_program__attach(prog2);
        if (!libbpf_get_error(link2)) {
            printf("✓ VFS kprobe attached\n");
        }
    }
    
    printf("\n=== TPM Simulation Active ===\n");
    printf("Monitoring file unlink operations...\n");
    printf("TPM counters and PCR simulation enabled\n");
    printf("Press Ctrl+C to stop\n\n");
    
    while (1) sleep(1);
    
cleanup:
    cleanup();
    return 0;
}
