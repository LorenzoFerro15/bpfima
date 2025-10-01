// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 
 * Ring buffer userspace reader for eBPF programs
 * Reads structured data from eBPF ring buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Event data structure for ring buffer - must match eBPF definition */
#define COMM_LEN 16
#define EVENT_NAME_LEN 32
#define MEASUREMENT_DATA_LEN 256
#define PCR_BUF_LEN 128

struct ima_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[COMM_LEN];
    char event_name[EVENT_NAME_LEN];
    char measurement_data[MEASUREMENT_DATA_LEN];
    char pcr_value[PCR_BUF_LEN];
    __u32 tmp_available;
    __s32 ima_result;
    __s32 pcr_result;
    __u32 data_len;
};

static volatile bool exiting = false;

static void sig_int(int signo)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/* Ring buffer callback function */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    FILE *output_file = (FILE *)ctx;
    const struct ima_event *event = data;
    
    if (data_sz != sizeof(*event)) {
        fprintf(stderr, "Invalid event size: got %zu, expected %zu\n", 
                data_sz, sizeof(*event));
        return 0;
    }
    
    /* Convert timestamp to human readable format */
    time_t ts_sec = event->timestamp / 1000000000ULL;
    long ts_nsec = event->timestamp % 1000000000ULL;
    char time_str[64];
    struct tm *tm_info = localtime(&ts_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Print to console */
    printf("=== IMA EVENT ===\n");
    printf("Timestamp: %s.%09ld\n", time_str, ts_nsec);
    printf("Process: %s (pid=%u, uid=%u, gid=%u)\n", 
           event->comm, event->pid, event->uid, event->gid);
    printf("Event: %s\n", event->event_name);
    printf("Measurement Data: %s (len=%u)\n", 
           event->measurement_data, event->data_len);
    printf("TPM Available: %s\n", event->tmp_available ? "YES" : "NO");
    printf("IMA Result: %d\n", event->ima_result);
    printf("PCR Result: %d\n", event->pcr_result);
    if (event->pcr_result == 0) {
        printf("PCR Value: %.64s\n", event->pcr_value);
    }
    printf("\n");
    
    /* Write to file if provided */
    if (output_file) {
        fprintf(output_file, 
                "%s.%09ld|%s|%u|%u|%u|%s|%s|%u|%d|%d|%.64s\n",
                time_str, ts_nsec,
                event->comm,
                event->pid, event->uid, event->gid,
                event->event_name,
                event->measurement_data,
                event->tmp_available,
                event->ima_result,
                event->pcr_result,
                event->pcr_result == 0 ? event->pcr_value : "N/A");
        fflush(output_file);
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    FILE *output_file = NULL;
    int map_fd = -1;
    int err = 0;
    const char *ebpf_filename = "kfunc_tpm.o";
    
    if (argc < 2) {
        printf("Usage: %s <output_file> [ebpf_file]\n", argv[0]);
        printf("  output_file: File to write structured logs (use '-' for stdout only)\n");
        printf("  ebpf_file: eBPF object file (default: kfunc_tpm.o)\n");
        return 1;
    }
    
    if (argc > 2) {
        ebpf_filename = argv[2];
    }
    
    /* Open output file */
    if (strcmp(argv[1], "-") != 0) {
        output_file = fopen(argv[1], "a");
        if (!output_file) {
            perror("Failed to open output file");
            return 1;
        }
        printf("Appending structured logs to: %s\n", argv[1]);
    }
    
    /* Set up signal handler */
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "Failed to set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }
    
    /* Set up libbpf */
    libbpf_set_print(libbpf_print_fn);
    
    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        goto cleanup;
    }
    
    /* Open and load BPF program */
    obj = bpf_object__open_file(ebpf_filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file '%s' failed\n", ebpf_filename);
        obj = NULL;
        goto cleanup;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }
    
    /* Find the BPF program */
    prog = bpf_object__find_program_by_name(obj, "handle_unlinkat_tpm");
    if (!prog) {
        fprintf(stderr, "ERROR: finding BPF program 'handle_unlinkat_tpm' failed\n");
        goto cleanup;
    }
    
    /* Attach the program */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching BPF program failed\n");
        link = NULL;
        goto cleanup;
    }
    
    /* Get the ring buffer map */
    map_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding ring buffer map failed\n");
        goto cleanup;
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(map_fd, handle_event, output_file, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("Successfully loaded and attached BPF program!\n");
    printf("Listening for IMA events on ring buffer... Press Ctrl-C to stop.\n");
    
    /* Poll for events */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100); /* timeout 100ms */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    printf("\nShutting down...\n");

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (output_file && output_file != stdout) {
        fclose(output_file);
    }
    
    return err < 0 ? -err : 0;
}