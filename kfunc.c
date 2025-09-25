#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
typedef long long s64;
extern int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) __ksym;
extern int bpf_ima_is_enabled(void) __ksym;
extern int bpf_get_file_path(struct file *file, char *buf, u32 buf_size) __ksym;
extern int bpf_ima_measure_data(const char *event_label, const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_file_info(struct file *file, char *hash_buf, u32 buf_size) __ksym;
extern int bpf_ima_extend_measurement(const char *event_name, const char *data, u32 data_len) __ksym;
extern int bpf_ima_get_measurement_count(void) __ksym;
extern int bpf_ima_get_pcr_value(char *pcr_buf, u32 buf_size) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Monitor file unlink operations and perform IMA measurements */
SEC("kprobe/do_unlinkat")
int handle_kprobe(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char str[] = "Hello, world!";
    char substr[] = "wor";
    
    int result = bpf_strstr(str, sizeof(str) - 1, substr, sizeof(substr) - 1);
    if (result != -1) {
        bpf_printk("'%s' found in '%s' at index %d\n", substr, str, result);
    }
    
    int ima_enabled = bpf_ima_is_enabled();
    bpf_printk("IMA enabled: %d\n", ima_enabled);
    
    char event_name[] = "file_unlink";
    char measurement_data[] = "unlink_operation_detected";
    char pcr_buffer[64];
    
    int extend_ret = bpf_ima_extend_measurement(event_name, measurement_data, sizeof(measurement_data) - 1);
    int count = bpf_ima_get_measurement_count();
    int pcr_ret = bpf_ima_get_pcr_value(pcr_buffer, sizeof(pcr_buffer));
    
    bpf_printk("IMA extend result: %d, count: %d\n", extend_ret, count);
    if (pcr_ret == 0) {
        bpf_printk("PCR value: %.32s\n", pcr_buffer);
    }
    
    bpf_printk("Hello, world! (pid: %d) bpf_strstr %d, IMA: %d\n", pid, result, ima_enabled);
    return 0;
}