/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_IMA_COMMON_H__
#define __BPF_IMA_COMMON_H__

#define COMM_LEN 16
#define EVENT_NAME_LEN 32
#define MEASUREMENT_DATA_LEN 256
#define PCR_BUF_LEN 128

/* Event data structure for ring buffer */
struct ima_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[COMM_LEN];
    char event_name[EVENT_NAME_LEN];
    char measurement_data[MEASUREMENT_DATA_LEN];
    char pcr_value[PCR_BUF_LEN];
        __u32 tpm_available;
    __s32 ima_result;
    __s32 pcr_result;
    __u32 data_len;
};

#endif /* __BPF_IMA_COMMON_H__ */