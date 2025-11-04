#ifndef BPFIMA_MEASUREMENTS_H
#define BPFIMA_MEASUREMENTS_H

#include "bpfima_common.h"

/* Measurement entry creation helper */
struct measurement_entry *create_measurement_entry(const char *event_name,
                                                   const char *event_data,
                                                   const u8 *digest,
                                                   gfp_t gfp_flags);

/* BPF IMA template entry creation helper */
struct bpf_ima_template_entry *create_bpf_ima_entry(const char *event_name,
                                                     const char *event_data,
                                                     const u8 *digest,
                                                     gfp_t gfp_flags);

#endif /* BPFIMA_MEASUREMENTS_H */
