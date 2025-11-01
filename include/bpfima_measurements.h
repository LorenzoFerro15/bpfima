#ifndef BPFIMA_MEASUREMENTS_H
#define BPFIMA_MEASUREMENTS_H

#include <linux/slab.h>
#include "bpfima_common.h"

/* Measurement entry creation helper */
struct measurement_entry *create_measurement_entry(const char *event_name,
                                                   const char *event_data,
                                                   const u8 *digest,
                                                   gfp_t gfp_flags);

#endif /* BPFIMA_MEASUREMENTS_H */
