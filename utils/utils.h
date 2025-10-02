#ifndef UTILS_H
#define UTILS_H

static __always_inline int build_measurement_data(char *measurement_data, int max_len, 
                                                  const char *comm, pid_t pid, u32 uid)
#enfif