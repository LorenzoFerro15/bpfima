#!/bin/bash

# TEST TO GATHER DATA ON BINARY EXECUTION - Warm run
# Get the user-space and kernel-space times to execute a simple binary with bpfima triggering the bprm_check_security hook
# The binary is always the same, so the TPM doesn't record the measurement

# csv files initialization
FILE_CSV_BPRM_SECOND_EXEC="test_bprm_second_exec_times.csv"
FILE_CSV_BPRM_SECOND_MAP="test_bprm_second_map_times.csv"

if [ ! -f "$FILE_CSV_BPRM_SECOND_EXEC" ]; then
    echo "start,end,diff" > "$FILE_CSV_BPRM_SECOND_EXEC"
fi

if [ ! -f "$FILE_CSV_BPRM_SECOND_MAP" ]; then
    echo "index,total_time,deps_time,measure_time,hash_time,extend_time,get_config_time,filtering_time,binary_name" > $FILE_CSV_BPRM_SECOND_MAP
fi

gcc /tmp/test_binary.c -o /tmp/test_binary
# Run some times, so measure_time and test_binary are loaded in memory and measured by the TPM
for i in {0..2}; do
./measure_time ./test_binary
done

# Execute 100 executions and record the user-space time
for i in {0..100}; do
    ./measure_time ./test_binary >> "$FILE_CSV_BPRM_SECOND_EXEC"
done

# Bump data from BPF map to csv file to gather statistics about the hook
bpftool map dump pinned /sys/fs/bpf/bpf_timing_stats_bprm -j | jq -r '
  .[] | select(.formatted.value.total_time > 0) | [
    .formatted.key,
    .formatted.value.total_time,
    .formatted.value.deps_time,
    .formatted.value.measure_time,
    .formatted.value.hash_time,
    .formatted.value.extend_time,
    .formatted.value.get_config_time,
    .formatted.value.filtering_time,
    .formatted.value.binary_name
  ] | @csv
' >> $FILE_CSV_BPRM_SECOND_MAP