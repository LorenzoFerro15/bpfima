#!/bin/bash

# TEST TO GATHER DATA ON BINARY EXECUTION - Cold run
# Get the user-space and kernel-space times to execute a simple binary with bpfima triggering the bprm_check_security hook
# As the binary is always different, the TPM has to record the measurement each time, representing the worst case scenario

# csv files initialization
FILE_CSV_BPRM_FIRST_EXEC="test_bprm_first_exec_times.csv"
FILE_CSV_BPRM_FIRST_MAP="test_bprm_first_map_times.csv"

if [ ! -f "$FILE_CSV_BPRM_FIRST_EXEC" ]; then
    echo "start,end,diff" > "$FILE_CSV_BPRM_FIRST_EXEC"
fi

if [ ! -f "$FILE_CSV_BPRM_FIRST_MAP" ]; then
    echo "index,total_time,deps_time,measure_time,hash_time,extend_time,get_config_time,filtering_time,binary_name" > $FILE_CSV_BPRM_FIRST_MAP
fi

gcc /tmp/test_binary.c -o /tmp/test_binary
# Run some times, so measure_time is loaded in memory and measured by the TPM
for i in {0..2}; do
./measure_time ./test_binary
done

# Run many times with different return codes, so the TPM always records the measurements
for i in {1..101}; do
    sed -i "4s/.*/    return ${i};/" test_binary.c
    gcc /tmp/test_binary.c -o /tmp/test_binary
    ./measure_time ./test_binary >> "$FILE_CSV_BPRM_FIRST_EXEC"
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
' >> $FILE_CSV_BPRM_FIRST_MAP

# Reset file to the initial state
sed -i "4s/.*/    return 0;/" test_binary.c