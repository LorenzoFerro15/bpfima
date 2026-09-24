#!/bin/bash

# TEST TO GATHER DATA ON SOCKET CREATION - Cold run
# Get the user-space and kernel-space times to open a socket with bpfima triggering the socket_connect hook
# As the destination port is always different, the TPM has to record the measurement each time, representing the worst case scenario

# csv files initialization
FILE_CSV_SOCKET_FIRST_EXEC="test_socket_first_exec_times.csv"
FILE_CSV_SOCKET_FIRST_MAP="test_socket_first_map_times.csv"

if [ ! -f "$FILE_CSV_SOCKET_FIRST_EXEC" ]; then
    echo "start,end,diff" > "$FILE_CSV_SOCKET_FIRST_EXEC"
fi

if [ ! -f "$FILE_CSV_SOCKET_FIRST_MAP" ]; then
    echo "index,total_time,deps_time,measure_time,hash_time,extend_time,get_config_time,filtering_time,binary_name" > $FILE_CSV_SOCKET_FIRST_MAP
fi

# SOCKET_CONNECT HOOK
gcc /tmp/socket_test_binary.c -o /tmp/socket_test_binary
# Run some times, so measure_time is loaded in memory and measured by the TPM
for i in {0..2}; do
./measure_time ./socket_test_binary
done

# Run many times with different destination ports, so the TPM always records the measurements
# It doesn't matter if the connection phase, as the hook is triggered when opening the socket
for i in {50000..50100}; do
  sed -i "12s/.*/        serv_addr.sin_port = htons(${i});/" socket_test_binary.c
  gcc /tmp/socket_test_binary.c -o /tmp/socket_test_binary
  ./measure_time ./socket_test_binary >> "$FILE_CSV_SOCKET_FIRST_EXEC"
done

# Bump data from BPF map to csv file to gather statistics about the hook
bpftool map dump pinned /sys/fs/bpf/bpf_timing_stats_socket -j | jq -r '
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
' >> $FILE_CSV_SOCKET_FIRST_MAP

# Reset file to the initial state
sed -i "12s/.*/        serv_addr.sin_port = htons(55555);/" socket_test_binary.c


