#!/bin/bash

# TEST TO GATHER DATA ON SOCKET CREATION - Baseline
# Get the user-space time to open a socket without bpfima

# csv file initialization
FILE_CSV_SOCKET_BASELINE_EXEC="test_socket_baseline_exec_times.csv"

if [ ! -f "$FILE_CSV_SOCKET_BASELINE_EXEC" ]; then
    echo "start,end,diff" > "$FILE_CSV_SOCKET_BASELINE_EXEC"
fi

gcc /tmp/socket_test_binary.c -o /tmp/socket_test_binary > /dev/null 2>&1
# Execute the binary some times so it is loaded in memory
for i in {0..2}; do
./measure_time ./socket_test_binary
done

# Execute 100 executions and record the user-space time
for i in {0..100}; do
    ./measure_time ./socket_test_binary >> "$FILE_CSV_SOCKET_BASELINE_EXEC"
done
