#!/bin/bash

# TEST TO GATHER DATA ON BINARY EXECUTION - Baseline
# Get the user-space time to execute a simple binary without bpfima

# csv file initialization
FILE_CSV_BPRM_BASE_EXEC="test_bprm_baseline_exec_times.csv"

if [ ! -f "$FILE_CSV_BPRM_BASE_EXEC" ]; then
    echo "start,end,diff" > "$FILE_CSV_BPRM_BASE_EXEC"
fi

gcc /tmp/test_binary.c -o /tmp/test_binary
# Execute the binary some times so it is loaded in memory
for i in {0..2}; do
./measure_time ./test_binary
done

# Execute 100 executions and record the user-space time
for i in {0..100}; do
    ./measure_time ./test_binary >> "$FILE_CSV_BPRM_BASE_EXEC"
done