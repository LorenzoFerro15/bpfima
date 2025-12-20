#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <number_of_runs> <output_file>"
    exit 1
fi

RUNS=$1
OUTPUT=$2

# Ensure we have sudo permissions upfront
sudo -v

# Clear output file
: > "$OUTPUT"

echo "Starting $RUNS runs, outputting to $OUTPUT..."

for ((i=1; i<=RUNS; i++)); do
    echo "Run $i/$RUNS..."
    
    sudo timeout -s SIGINT 5s ./scripts/perf_test.sh >> "$OUTPUT" 
    
    echo "" >> "$OUTPUT"
    
    sleep 2
done

echo "Completed $RUNS runs. Results saved to $OUTPUT."
