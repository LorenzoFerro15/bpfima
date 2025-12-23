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


echo "Generating graphs from $OUTPUT..."
echo "Generating graphs from $OUTPUT..."
python3 scripts/plot_averages.py "$OUTPUT"

HEATMAP_LOG="size_exec_latency.log"
rm -f "$HEATMAP_LOG"

echo "Running Heatmap Warmup (Cold Run) to discard initial optimizations..."
sudo ./scripts/heatmap_test.sh > /dev/null 2>&1
sudo ./scripts/heatmap_test.sh > /dev/null 2>&1

echo "Starting Heatmap Series..."
for ((i=1; i<=RUNS; i++)); do
    echo "Heatmap Run $i/$RUNS..."
    sudo ./scripts/heatmap_test.sh
done

echo "Generating Heatmap..."
python3 scripts/plot_heatmap.py "$HEATMAP_LOG"

echo "Completed $RUNS runs. Results saved to $OUTPUT and graphs generated."
