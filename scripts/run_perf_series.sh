#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <number_of_runs> <output_file>"
    exit 1
fi

if [ -n "$VIRTUAL_ENV" ]; then
    VENV_PYTHON="$VIRTUAL_ENV/bin/python3"
else
    VENV_PYTHON=$(which python3)
fi

RUNS=$1
OUTPUT=$2

sudo -v
: > "$OUTPUT"

echo "Starting $RUNS runs, outputting to $OUTPUT..."

for ((i=1; i<=RUNS; i++)); do
    echo "Run $i/$RUNS..."
    sudo timeout -s SIGINT 5s ./scripts/perf_test.sh >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    sleep 2
done

echo "Generating graphs from $OUTPUT..."
$VENV_PYTHON scripts/plot_averages.py "$OUTPUT"

HEATMAP_LOG="size_exec_latency.log"
rm -f "$HEATMAP_LOG"

echo "Running Heatmap Warmup..."
sudo ./scripts/heatmap_test.sh > /dev/null 2>&1

echo "Starting Heatmap Series..."
for ((i=1; i<=RUNS; i++)); do
    echo "Heatmap Run $i/$RUNS..."
    sudo ./scripts/heatmap_test.sh
done

echo "Generating Heatmap..."
$VENV_PYTHON scripts/plot_heatmap.py "$HEATMAP_LOG"

echo "Completed $RUNS runs."

THROUGHPUT_LOG="test_throughput.log"
: > "$THROUGHPUT_LOG"

echo "Starting Throughput Series..."
LOADS=(10 50 100 200)

for load in "${LOADS[@]}"; do
    echo "Running Throughput Test: Exec @ $load..."
    sudo ./scripts/throughput_test.sh exec "$load" >> "$THROUGHPUT_LOG"
    echo "Running Throughput Test: Socket @ $load..."
    sudo ./scripts/throughput_test.sh socket "$load" >> "$THROUGHPUT_LOG"
done

echo "Generating Throughput Graph..."
$VENV_PYTHON scripts/plot_throughput.py "$THROUGHPUT_LOG"
echo "Throughput tests completed."
