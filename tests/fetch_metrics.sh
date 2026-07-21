#!/bin/bash

# TEST TO GATHER DATA ON THE CONTROLLER USAGE OF CPU AND RAM
# Configuration
METRICS_URL="http://localhost:8080/metrics"
OUTPUT_FILE="metrics_dump.txt"
CSV_FILE="controller_metrics.csv"
POLL_INTERVAL=1

if [ ! -f "$CSV_FILE" ]; then
    echo "Timestamp,CPU_Seconds,RAM_MB,RAM_Bytes" > "$CSV_FILE"
fi
while true; do
    # Fetch the metrics and save them to the output file
    curl -s "$METRICS_URL" > "$OUTPUT_FILE"

    TIMESTAMP=$(date +%s%N)

    # Parse the CPU and RAM metrics
    CPU_SECONDS=$(grep "^process_cpu_seconds_total " "$OUTPUT_FILE" | awk '{print $2}')
    RAM_BYTES=$(grep "^process_resident_memory_bytes " "$OUTPUT_FILE" | awk '{print $2}')

    # Convert RAM from bytes to Megabytes (MB) for readability using awk
    RAM_MB=$(awk -v bytes="$RAM_BYTES" 'BEGIN { printf "%.2f", bytes / 1024 / 1024 }')

    # Append the comma-separated format to the CSV file
    echo "$TIMESTAMP,$CPU_SECONDS,$RAM_MB,$RAM_BYTES" >> "$CSV_FILE"

    # Wait for the specified interval before the next request
    sleep $POLL_INTERVAL
done