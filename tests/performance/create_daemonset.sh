#!/bin/bash

# TEST TO GATHER DATA ON POD CREATION
FILE_CSV_DWN="create_daemonset_pull_image.csv"
FILE_CSV_RMMOD="create_daemonset_cold.csv"
FILE_CSV="create_daemonset_warm.csv"

if [ ! -f "$FILE_CSV_DWN" ]; then
    echo "start,end" > "$FILE_CSV_DWN"
fi
if [ ! -f "$FILE_CSV_RMMOD" ]; then
    echo "start,end" > "$FILE_CSV_RMMOD"
fi
if [ ! -f "$FILE_CSV" ]; then
    echo "start,end" > "$FILE_CSV"
fi

# Get the env ready
helm install bpfima ./bpfima
kubectl rollout status daemonset/bpfima

# Warm start: test time to run the container if the module was already inserted
for i in {1..100}; do
    START_EPOCH=$(date +%s%N)
    kubectl rollout restart daemonset/bpfima
    kubectl rollout status daemonset/bpfima
    END_EPOCH=$(date +%s%N)
    echo "${START_EPOCH},${END_EPOCH}" >> "$FILE_CSV"
    sleep 5
done

# Clean up before moving to the next test
helm uninstall bpfima
sleep 20

# Cold start: test time to run container if the image is already available recompiling the module each time
for i in {1..100}; do
    START_EPOCH=$(date +%s%N)
    helm install bpfima ./bpfima
    kubectl rollout status daemonset/bpfima
    END_EPOCH=$(date +%s%N)
    echo "${START_EPOCH},${END_EPOCH}" >> "$FILE_CSV_RMMOD"
    helm uninstall bpfima
    kubectl wait --for=delete pod -l app.kubernetes.io/name=bpfima --timeout=60s
    sleep 20
done

crictl rmi iochia02/bpfima:v2.92 || true
sleep 5

# Cold start + pull image: test time to download and run container
for i in {1..100}; do
    START_EPOCH=$(date +%s%N)
    helm install bpfima ./bpfima
    kubectl rollout status daemonset/bpfima
    END_EPOCH=$(date +%s%N)
    echo "${START_EPOCH},${END_EPOCH}" >> "$FILE_CSV_DWN"
    helm uninstall bpfima
    kubectl wait --for=delete pod -l app=bpfima --timeout=60s
    sleep 20
    crictl rmi iochia02/bpfima:v2.92
    sleep 5
done