#!/bin/bash

# TEST TO GATHER DATA ON POD CREATION
FILE_CSV_DWN="create_daemonset_download.csv"
FILE_CSV_RMMOD="create_daemonset_rm_module.csv"
FILE_CSV="create_daemonset.csv"

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
kubectl apply -f bpfima.yaml
kubectl rollout status daemonset/bpfima
kubectl delete ds bpfima
kubectl wait --for=delete pod -l app=bpfima --timeout=60s

# Warm start: test time to run the container if the module was already inserted
for i in {1..100}; do
START_EPOCH=$(date +%s%N)
kubectl apply -f /tmp/bpfima.yaml
kubectl rollout status daemonset/bpfima
END_EPOCH=$(date +%s%N)
echo "${START_EPOCH},${END_EPOCH}" >> "$FILE_CSV"
kubectl delete ds bpfima
kubectl wait --for=delete pod -l app=bpfima --timeout=60s
done

sleep 5
rmmod bpfima

# Cold start: test time to run container if the image is already available recompiling the module each time
for i in {1..100}; do
    START_EPOCH=$(date +%s%N)
    kubectl apply -f /tmp/bpfima.yaml
    kubectl rollout status daemonset/bpfima
    END_EPOCH=$(date +%s%N)
    echo "${START_EPOCH},${END_EPOCH}" >> "$FILE_CSV_RMMOD"
    kubectl delete ds bpfima
    kubectl wait --for=delete pod -l app=bpfima --timeout=60s
    sleep 5
    rm -f /sys/fs/bpf/*
    rmmod bpfima
done

crictl rmi iochia02/bpfima:v2.85
sleep 5
# Cold start + pull image: test time to download and run container
for i in {1..90}; do
    START_EPOCH=$(date +%s%N)
    kubectl apply -f /tmp/bpfima.yaml
    kubectl rollout status daemonset/bpfima
    END_EPOCH=$(date +%s%N)
    echo "${START_EPOCH},${END_EPOCH}" >> "$FILE_CSV_DWN"
    kubectl delete ds bpfima
    kubectl wait --for=delete pod -l app=bpfima --timeout=60s
    sleep 5
    rm -f /sys/fs/bpf/*
    rmmod bpfima
    crictl rmi iochia02/bpfima:v2.85
    sleep 5
done