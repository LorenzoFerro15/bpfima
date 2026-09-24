#!/bin/bash

# TEST TO GATHER DATA ON POLICY UPDATE (SINGLE-ATTRIBUTE UPDATE)
# Change the min_file_size each time, so the hash is always different
for i in {1..100}; do
    sed -i "14s/.*/    min_file_size: ${i}/" policy_single_change_test.yaml
    echo "${i} $(date +%s%N)"
    kubectl apply -f policy_single_change_test.yaml > /dev/null 2>&1
    sleep 2
done

