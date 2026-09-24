#!/bin/bash

# TEST TO GATHER DATA ON POLICY UPDATE (MULTI-ATTRIBUTE UPDATE)
# Swap between two different policies and change the min_file_size each time, so the hash is always different
for i in {1..100}; do
    sed -i "10s/.*/    min_file_size: ${i}/" policy_multiple_change_test_1.yaml
    echo "${i} $(date +%s%N)"
    kubectl apply -f policy_multiple_change_test_1.yaml > /dev/null 2>&1
    sleep 2
    sed -i "10s/.*/    min_file_size: ${i}/" policy_multiple_change_test_2.yaml
    echo "${i} $(date +%s%N)"
    kubectl apply -f policy_multiple_change_test_2.yaml > /dev/null 2>&1
    sleep 2
done

