#!/bin/bash

set -e

cd /opt/bpfima
make all

insmod build/bpfima.ko
echo "Module inserted"

./build/bpfima-tool load build/lsm_bprm_check_security.o -d
./build/bpfima-tool policy-init
echo "eBPF program loaded and maps initialized"

sleep infinity