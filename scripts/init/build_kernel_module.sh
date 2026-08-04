#!/bin/bash

set -e

TPM_PCR=$1

# First of all, verify if the module is already inserted and the version is the same
# This optimization allows to save time avoiding rebuilding the module each time and losing the previous logs
if cat /proc/modules | grep -q bpfima; then
    echo "Module already inserted"
    echo "Verifying version..."
    LOADED_VER=$(cat /sys/module/bpfima/version 2>/dev/null)
    DISK_VER=$(awk -F'"' '/MODULE_VERSION/ {print $2}' /opt/bpfima/src/bpfima_main.c)
    if [ "$LOADED_VER" != "$DISK_VER" ]; then
        echo "Different version available... building it"
        rmmod bpfima
    else
        echo "Same version available... reusing it"
        exit 0
    fi
fi

# Discover kernel version and node distribution
KERNEL_VER=$(uname -r)

# Verify whether headers are already present (check if the symbolic link is present)
# If missing, install the headers using nsenter
if [ ! -d "/host/lib/modules/$KERNEL_VER/build/include" ]; then
    if ! nsenter --target 1 --mount -- sh -s < /opt/bpfima/scripts/init/install_kernel_devel.sh; then
        echo "Error: something went wrong during the headers installations"
        exit 1
    fi
else
    echo "Headers already present"
fi

# Store the directory where the headers are (depending on the distro)
if [ -d "/host/usr/src/kernels/$KERNEL_VER" ]; then
    export KERNEL_SRC="/host/usr/src/kernels/$KERNEL_VER"
elif [ -d "/host/usr/src/linux-headers-$KERNEL_VER" ]; then
    export KERNEL_SRC="/host/usr/src/linux-headers-$KERNEL_VER"
    ln -sf /host/usr/src/linux-headers-${KERNEL_VER%-*}-common /usr/src/linux-headers-${KERNEL_VER%-*}-common
else
    echo "Error: Headers not found $KERNEL_VER"
    exit 1
fi

# If missing, install the debug info and create the necessary symlink
if [ ! -f "/host/usr/lib/debug/boot/vmlinux-$KERNEL_VER" ] || [ -f "/host/usr/lib/debug/lib/modules/$KERNEL_VER/vmlinux" ]; then
    if ! nsenter --target 1 --mount -- sh -s < /opt/bpfima/scripts/init/install_debug_info.sh; then
        echo "Error: something went wrong during the debug info installations"
        exit 1
    fi
else
    echo "Debug info already present"
fi

ln -sf $(find /host/usr/lib/debug -name vmlinux -type f | head -1) $KERNEL_SRC/vmlinux
# Make, load and initialize the tool
cd /opt/bpfima
make modules KERNEL_SRC=$KERNEL_SRC KERNEL_HEADERS=$KERNEL_SRC
rm -f /host/lib/modules/$KERNEL_VER/build/vmlinux

# Load the module
insmod build/bpfima.ko tpm-pcr-index="${TPM_PCR}"
echo "Module inserted"
