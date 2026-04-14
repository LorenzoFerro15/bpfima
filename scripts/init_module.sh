#!/bin/bash

set -e

# Discover kernel version and node distribution
KERNEL_VER=$(uname -r)

# Verify whether headers are already present (check if the symbolic link is present)
# If missing, install the headers using nsenter
if [ ! -d "/host/lib/modules/$KERNEL_VER/build/include" ]; then
    if ! nsenter --target 1 --mount -- sh -s < /opt/bpfima/scripts/install_kernel_devel.sh; then
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
    if ! nsenter --target 1 --mount -- sh -s < /opt/bpfima/scripts/install_debug_info.sh; then
        echo "Error: something went wrong during the debug info installations"
        exit 1
    fi
else
    echo "Debug info already present"
fi

ln -sf $(find /host/usr/lib/debug -name vmlinux -type f | head -1) $KERNEL_SRC/vmlinux
# Make, load and initialize the tool
cd /opt/bpfima
make all KERNEL_SRC=$KERNEL_SRC KERNEL_HEADERS=$KERNEL_SRC
rm -f /host/lib/modules/$KERNEL_VER/build/vmlinux

# Unload the module if already present
if cat /proc/modules | grep bpfima; then
    rmmod bpfima
fi

insmod build/bpfima.ko
echo "Module inserted"

./build/bpfima-tool load build/lsm_bprm_check_security.o -d
./build/bpfima-tool policy-init
echo "eBPF program loaded and maps initialized"

sleep infinity