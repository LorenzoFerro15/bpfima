#!/bin/bash

set -e

# Discover kernel version and node distribution
KERNEL=$(uname -r)
ARCH=$(uname -m)
TEMP=${KERNEL%.*}
VERSION=${TEMP%%-*}
RELEASE=${TEMP#*-}
NODE_DISTRO=$(grep -h "^ID=" /etc/*-release | head -n1 | cut -d= -f2 | tr -d '"')

# Download the correct kernel headers depending on the running system
# For now, only fedora, debian and ubuntu distributions are supported
case "$NODE_DISTRO" in
    ubuntu|debian)
        apt-get update && apt-get install -y --no-install-recommends linux-headers-$KERNEL
        ;;
    fedora)
        if ! dnf -q -y install kernel-devel-${KERNEL} > /dev/null; then
            echo "Failed to find kernel-devel-${KERNEL} in repositories."
            KOJI_KERNEL_DEVEL_URL=https://kojipkgs.fedoraproject.org/packages/kernel/$VERSION/$RELEASE/$ARCH/kernel-devel-$KERNEL.rpm
            echo "Trying to download kernel-devel from koji: $KOJI_KERNEL_DEVEL_URL..."
            if ! dnf -q -y install $KOJI_KERNEL_DEVEL_URL --setopt=install_weak_deps=False; then
                echo "Can't find kernel-devel-${KERNEL}"
                echo "Please try to update your kernel on the host system."
                exit 1
            fi
        fi
        ;;
    *)
        echo "Error: '$NODE_DISTRO' not supported."
        echo "Please try to install the suitable kernel headers on the host system."
        exit 1
        ;;
esac


# Create the symbolic link to /lib/modules/$KERNEL if not present
# It's used during the modules make to find the headers
# if [ ! -L "/lib/modules/$KERNEL/build" ]; then
#    mkdir -p /lib/modules/$KERNEL
#    cd /lib/modules/$KERNEL
#    if [ -d "/usr/src/kernels/$KERNEL" ]; then
#        DIR="../../../usr/src/kernels/$KERNEL"
#    elif [ -d "/usr/src/linux-headers-$KERNEL" ]; then
#        DIR="../../../usr/src/linux-headers-$KERNEL"
#    else
#        echo "Error: Headers not found $KERNEL"
#        exit 1
#    fi
#    ln -sf "$DIR" "build"
#fi