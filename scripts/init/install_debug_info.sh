#!/bin/bash

set -e

# Discover kernel version and node distribution
KERNEL=$(uname -r)
ARCH=$(uname -m)
TEMP=${KERNEL%.*}
VERSION=${TEMP%%-*}
RELEASE=${TEMP#*-}
NODE_DISTRO=$(grep -h "^ID=" /etc/*-release | head -n1 | cut -d= -f2 | tr -d '"')

# Download the correct kernel debuginfo depending on the running system
# For now, only fedora, debian and ubuntu distributions are supported
case "$NODE_DISTRO" in
    ubuntu|debian)
        apt-get update && apt-get install -y --no-install-recommends linux-image-$KERNEL-dbg
        ;;
    fedora)
        if ! dnf -q -y install kernel-debuginfo-${KERNEL} > /dev/null; then
            echo "Failed to find kernel-debuginfo-${KERNEL} in repositories."
            KOJI_KERNEL_DEBUGINFO_URL=https://kojipkgs.fedoraproject.org/packages/kernel/$VERSION/$RELEASE/$ARCH/kernel-debuginfo-$KERNEL.rpm
            KOJI_KERNEL_DEBUGINFO_COMMON_URL=https://kojipkgs.fedoraproject.org/packages/kernel/$VERSION/$RELEASE/$ARCH/kernel-debuginfo-common-$ARCH-$KERNEL.rpm
            echo "Trying to download kernel-debuginfo from koji: $KOJI_KERNEL_DEBUGINFO_URL..."
            if ! dnf -q -y install $KOJI_KERNEL_DEBUGINFO_URL $KOJI_KERNEL_DEBUGINFO_COMMON_URL --setopt=install_weak_deps=False; then
                echo "Can't find kernel-debuginfo-${KERNEL}"
                echo "Please try to update your kernel on the host system."
                exit 1
            fi
        fi
        ;;
    *)
        echo "Error: '$NODE_DISTRO' not supported."
        echo "Please try to install the suitable kernel debiginfo on the host system."
        exit 1
        ;;
esac

