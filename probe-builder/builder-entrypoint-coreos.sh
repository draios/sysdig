#!/bin/bash

# required env vars:
# HASH
# HASH_ORIG
# KERNELDIR
# KERNEL_RELEASE
# OUTPUT
# DRIVER_DEVICE_NAME
# DRIVER_NAME
# DRIVER_VERSION

set -euo pipefail

ARCH=$(uname -m)

if [[ -f "${KERNELDIR}/scripts/gcc-plugins/stackleak_plugin.so" ]]; then
	echo "Rebuilding gcc plugins for ${KERNELDIR}"
	(cd "${KERNELDIR}" && make gcc-plugins)
fi

(cd $KERNELDIR && make modules_prepare)

echo Building $DRIVER_NAME-$DRIVER_VERSION-$ARCH-$KERNEL_RELEASE-$HASH.ko

mkdir -p /build/sysdig
cd /build/sysdig

cmake -DCMAKE_BUILD_TYPE=Release -DDRIVER_NAME=$DRIVER_NAME -DDRIVER_VERSION=$DRIVER_VERSION -DDRIVER_DEVICE_NAME=$DRIVER_DEVICE_NAME -DCREATE_TEST_TARGETS=OFF /build/probe/sysdig
make driver
strip -g driver/$DRIVER_NAME.ko

KO_VERSION=$(/sbin/modinfo driver/$DRIVER_NAME.ko | grep vermagic | tr -s " " | cut -d " " -f 2)
if [ "$KO_VERSION" != "$KERNEL_RELEASE" ]; then
	echo "Corrupted driver, KO_VERSION " $KO_VERSION ", KERNEL_RELEASE " $KERNEL_RELEASE
	exit 1
fi

cp driver/$DRIVER_NAME.ko $OUTPUT/$DRIVER_NAME-$DRIVER_VERSION-$ARCH-$KERNEL_RELEASE-$HASH.ko
cp driver/$DRIVER_NAME.ko $OUTPUT/$DRIVER_NAME-$DRIVER_VERSION-$ARCH-$KERNEL_RELEASE-$HASH_ORIG.ko

