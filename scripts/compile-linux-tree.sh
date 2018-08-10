#!/bin/bash
#
# This script tries to compile the sysdig probes against all the stable kernel
# releases that match a specific pattern.
#
# Usage:
#
# compile-linux-tree.sh SYSDIG_SOURCE_DIRECTORY LINUX_TREE PATTERN1 PATTERN2 ...
#
# Example:
#
# compile-linux-tree.sh ~/sysdig_src ~/linux_tree 'v4.1[4-9]*'
#
set -uo pipefail

SYSDIG_SRC_DIR=$1
LINUX_TREE=$2
shift 2
PATTERNS=$@

export KERNELDIR=$LINUX_TREE

cd "$LINUX_TREE"

TAGS=$(git tag -l $PATTERNS | sort -V)

echo "Processing the following versions: $TAGS"

for tag in $TAGS
do
        cd "$LINUX_TREE"
        git checkout "$tag" &> /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (git)"
                continue
        fi

        make distclean &> /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (make distclean)"
                continue
        fi

        make defconfig &> /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (make defconfig)"
                continue
        fi

        make modules_prepare &> /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (make modules_prepare)"
                continue
        fi

        cd "$SYSDIG_SRC_DIR"

        make -C driver/bpf clean &> /dev/null
        rm -rf build

        mkdir build
        cd build
        cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_BPF=ON .. > /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (cmake)"
                continue
        fi

        make driver VERBOSE=1 > /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (driver)"
                continue
        fi

        make bpf VERBOSE=1 > /dev/null
        if [ $? -ne 0 ]; then
                echo "$tag -> failure (bpf)"
                continue
        fi

        echo "$tag -> success"
done

echo "All done"
