#!/bin/bash
#
# This script builds containers of kernel module builder, which is used to 
# compile the sysdig-probe and/or other probe modules.
# Generally, one build container for one family of linux distro.
#

SCRIPT_PATH="$(cd $(dirname ${BASH_SOURCE[0]} ) && pwd -P)"
pushd ${SCRIPT_PATH}

# Builder container for Fedora linux (including Fedora Atomic)
docker build -t fedora-builder:latest -f Dockerfiles/Dockerfile.fedora .

popd
