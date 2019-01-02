#!/bin/sh

set -euo pipefail

# Defaults
DRIVER_DIR=/opt/draios/src/draios-agent-0.1.1dev
KERNEL_DIR=/lib/modules/$(uname -r)/build
OUT_DIR=${HOME}/.sysdig

usage()
{
	echo "build_bpf_probe [-d <driver_path>] [-k <kernel_path>] [-o <output_path>]"
}

# Options parsing
while [ -n "${1-}" ]; do
	case $1 in
	-d | --driver )    shift
	                   DRIVER_DIR=$1
	                   ;;
	-k | --kernel )    shift
	                   KERNEL_DIR=$1
	                   ;;
	-o | --output )    shift
	                   OUT_DIR=$1
	                   ;;
	-h | --help )      usage
	                   exit
	                   ;;
	* )                usage
	                   exit 1
	                   ;;
	esac
	shift
done

mkdir -p ${HOME}/.sysdig

docker build -t ebpf-probe-builder:latest --pull .
docker run --rm -it -v ${OUT_DIR}:/out -v ${DRIVER_DIR}:/driver -v ${KERNEL_DIR}:/kernel -e BPF_PROBE_FILENAME=bpf_probe.o ebpf-probe-builder:latest

echo "Probe is in ${OUT_DIR}/"
