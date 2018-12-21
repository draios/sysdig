#!/bin/sh

mkdir -p ${HOME}/.sysdig

docker build -t ebpf-probe-builder:latest --pull .
docker run --rm -it -v ${HOME}/.sysdig:/out -v /opt/draios/src/draios-agent-0.1.1dev:/driver -v /lib/modules/$(uname -r)/build:/kernel -v /:/host:ro -e BPF_PROBE_FILENAME=bpf_probe.o ebpf-probe-builder:latest

echo "Probe is in ${HOME}/.sysdig/"
