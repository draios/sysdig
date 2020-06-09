FROM debian:unstable

MAINTAINER Sysdig <support@sysdig.com>

# Based on the sysdig container, used for building eBPF probe

RUN apt-get update \
 && apt-get dist-upgrade -y \
 && apt-get install -y --no-install-recommends \
	clang \
	gcc \
	libelf-dev \
	libelf1 \
	llvm \
	make \
 && rm -rf /var/lib/apt/lists/*

COPY ./probe-builder-entrypoint.sh /

ENTRYPOINT ["/probe-builder-entrypoint.sh"]
