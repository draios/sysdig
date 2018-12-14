FROM debian:unstable

MAINTAINER Sysdig <support@sysdig.com>

ENV SYSDIG_HOST_ROOT /host

ENV AGENT_VERSION 0.1.1dev

ENV SYSDIG_SRC /draios

ENV HOME /root

ENV CXX /usr/bin/g++

# Based on the sysdig container, used for building eBPF probe

RUN apt-get update \
 && apt-get dist-upgrade -y \
 && apt-get install -y --no-install-recommends \
    apt-utils \
    cmake \
	ca-certificates \
	bzip2 \
	clang-7 \
	gcc \
	g++ \
	libc6-dev \
	libelf-dev \
	libelf1 \
	llvm-7 \
	make \
	xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Use clang-7 as the default clang
RUN rm -rf /usr/bin/clang \
 && rm -rf /usr/bin/llc \
 && ln -s /usr/bin/clang-7 /usr/bin/clang \
 && ln -s /usr/bin/llc-7 /usr/bin/llc

RUN rm -df /lib/modules \
 && ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

COPY ./probe-builder-entrypoint.sh /

ENTRYPOINT ["/probe-builder-entrypoint.sh"]
