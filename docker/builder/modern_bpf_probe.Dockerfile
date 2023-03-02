FROM ubuntu:22.04

LABEL name="sysdig/sysdig-skel-builder"
LABEL usage="docker run -v $PWD/..:/source -v $PWD/build:/build sysdig/sysdig-skel-builder cmake"

ARG BUILD_TYPE=release
ARG BUILD_DRIVER=OFF
ARG BUILD_BPF=OFF
ARG BUILD_VERSION=dev
ARG BUILD_WARNINGS_AS_ERRORS=OFF
ARG MAKE_JOBS=4

ENV BUILD_TYPE=${BUILD_TYPE}
ENV BUILD_DRIVER=${BUILD_DRIVER}
ENV BUILD_BPF=${BUILD_BPF}
ENV BUILD_VERSION=${BUILD_VERSION}
ENV BUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS}
ENV MAKE_JOBS=${MAKE_JOBS}

COPY ./root /

WORKDIR /

# build toolchain
RUN apt update && \
	apt install -y build-essential git curl wget clang llvm libelf-dev && \
	git clone https://github.com/libbpf/bpftool.git --branch v7.0.0 --single-branch && \
	cd bpftool && \
	git submodule update --init && \
	cd src && make install && rm -r /bpftool

# With some previous cmake versions it fails when downloading `zlib` with curl in the libs building phase
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.22.5/cmake-3.22.5-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.22.5-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-3.22.5-linux-$(uname -m)/

# DTS
ENTRYPOINT ["build"]
CMD ["usage"] 
