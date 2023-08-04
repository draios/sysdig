FROM centos:7

LABEL name="sysdig/sysdig-builder"
LABEL usage="docker run -v $PWD/..:/source -v $PWD/build:/build sysdig/sysdig-builder cmake"

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
RUN yum -y install centos-release-scl; \
    yum -y install devtoolset-9-gcc devtoolset-9-gcc-c++ git wget make m4 rpm-build clang perl-IPC-Cmd ; \
	source scl_source enable devtoolset-9

# With some previous cmake versions it fails when downloading `zlib` with curl in the libs building phase
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.22.5/cmake-3.22.5-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.22.5-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-3.22.5-linux-$(uname -m)/

# DTS
ENV BASH_ENV=/usr/bin/scl_enable \
    ENV=/usr/bin/scl_enable \
    PROMPT_COMMAND=". /usr/bin/scl_enable"

ENTRYPOINT ["build"]
CMD ["usage"]
