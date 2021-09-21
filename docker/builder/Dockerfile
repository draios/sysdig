FROM registry.access.redhat.com/ubi8

LABEL name="sysdig/builder"
LABEL usage="docker run -v $PWD/..:/source -v $PWD/build:/build sysdig/sysdig-builder cmake"

ARG BUILD_TYPE=release
ARG BUILD_DRIVER=OFF
ARG BUILD_BPF=OFF
ARG BUILD_WARNINGS_AS_ERRORS=ON
ARG MAKE_JOBS=4

ENV BUILD_TYPE=${BUILD_TYPE}
ENV BUILD_DRIVER=${BUILD_DRIVER}
ENV BUILD_BPF=${BUILD_BPF}
ENV BUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS}
ENV MAKE_JOBS=${MAKE_JOBS}

RUN yum -y install \
    gcc \
    gcc-c++ \
    make \
    autoconf \
    automake \
    pkg-config \
    patch \
    libtool \
    cmake \
    llvm-toolset \
    diffutils \
    zlib-devel \
    bzip2 \
    cmake \
    clang \
    git

RUN gpg --batch --keyserver keyserver.ubuntu.com --recv-keys \
    12768A96795990107A0D2FDFFC57E3CCACD99A78

WORKDIR /src/elfutils
RUN curl --remote-name-all -L https://sourceware.org/elfutils/ftp/0.185/elfutils-0.185.tar.bz2{,.sig} \
    && gpg --verify elfutils-0.185.tar.bz2.sig \
    && tar --strip-components=1 -xf elfutils-0.185.tar.bz2 \
    && rm elfutils-0.185.tar.bz2 \
    && ./configure --enable-libdebuginfod=dummy --disable-debuginfod \
    && make \
    && make install-strip

COPY ./root /

WORKDIR /

ENTRYPOINT ["build"]
CMD ["usage"]
