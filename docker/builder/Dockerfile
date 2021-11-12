FROM registry.access.redhat.com/ubi8

LABEL name="sysdig/builder"
LABEL usage="docker run -v $PWD/..:/source -v $PWD/build:/build sysdig/sysdig-builder cmake"

ARG BUILD_TYPE=release
ARG BUILD_DRIVER=OFF
ARG BUILD_BPF=OFF
ARG BUILD_VERSION=dev
ARG BUILD_WARNINGS_AS_ERRORS=ON
ARG MAKE_JOBS=4

ENV BUILD_TYPE=${BUILD_TYPE}
ENV BUILD_DRIVER=${BUILD_DRIVER}
ENV BUILD_BPF=${BUILD_BPF}
ENV BUILD_VERSION=${BUILD_VERSION}
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
    git \
    file \
    xz \
    perl \
    rpm-build \
    rsync

RUN curl -O -L https://mirrors.ocf.berkeley.edu/gnu/gnu-keyring.gpg \
	&& gpg -q --import gnu-keyring.gpg

RUN gpg --batch --keyserver keyserver.ubuntu.com --recv-keys \
    12768A96795990107A0D2FDFFC57E3CCACD99A78

RUN mkdir -p /usr/share/debian-keyrings \
    && rsync -az --progress keyring.debian.org::keyrings/keyrings/ /usr/share/debian-keyrings

WORKDIR /src
RUN mkdir /src/elfutils \
    && cd /src/elfutils \ 
    && curl --remote-name-all -L https://sourceware.org/elfutils/ftp/0.185/elfutils-0.185.tar.bz2{,.sig} \
    && gpg --verify elfutils-0.185.tar.bz2.sig \
    && tar --strip-components=1 -xf elfutils-0.185.tar.bz2 \
    && ./configure --enable-libdebuginfod=dummy --disable-debuginfod \
    && make \
    && make install-strip \
    && rm -fr /src/elfutils

# needed for dpkg autogen
RUN mkdir /src/gettext \
    && cd /src/gettext \ 
    && curl --remote-name-all -L https://ftp.gnu.org/pub/gnu/gettext/gettext-0.21.tar.gz{,.sig} \
    && gpg --verify gettext-0.21.tar.gz.sig \
    && tar --strip-components=1 -xf gettext-0.21.tar.gz \
    && ./configure \
    && make \
    && make install-strip \
    && rm -fr /src/gettext

RUN mkdir /src/dpkg \
    && cd /src/dpkg \
    && curl --remote-name-all -L http://deb.debian.org/debian/pool/main/d/dpkg/dpkg_1.20.9{.tar.xz,.dsc} \
    && gpg --keyring /usr/share/debian-keyrings/debian-keyring.gpg --verify ./dpkg_1.20.9.dsc \
    && SIGNED_CHECKSUM=$(grep Checksums-Sha256 -A 1 dpkg_1.20.9.dsc | grep dpkg_1.20.9.tar.xz | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | cut -d ' ' -f 1) \
    && ACTUAL_CHECKSUM=$(sha256sum ./dpkg_1.20.9.tar.xz | cut -d ' ' -f 1) \
    && [[ $SIGNED_CHECKSUM == $ACTUAL_CHECKSUM ]] \
    && tar --strip-components=1 -xf dpkg_1.20.9.tar.xz \
    && ./autogen \
    && ./configure --disable-dselect --disable-start-stop-daemon --disable-update-alternatives \
    && make install-strip \
    && rm -fr /src/dpkg

COPY ./root /

WORKDIR /

ENTRYPOINT ["build"]
CMD ["usage"]
