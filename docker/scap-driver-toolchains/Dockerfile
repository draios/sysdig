FROM registry.access.redhat.com/ubi8 AS base

RUN yum update \
	&& yum install -y gcc \
	gcc-c++ \
	make \
	cmake \
	xz \
	curl \
	python3 \
	gnupg \
	diffutils \
	wget \
	bzip2

RUN curl -O -L https://mirrors.ocf.berkeley.edu/gnu/gnu-keyring.gpg \
	&& gpg -q --import gnu-keyring.gpg

RUN gpg --batch --keyserver keyserver.ubuntu.com --recv-keys A2C794A986419D8A

FROM base AS tools

WORKDIR /src/binutils

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.gz{,.sig} \
	&& gpg --verify binutils-2.30.tar.gz.sig \
	&& tar --strip-components=1 -xf binutils-2.30.tar.gz

RUN ./configure --prefix=/opt/scap-driver-toolchains/binutils-2.30 \
	&& make \
	&& make install-strip

WORKDIR /src/dkms

RUN curl --remote-name-all -L https://github.com/dell/dkms/archive/refs/tags/v2.8.5.tar.gz \
	&& tar --strip-components=1 -xf v2.8.5.tar.gz \
 	&& make tarball \
 	&& make install DESTDIR=/opt/scap-driver-toolchains/dkms

FROM base AS llvm-7

WORKDIR /src/llvm/7

RUN curl --remote-name-all -L https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/cfe-7.1.0.src.tar.xz{,.sig} \
	https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/llvm-7.1.0.src.tar.xz{,.sig} \
	&& gpg --verify cfe-7.1.0.src.tar.xz.sig \
	&& gpg --verify llvm-7.1.0.src.tar.xz.sig \
	&& tar -xf llvm-7.1.0.src.tar.xz \
	&& tar -xf cfe-7.1.0.src.tar.xz \
	&& mv cfe-7.1.0.src clang

WORKDIR /src/llvm/7/build

RUN cmake -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_INSTALL_PREFIX=/opt/scap-driver-toolchains/llvm-7 -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_CXX_FLAGS='-static-libgcc' -G "Unix Makefiles" ../llvm-7.1.0.src \
	&& make \
	&& make install/strip

FROM base AS gcc-5

WORKDIR /src/gcc/5

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-5.5.0/gcc-5.5.0.tar.gz{,.sig} \
	&& gpg --verify gcc-5.5.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-5.5.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-5 --enable-languages=c --disable-libsanitizer --disable-multilib \
	&& make \
	&& make install-strip

FROM base AS gcc-6

WORKDIR /src/gcc/6

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-6.5.0/gcc-6.5.0.tar.gz{,.sig} \
	&& gpg --verify gcc-6.5.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-6.5.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-6 --enable-languages=c --disable-libsanitizer --disable-multilib \
	&& make \
	&& make install-strip

FROM base AS gcc-7

WORKDIR /src/gcc/7

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-7.5.0/gcc-7.5.0.tar.gz{,.sig} \
	&& gpg --verify gcc-7.5.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-7.5.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-7 --enable-languages=c --disable-libsanitizer --disable-multilib \
	&& make \
	&& make install-strip

FROM base AS gcc-8

WORKDIR /src/gcc/8

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.gz{,.sig} \
	&& gpg --verify gcc-8.5.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-8.5.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-8 --enable-languages=c --disable-multilib \
	&& make \
	&& make install-strip

FROM base AS gcc-9

WORKDIR /src/gcc/9

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-9.4.0/gcc-9.4.0.tar.gz{,.sig} \
	&& gpg --verify gcc-9.4.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-9.4.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-9 --enable-languages=c --disable-multilib \
	&& make \
	&& make install-strip

FROM base AS gcc-10

WORKDIR /src/gcc/10

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-10.3.0/gcc-10.3.0.tar.gz{,.sig} \
	&& gpg --verify gcc-10.3.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-10.3.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-10 --enable-languages=c --disable-multilib \
	&& make \
	&& make install-strip

FROM registry.access.redhat.com/ubi8

COPY --from=tools /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=llvm-7 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=gcc-5 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=gcc-6 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=gcc-7 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=gcc-8 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=gcc-9 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
COPY --from=gcc-10 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/

