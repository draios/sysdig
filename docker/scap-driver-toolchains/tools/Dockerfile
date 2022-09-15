FROM ghcr.io/draios/scap-driver-toolchains-base:dev AS tools

ARG MAKE_JOBS=4
ENV MAKE_JOBS=${MAKE_JOBS}

WORKDIR /src/binutils

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.gz{,.sig} \
	&& gpg --verify binutils-2.30.tar.gz.sig \
	&& tar --strip-components=1 -xf binutils-2.30.tar.gz

RUN ./configure --prefix=/opt/scap-driver-toolchains/binutils-2.30 \
	&& make -j ${MAKE_JOBS} \
	&& make install-strip

WORKDIR /src/dkms

RUN curl --remote-name-all -L https://github.com/dell/dkms/archive/refs/tags/v2.8.5.tar.gz \
	&& tar --strip-components=1 -xf v2.8.5.tar.gz \
	&& make -j ${MAKE_JOBS} tarball \
	&& make install DESTDIR=/opt/scap-driver-toolchains/dkms


FROM registry.access.redhat.com/ubi8
COPY --from=tools /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
