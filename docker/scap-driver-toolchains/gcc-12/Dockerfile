FROM ghcr.io/draios/scap-driver-toolchains-base:dev AS gcc-12

ARG MAKE_JOBS=4
ENV MAKE_JOBS=${MAKE_JOBS}

WORKDIR /src/gcc/12

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-12.2.0/gcc-12.2.0.tar.gz{,.sig} \
	&& gpg --verify gcc-12.2.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-12.2.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-12 --enable-languages=c --disable-multilib \
	&& make -j ${MAKE_JOBS} \
	&& make install-strip


FROM registry.access.redhat.com/ubi8
COPY --from=gcc-12 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
