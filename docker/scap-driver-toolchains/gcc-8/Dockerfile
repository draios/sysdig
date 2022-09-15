FROM ghcr.io/draios/scap-driver-toolchains-base:dev AS gcc-8

ARG MAKE_JOBS=4
ENV MAKE_JOBS=${MAKE_JOBS}

WORKDIR /src/gcc/8

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.gz{,.sig} \
	&& gpg --verify gcc-8.5.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-8.5.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-8 --enable-languages=c --disable-multilib \
	&& make -j ${MAKE_JOBS} \
	&& make install-strip


FROM registry.access.redhat.com/ubi8
COPY --from=gcc-8 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
