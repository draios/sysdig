FROM ghcr.io/draios/scap-driver-toolchains-base:dev AS gcc-10

ARG MAKE_JOBS=4
ENV MAKE_JOBS=${MAKE_JOBS}

WORKDIR /src/gcc/10

RUN curl --remote-name-all -L https://ftp.gnu.org/gnu/gcc/gcc-10.3.0/gcc-10.3.0.tar.gz{,.sig} \
	&& gpg --verify gcc-10.3.0.tar.gz.sig \
	&& tar --strip-components=1 -xf gcc-10.3.0.tar.gz \
	&& ./contrib/download_prerequisites

RUN ./configure --prefix=/opt/scap-driver-toolchains/gcc-10 --enable-languages=c --disable-multilib \
	&& make -j ${MAKE_JOBS} \
	&& make install-strip


FROM registry.access.redhat.com/ubi8
COPY --from=gcc-10 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
