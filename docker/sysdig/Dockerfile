FROM ghcr.io/draios/sysdig-builder:dev AS builder

ARG BUILD_VERSION=0.1.1dev
ENV BUILD_VERSION=${BUILD_VERSION}

WORKDIR /source

COPY . /source/sysdig

RUN if [ -d /source/sysdig/falcosecurity-libs ]; then ln -s /source/sysdig/falcosecurity-libs /source/libs; fi

RUN INSTALL_PREFIX=/opt/sysdig build cmake
RUN build install

FROM registry.access.redhat.com/ubi8/ubi

RUN yum -y install \
    make \
    kmod \
    gcc \
    clang \
    llvm-toolset

RUN mkdir -p /tmp/dkms \
    && cd /tmp/dkms \
    && curl --remote-name-all -L https://github.com/dell/dkms/archive/refs/tags/v2.8.5.tar.gz \
    && tar --strip-components=1 -xf v2.8.5.tar.gz \
    && make tarball \
    && make install \
    && cd /tmp \
    && rm -fr /tmp/dkms

COPY --from=builder /opt/sysdig /opt/sysdig
RUN for b in /opt/sysdig/bin/*; do ln -s "$b" /usr/bin/$(basename "$b"); done \
    && for b in /opt/sysdig/src/*; do ln -s "$b" /usr/src/$(basename "$b"); done

COPY docker/sysdig/docker-entrypoint.sh /

ENV HOST_ROOT /host
ENV SYSDIG_HOST_ROOT /host

RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["bash"]
