FROM registry.access.redhat.com/ubi8/ubi

LABEL usage="docker run --rm -i -t --privileged --net=host -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /src:/src -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --name NAME IMAGE"

ARG BUILD_VERSION=0.1.1dev
ENV BUILD_VERSION=${BUILD_VERSION}

ENV HOST_ROOT /host
ENV HOME /root

RUN yum -y install \
    make \
    kmod \
    gcc \
    clang \
    llvm-toolset \
    less

RUN mkdir -p /tmp/dkms \
    && cd /tmp/dkms \
    && curl --remote-name-all -L https://github.com/dell/dkms/archive/refs/tags/v2.8.5.tar.gz \
    && tar --strip-components=1 -xf v2.8.5.tar.gz \
    && make tarball \
    && make install \
    && cd /tmp \
    && rm -fr /tmp/dkms

COPY ./sysdig-${BUILD_VERSION}-*.rpm /

RUN rpm --nodeps --force -i /sysdig-${BUILD_VERSION}-$(uname -p).rpm && rm /sysdig-*.rpm

COPY docker/sysdig/docker-entrypoint.sh /

RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["bash"]
