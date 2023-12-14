FROM registry.access.redhat.com/ubi8/ubi

LABEL maintainer="Sysdig <support@sysdig.com>"
LABEL usage="docker run --rm -i -t --privileged --net=host -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /src:/src -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --name NAME IMAGE"

ARG VERSION=0.34.1
ENV VERSION=${VERSION}

ENV HOST_ROOT /host
ENV HOME /root

RUN yum -y install \
		make \
		kmod \
		gcc \
		clang \
		llvm-toolset \
		less \
	&& mkdir -p /tmp/dkms \
	&& cd /tmp/dkms \
	&& curl --remote-name-all -L https://github.com/dell/dkms/archive/refs/tags/v2.8.5.tar.gz \
	&& tar --strip-components=1 -xf v2.8.5.tar.gz \
	&& make tarball \
	&& make install \
	&& cd /tmp \
	&& rm -fr /tmp/dkms \
	&& curl -L -o sysdig.rpm "https://github.com/draios/sysdig/releases/download/${VERSION}/sysdig-${VERSION}-x86_64.rpm" \
	&& rpm --nodeps --force -i ./sysdig.rpm \
	&& rm ./sysdig.rpm \
	&& rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

COPY docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["bash"]
