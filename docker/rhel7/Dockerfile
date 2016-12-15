FROM registry.access.redhat.com/rhel7.2:latest 

MAINTAINER Sysdig <support@sysdig.com>

ENV SYSDIG_REPOSITORY stable

LABEL RUN="docker run --privileged -i -t -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro --name NAME IMAGE"

ENV SYSDIG_HOST_ROOT /host

ENV HOME /root

ADD http://download.draios.com/${SYSDIG_REPOSITORY}/rpm/draios.repo /etc/yum.repos.d/draios.repo

RUN rpm --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public

RUN rpm -Uvh http://mirrors.kernel.org/fedora-epel/7/x86_64/e/epel-release-7-8.noarch.rpm

# We delete everything on /usr/src/kernels otherwise
# it messes up docker-entrypoint.sh
RUN yum -y --enablerepo=epel install gcc dkms sysdig && \
	rpm --nodeps -e kernel-devel kernel-headers && \
	rm -fr /usr/src/kernels && \
	yum clean all

RUN ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["bash"]
