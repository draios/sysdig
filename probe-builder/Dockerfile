FROM centos:7

RUN yum -y install \
	curl \
	dpkg-deb \
	epel-release \
	git \
	jq \
	kpartx \
	python-lxml \
	wget \
	&& yum -y install jq \
	&& yum clean all

RUN curl -fsSL https://get.docker.io | bash

ADD . /builder
WORKDIR /builder
ENTRYPOINT [ "/builder/main-builder-entrypoint.sh" ]
