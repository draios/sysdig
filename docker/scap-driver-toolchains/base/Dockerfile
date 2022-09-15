FROM registry.access.redhat.com/ubi8

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
