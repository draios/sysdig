FROM oraclelinux:7

RUN yum -y install \
    wget \
    git \
    gcc \
    gcc-c++ \
    make \
    cmake \
    libdtrace-ctf \
    python-lxml && yum clean all

WORKDIR /build

# Use the same directory structure as the jenkins worker
RUN mkdir -p sysdig/scripts
ADD oracle-kernel-crawler.py sysdig/scripts/
ADD build-probe-binaries sysdig/scripts/

WORKDIR probe

ENTRYPOINT [ "../sysdig/scripts/build-probe-binaries" ]
