FROM debian:wheezy

MAINTAINER Sysdig <support@sysdigcloud.com>

ENV REPO cgroups
ENV SYSDIG_VERSION 0.99.41

ENV SYSDIG_HOST_ROOT /host

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
 && apt-get install -y bash-completion curl

RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/$REPO/deb/draios.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends sysdig=$SYSDIG_VERSION \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["bash"]
