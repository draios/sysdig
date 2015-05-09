FROM debian:unstable

MAINTAINER Sysdig <support@sysdigcloud.com>

ENV SYSDIG_REPOSITORY stable

ENV SYSDIG_HOST_ROOT /host

ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
	bash-completion \
	curl \
	ca-certificates \
	gcc \
	gcc-4.8

RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/$SYSDIG_REPOSITORY/deb/draios.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends sysdig \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["bash"]
