FROM debian:wheezy

MAINTAINER Sysdig <support@sysdigcloud.com>

ENV REPO cgroups
ENV AGENT_VERSION 0.99.35
ENV SYSDIG_VERSION 0.99.35

ENV SYSDIG_HOST_ROOT /host

RUN apt-get update \
 && apt-get install -y curl

RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/$REPO/deb/draios.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends draios-agent=$AGENT_VERSION sysdig=$SYSDIG_VERSION \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
