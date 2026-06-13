FROM debian:12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    LANG=C.UTF-8

RUN set -eux; \
    apt-get update -q; \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      iproute2 \
      iptables \
      iputils-ping \
      openvpn \
      procps \
      psmisc \
      python3; \
    rm -rf /var/lib/apt/lists/*

COPY docker/agent/entrypoint.sh /usr/local/bin/proxy-agent-entrypoint

RUN set -eux; \
    chmod +x /usr/local/bin/proxy-agent-entrypoint; \
    mkdir -p /opt/proxy_lite/configs

WORKDIR /opt/proxy_lite

ENTRYPOINT ["proxy-agent-entrypoint"]
