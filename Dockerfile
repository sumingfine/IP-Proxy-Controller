FROM debian:12-slim

ENV HOST=0.0.0.0 \
    PORT=8080 \
    DATABASE_PATH=/data/proxy_controller.sqlite3 \
    WORKSPACE=/opt/proxy_lite \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    LANG=C.UTF-8

WORKDIR /app

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
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /data /opt/proxy_lite/configs

COPY src /app/src
COPY docker/controller /app/docker/controller
COPY docker/agent/entrypoint.sh /usr/local/bin/proxy-agent-entrypoint
COPY docker/all-in-one/entrypoint.sh /usr/local/bin/koyeb-all-in-one-entrypoint

RUN set -eux; \
    chmod +x /usr/local/bin/proxy-agent-entrypoint /usr/local/bin/koyeb-all-in-one-entrypoint

VOLUME ["/data", "/opt/proxy_lite"]
EXPOSE 8080 7920

ENTRYPOINT ["koyeb-all-in-one-entrypoint"]
