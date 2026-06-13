FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATABASE_PATH=/data/proxy_controller.sqlite3

WORKDIR /app

COPY src /app/src
COPY docker/controller /app/docker/controller

RUN set -eux; \
    mkdir -p /data

VOLUME ["/data"]
EXPOSE 8080

CMD ["python", "-u", "docker/controller/controller.py"]
