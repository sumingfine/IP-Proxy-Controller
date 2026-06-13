FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=2055 \
    DATABASE_PATH=/data/proxy_controller.sqlite3

WORKDIR /app

COPY src /app/src
COPY docker/controller /app/docker/controller

RUN set -eux; \
    mkdir -p /data

VOLUME ["/data"]
EXPOSE 2055

CMD ["python", "-u", "docker/controller/controller.py"]
