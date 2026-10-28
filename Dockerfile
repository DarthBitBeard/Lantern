FROM python:3.12-slim

# The dashboard listens on loopback. CMD below passes --host 127.0.0.1.
# A non-loopback address needs `lantern web --allow-lan` and a startup
# token from LANTERN_API_TOKEN_FILE or LANTERN_API_TOKEN (at least 128
# bits). This image does not contain a token. When stderr is not a
# terminal, Lantern does not print a generated token, because that
# stream is what `docker logs` stores. Do not publish port 8068.
#
# The process is the non-root user lantern (uid/gid 10001). /data is the
# SQLite volume and is created owned by that user. A host directory mounted
# on /data must be writable by uid 10001 (see docker-compose.yml).
#
# Capabilities. Drop all of them. TCP connect scans and reading the host
# ARP cache (host networking) need none. ICMP ping needs CAP_NET_RAW plus
# a ping binary. This image does not install ping. Do not rely on a setuid
# or file-capability ping: the recommended `no-new-privileges` option
# ignores both. Add NET_RAW back only in a derived image that ships ping.
#
# Recommended runtime, which docker-compose.yml sets:
#   --cap-drop ALL
#   --read-only
#   --tmpfs /tmp
#   --security-opt no-new-privileges
#   and a writable volume at /data
# Host networking is for scanning the host LAN, not for exposing the dashboard.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY lantern ./lantern

RUN pip install --no-cache-dir . \
    && groupadd --system --gid 10001 lantern \
    && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home lantern \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 700 /data

VOLUME ["/data"]
EXPOSE 8068
USER lantern

CMD ["lantern", "web", "--host", "127.0.0.1", "--port", "8068", "--db", "/data/lantern.db"]
