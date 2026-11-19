# Digest is the multi-arch index for library/python:3.12-slim, taken from
# registry-1.docker.io Docker-Content-Digest (verified 2026-10-28).
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

# The dashboard listens on loopback. CMD below passes --host 127.0.0.1.
# Strict auth is the default, so this image needs a token even on loopback,
# not only for a non-loopback bind. A non-loopback address also needs
# `lantern web --allow-lan`. The token comes from LANTERN_API_TOKEN_FILE
# or LANTERN_API_TOKEN (at least 128 bits). This image does not contain a
# token. When stderr is not a terminal, Lantern does not print a generated
# token, because that stream is what `docker logs` stores. Without a token
# the process exits 2 and does not listen. Do not publish port 8068.
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
COPY .github/requirements-build.txt .github/requirements-build.txt
COPY lantern ./lantern

# Build tools are the hash-pinned set CI already uses (Gideon L-1).
# --no-build-isolation keeps pip from fetching an unpinned setuptools.
# --no-deps matches dependencies = [] in pyproject.toml. The tools are
# removed after the package is installed; they are not runtime deps.
RUN pip install --no-cache-dir --require-hashes -r .github/requirements-build.txt \
    && pip install --no-cache-dir --no-deps --no-build-isolation . \
    && pip uninstall -y build packaging pyproject_hooks setuptools wheel \
    && groupadd --system --gid 10001 lantern \
    && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home lantern \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 700 /data

VOLUME ["/data"]
EXPOSE 8068
# Alive means TCP accept on the dashboard port. The default is
# 127.0.0.1:8068, the same address as CMD. LANTERN_HEALTH_HOST and
# LANTERN_HEALTH_PORT override that pair when the listen port changes.
# The check does not send a token and does not add a route that skips auth.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import os,socket; host=os.environ.get('LANTERN_HEALTH_HOST','127.0.0.1'); port=int(os.environ.get('LANTERN_HEALTH_PORT','8068')); s=socket.create_connection((host, port), 2); s.close()"
USER lantern

CMD ["lantern", "web", "--host", "127.0.0.1", "--port", "8068", "--db", "/data/lantern.db"]
