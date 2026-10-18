FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap \
    && chmod a-s /usr/bin/bwrap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 probe \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin probe
WORKDIR /opt/probe
COPY contract.py child.py probe.py server.py ./
RUN chmod 0555 /opt/probe && chmod 0444 /opt/probe/*.py
USER 10001:10001
EXPOSE 10000
CMD ["python", "-B", "/opt/probe/server.py"]
