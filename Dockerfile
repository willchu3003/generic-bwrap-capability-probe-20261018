# Preparation artifact only. Building/running requires the main conversation's
# separate fixed-package/service/publication decision and zero-spend evidence.
FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a
RUN apt-get update && apt-get install -y --no-install-recommends \
    s6=2.11.3.2-1 util-linux=2.38.1-5+deb12u3 \
    libseccomp2=2.5.4-1+deb12u1 libcap2=1:2.66-4+deb12u3+b1 \
    && rm -rf /var/lib/apt/lists/*
COPY --chown=0:0 . /opt/probe/
RUN python -B /opt/probe/build_layout.py
ENV PYTHONDONTWRITEBYTECODE=1
USER 0:0
EXPOSE 10000
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "/usr/local/bin/python", "-B", "/opt/probe/entry.py"]
