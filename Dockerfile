FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a
COPY observer.py /opt/observe/observer.py
USER 0:0
EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/python", "-B", "/opt/observe/observer.py"]
