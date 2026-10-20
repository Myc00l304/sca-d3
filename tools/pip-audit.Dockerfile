# Lokalny obraz pip-audit (brak oficjalnego obrazu). Wersja zapisywana w images.lock.
ARG BASE=python:3.12-slim-bookworm
FROM ${BASE}
ARG PIP_AUDIT_VERSION=2.10.1
RUN pip install --no-cache-dir "pip-audit==${PIP_AUDIT_VERSION}" && pip-audit --version > /pip-audit-version.txt
ENTRYPOINT ["pip-audit"]
