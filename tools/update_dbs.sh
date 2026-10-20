#!/usr/bin/env bash
# Aktualizuje bazy podatności Trivy i Grype (Dependency-Check: dc_update.sh).
# Skany korzystają potem wyłącznie z pobranych baz (bez aktualizacji w trakcie serii),
# co zapewnia jednakowy stan baz dla wszystkich projektów jednej serii.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
echo "[trivy] baza podatności i baza Java" >&2
docker run --rm --user "$DOCKER_USER" -e HOME=/tmp -e TRIVY_CACHE_DIR=/cache \
  -v "$CACHE_ROOT/trivy:/cache" "$(image trivy)" image --download-db-only
docker run --rm --user "$DOCKER_USER" -e HOME=/tmp -e TRIVY_CACHE_DIR=/cache \
  -v "$CACHE_ROOT/trivy:/cache" "$(image trivy)" image --download-java-db-only
echo "[grype] baza podatności" >&2
docker run --rm --user "$DOCKER_USER" -e GRYPE_DB_CACHE_DIR=/cache -e TMPDIR=/tmp \
  -v "$CACHE_ROOT/tmp:/tmp" -v "$CACHE_ROOT/grype:/cache" "$(image grype)" db update -v
docker run --rm --user "$DOCKER_USER" -e GRYPE_DB_CACHE_DIR=/cache \
  -v "$CACHE_ROOT/grype:/cache" "$(image grype)" db status
