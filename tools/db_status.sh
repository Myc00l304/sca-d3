#!/usr/bin/env bash
# Zapisuje stan baz podatności narzędzi (wersje, daty) do pliku JSON.
#   db_status.sh <plik_wyjściowy.json>
set -uo pipefail
source "$(dirname "$0")/lib.sh"
out="$(realpath -m "$1")"
{
  echo "=== trivy"; docker run --rm --user "$DOCKER_USER" -e TRIVY_CACHE_DIR=/cache \
    -v "$CACHE_ROOT/trivy:/cache" "$(image trivy)" --version 2>&1
  echo "=== grype"; docker run --rm --user "$DOCKER_USER" -e GRYPE_DB_CACHE_DIR=/cache -e TMPDIR=/tmp -v "$CACHE_ROOT/tmp:/tmp" \
    -v "$CACHE_ROOT/grype:/cache" "$(image grype)" db status 2>&1
  echo "=== grype-version"; docker run --rm "$(image grype)" version 2>&1
  echo "=== osv-scanner"; docker run --rm "$(image osv-scanner)" --version 2>&1
  echo "=== dependency-check"; docker run --rm "$(image dependency-check)" --version 2>&1
  echo "=== dependency-check-data"; ls -la --time-style=full-iso "$CACHE_ROOT/dc-data" 2>&1
  echo "=== images.lock"; cat "$TOOLS_DIR/images.lock"
} > "$out.txt"
echo "$out.txt"
