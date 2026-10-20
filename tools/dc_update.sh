#!/usr/bin/env bash
# Pierwsze pobranie bazy NVD dla Dependency-Check (może trwać kilkadziesiąt minut).
set -euo pipefail
source "$(dirname "$0")/lib.sh"
: "${NVD_API_KEY:?Ustaw zmienną NVD_API_KEY}"
docker run --rm --user "$DOCKER_USER" -v "$CACHE_ROOT/dc-data:/usr/share/dependency-check/data" \
  "$(image dependency-check)" --updateonly --nvdApiKey "$NVD_API_KEY"
