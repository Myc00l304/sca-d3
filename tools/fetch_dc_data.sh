#!/usr/bin/env bash
# Jeśli brak lokalnej bazy Dependency-Check, pobiera ją z wydania "dc-data" repozytorium
# (archiwum przygotowane raz na komputerze autorki). Dalej dc_update.sh dociąga tylko zmiany.
#   tools/fetch_dc_data.sh <właściciel/repozytorium>
set -euo pipefail
source "$(dirname "$0")/lib.sh"
repo="${1:?Podaj właściciel/repozytorium}"
if compgen -G "$CACHE_ROOT/dc-data/*.mv.db" > /dev/null; then
  echo "[dc-data] baza obecna w pamięci podręcznej" >&2
  exit 0
fi
url="https://github.com/$repo/releases/download/dc-data/dc-data.tar.zst"
echo "[dc-data] pobieranie $url" >&2
curl -fsSL "$url" -o /tmp/dc-data.tar.zst
rm -rf "$CACHE_ROOT/dc-data"
tar -C "$CACHE_ROOT" --zstd -xf /tmp/dc-data.tar.zst
ls -la "$CACHE_ROOT/dc-data" >&2
