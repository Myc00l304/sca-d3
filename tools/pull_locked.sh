#!/usr/bin/env bash
# Odtwarza obrazy z images.lock na nowej maszynie (np. w GitHub Actions): pobiera obrazy
# po skrócie i buduje lokalny obraz pip-audit w wersji zapisanej w images.lock.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
while IFS='=' read -r name ref; do
  [[ -z "$name" || "$name" == \#* || "$name" == pip-audit ]] && continue
  docker pull -q "$ref" >/dev/null && echo "[pull] $name" >&2
done < "$TOOLS_DIR/images.lock"
ver=$(sed -n 's/^# pip-audit: pip-audit //p' "$TOOLS_DIR/images.lock")
docker build -q --build-arg "PIP_AUDIT_VERSION=$ver" --build-arg "BASE=$(image python312)" -t "$(image pip-audit)" \
  -f "$TOOLS_DIR/pip-audit.Dockerfile" "$TOOLS_DIR" >/dev/null
echo "[build] pip-audit $ver" >&2
