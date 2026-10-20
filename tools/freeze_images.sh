#!/usr/bin/env bash
# Pobiera obrazy z images.txt, buduje obraz pip-audit i zapisuje niezmienne odwołania
# (image@sha256:...) w images.lock. Uruchamiać raz, przed badaniem właściwym.
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f images.lock && "${1:-}" != "--force" ]]; then
  echo "images.lock już istnieje. Użyj --force, aby zamrozić ponownie." >&2
  exit 1
fi
tmp=$(mktemp)
echo "# Zamrożono: $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$tmp"
while IFS='=' read -r name ref; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  echo "[pull] $ref" >&2
  docker pull -q "$ref" >/dev/null
  digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref")
  echo "$name=$digest" >> "$tmp"
done < images.txt
echo "[build] pip-audit" >&2
docker build -q -t sca-pip-audit:local -f pip-audit.Dockerfile . >/dev/null
pa_id=$(docker image inspect --format '{{.Id}}' sca-pip-audit:local)
pa_ver=$(docker run --rm --entrypoint cat sca-pip-audit:local /pip-audit-version.txt)
docker tag sca-pip-audit:local "sca-pip-audit:${pa_id#sha256:}"
echo "pip-audit=sca-pip-audit:${pa_id#sha256:}" >> "$tmp"
echo "# pip-audit: $pa_ver" >> "$tmp"
mv "$tmp" images.lock
cat images.lock
