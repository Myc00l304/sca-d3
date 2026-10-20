#!/usr/bin/env bash
# Sprawdza empirycznie, które ustawienia OSV-Scanner i Grype pozwalają odczytać zainstalowane
# artefakty (forma F2). Wynik: /tmp/probe_f2.txt
set -uo pipefail
source "$(dirname "$0")/lib.sh"
ROOT="$(cd "$TOOLS_DIR/.." && pwd)"
out=/tmp/probe_f2.txt; : > "$out"
osv=$(image osv-scanner); grype=$(image grype)
for eco in npm PyPI Maven; do
  d=$(find "$ROOT/d1/projects_s1/$eco" -mindepth 3 -maxdepth 3 -type d -path '*/pos/F2' | head -1)
  [[ -z "$d" ]] && continue
  echo "##### $eco: $d" >> "$out"
  for plugins in artifact all java/archive javascript/packagejson python/wheelegg python/pip; do
    echo "=== osv --x-plugins $plugins" >> "$out"
    docker run --rm --user "$DOCKER_USER" -v "$d:/src:ro" "$osv" scan source -r \
      --x-plugins "$plugins" --format json /src > /tmp/probe.json 2> /tmp/probe.log
    echo "kod=$? pakiety_z_podatnościami=$(grep -c '"package"' /tmp/probe.json)" >> "$out"
    grep -iE "unknown|invalid|not found|Scanned|found [0-9]+ package|error" /tmp/probe.log | head -6 >> "$out"
  done
done
echo "##### grype config (fragmenty o katalogerach)" >> "$out"
docker run --rm "$grype" config 2>&1 | grep -n -i -B2 -A8 "catalog" | head -80 >> "$out"
echo "Zapisano $out"
