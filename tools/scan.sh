#!/usr/bin/env bash
# Uruchamia jedno narzędzie na jednym katalogu projektu.
#   scan.sh <narzędzie> <katalog_projektu> <katalog_wyników>
# Narzędzia: trivy, grype, osv-scanner, osv-scanner-ext, dependency-check, npm-audit, pip-audit
# Wynik: <katalog_wyników>/<narzędzie>.json oraz <narzędzie>.meta.json
# (kod wyjścia, czas ścienny w sekundach, obraz, znacznik czasu).
set -uo pipefail
source "$(dirname "$0")/lib.sh"
tool="$1"; src="$(realpath "$2")"; out="$(realpath -m "$3")"
mkdir -p "$out"
raw="$out/$tool.json"; log="$out/$tool.log"
common=(--rm --user "$DOCKER_USER" -v "$src:/src:ro")

start=$(date +%s.%N)
case "$tool" in
  trivy)
    img=$(image trivy)
    # F1: pliki manifestu i blokady (tryb fs); F2: zainstalowane artefakty (tryb rootfs).
    # Zależności Maven rozwiązywane z lokalnego repozytorium (bez zapytań do Maven Central).
    mode=fs; [[ "$(basename "$src")" == F2 ]] && mode=rootfs
    docker run "${common[@]}" -e HOME=/tmp -e TRIVY_CACHE_DIR=/cache \
      -v "$CACHE_ROOT/trivy:/cache" -v "$CACHE_ROOT/m2:/tmp/.m2:ro" \
      "$img" "$mode" --scanners vuln --format json --quiet --offline-scan \
      --skip-db-update --skip-java-db-update /src > "$raw" 2> "$log"
    code=$? ;;
  grype)
    img=$(image grype)
    docker run "${common[@]}" -e GRYPE_DB_CACHE_DIR=/cache -e GRYPE_DB_AUTO_UPDATE=false \
      -e TMPDIR=/tmp -v "$CACHE_ROOT/tmp:/tmp" -v "$CACHE_ROOT/grype:/cache" \
      "$img" dir:/src -o json > "$raw" 2> "$log"
    code=$? ;;
  osv-scanner)
    img=$(image osv-scanner)
    docker run "${common[@]}" "$img" scan source --recursive --format json /src > "$raw" 2> "$log"
    code=$? ;;
  osv-scanner-ext)
    # wariant rozszerzony: zestaw wtyczek "artifact" (zainstalowane artefakty, forma F2)
    img=$(image osv-scanner)
    docker run "${common[@]}" "$img" scan source --recursive --x-plugins artifact \
      --format json /src > "$raw" 2> "$log"
    code=$? ;;
  dependency-check)
    img=$(image dependency-check)
    : "${NVD_API_KEY:?Ustaw zmienną NVD_API_KEY}"
    docker run "${common[@]}" -v "$out:/out" -v "$CACHE_ROOT/dc-data:/usr/share/dependency-check/data" \
      "$img" --scan /src --format JSON --out /out --project case --enableExperimental \
      --nvdApiKey "$NVD_API_KEY" ${SCA_OFFLINE:+--noupdate} ${SCA_OFFLINE_DC:+--noupdate} > "$log" 2>&1
    code=$?
    [[ -f "$out/dependency-check-report.json" ]] && mv "$out/dependency-check-report.json" "$raw" ;;
  npm-audit)
    img=$(image node)
    if [[ -f "$src/package-lock.json" ]]; then
      docker run "${common[@]}" -e HOME=/tmp -w /src "$img" \
        npm audit --json --package-lock-only > "$raw" 2> "$log"
      code=$?
    else
      echo '{"skipped":"no package-lock.json"}' > "$raw"; code=0
    fi ;;
  pip-audit)
    img=$(image pip-audit)
    if [[ -f "$src/requirements.txt" ]]; then
      docker run "${common[@]}" -e HOME=/tmp "$img" -r /src/requirements.txt --no-deps \
        --disable-pip --format json > "$raw" 2> "$log"
      code=$?
    else
      echo '{"skipped":"no requirements.txt"}' > "$raw"; code=0
    fi ;;
  *) echo "Nieznane narzędzie: $tool" >&2; exit 2 ;;
esac
end=$(date +%s.%N)
python3 - "$out/$tool.meta.json" "$tool" "$img" "$code" "$start" "$end" <<'PY'
import json, sys, datetime as dt
path, tool, img, code, start, end = sys.argv[1:]
json.dump({"tool": tool, "image": img, "exit_code": int(code),
           "wall_seconds": round(float(end) - float(start), 3),
           "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
           "offline": bool(__import__("os").environ.get("SCA_OFFLINE"))},
          open(path, "w"), indent=2)
PY
exit 0
