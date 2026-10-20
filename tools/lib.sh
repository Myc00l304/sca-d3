# Wspólne funkcje dla skryptów powłoki.
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_ROOT="${SCA_CACHE:-$HOME/.cache/sca-thesis}"
mkdir -p "$CACHE_ROOT"/trivy "$CACHE_ROOT"/grype "$CACHE_ROOT"/dc-data "$CACHE_ROOT"/m2 "$CACHE_ROOT"/npm "$CACHE_ROOT"/pip "$CACHE_ROOT"/tmp
image() {  # image <nazwa> -> odwołanie z images.lock
  local ref
  ref=$(grep -E "^$1=" "$TOOLS_DIR/images.lock" | head -1 | cut -d= -f2-)
  [[ -n "$ref" ]] || { echo "Brak obrazu '$1' w images.lock (uruchom freeze_images.sh)" >&2; return 1; }
  echo "$ref"
}
DOCKER_USER="$(id -u):$(id -g)"
