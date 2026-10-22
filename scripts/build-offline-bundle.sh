#!/usr/bin/env bash
#
# build-offline-bundle.sh — produce deployable Linux artefacts for one edition.
#
#   dist/emsign-trust-check-<ver>-docker-<arch>.tar.gz        internet edition image
#   dist/emsign-trust-check-<ver>-lan-docker-<arch>.tar.gz    LAN edition image
#   dist/emsign-trust-check-<ver>-static.tar.gz               internet edition, no Docker
#   dist/emsign-trust-check-<ver>-lan-static.tar.gz           LAN edition, no Docker
#
# The edition is materialised at build time (see build-edition.py). The shipped
# artefact contains no runtime switch: the LAN build has no live-probe UI and
# makes no external request.
#
# Usage: ./scripts/build-offline-bundle.sh 1.0.4 [--edition internet|lan]
#
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

VERSION="${1:-1.0.0}"
shift || true
EDITION="internet"
while [ $# -gt 0 ]; do
  case "$1" in
    --edition) EDITION="${2:-}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
case "$EDITION" in internet|lan) ;; *) echo "--edition must be internet or lan" >&2; exit 1 ;; esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

command -v docker >/dev/null 2>&1 || { echo "docker is required on the build machine" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required on the build machine" >&2; exit 1; }
mkdir -p dist

TAG_SUFFIX=""
NAME_SUFFIX=""
if [ "$EDITION" = lan ]; then TAG_SUFFIX="-lan"; NAME_SUFFIX="-lan"; fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> materialising ${EDITION} web UI"
python3 scripts/build-edition.py --edition "$EDITION" --src public --out "$WORK/public"

echo "==> building image emsign-trust-check:${VERSION}${TAG_SUFFIX} (alpine base)"
mkdir -p "$WORK/img"
cp -r "$WORK/public" "$WORK/img/public"
cat > "$WORK/img/Dockerfile" <<'DOCKER'
# Alpine-based static image: no runtime dependency, no outbound request.
FROM nginx:1.27-alpine
COPY public/ /usr/share/nginx/html/
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
EXPOSE 80
DOCKER

if docker buildx version >/dev/null 2>&1; then
  docker buildx build --provenance=false --sbom=false --platform "linux/${ARCH}" \
    -t "emsign-trust-check:${VERSION}${TAG_SUFFIX}" -t "emsign-trust-check:${EDITION}" \
    --load "$WORK/img"
else
  DOCKER_BUILDKIT=0 docker build -t "emsign-trust-check:${VERSION}${TAG_SUFFIX}" -t "emsign-trust-check:${EDITION}" "$WORK/img"
fi

echo "==> exporting image"
docker save "emsign-trust-check:${VERSION}${TAG_SUFFIX}" \
  | gzip -9 > "dist/emsign-trust-check-${VERSION}${NAME_SUFFIX}-docker-${ARCH}.tar.gz"

echo "==> packing static bundle"
STAGE="$WORK/stage"
mkdir -p "$STAGE/emsign-trust-check-${VERSION}${NAME_SUFFIX}"
cp -r "$WORK/public" "$STAGE/emsign-trust-check-${VERSION}${NAME_SUFFIX}/public"
cp -r scripts "$STAGE/emsign-trust-check-${VERSION}${NAME_SUFFIX}/"
cp README.md LICENSE "$STAGE/emsign-trust-check-${VERSION}${NAME_SUFFIX}/" 2>/dev/null || true
echo "$EDITION" > "$STAGE/emsign-trust-check-${VERSION}${NAME_SUFFIX}/EDITION.txt"
tar -czf "dist/emsign-trust-check-${VERSION}${NAME_SUFFIX}-static.tar.gz" \
  -C "$STAGE" "emsign-trust-check-${VERSION}${NAME_SUFFIX}"

echo "==> checksums"
( cd dist && sha256sum ./*.tar.gz > SHA256SUMS )

echo
echo "artifacts:"
ls -lh dist/ | grep -E "static|docker" || true
echo
echo "Deploy on an air-gapped host:"
echo "  1) copy dist/ over (USB / internal share)"
echo "  2) verify:   sha256sum -c SHA256SUMS            (in dist/)"
echo "  3) Docker:   tar xzf emsign-trust-check-${VERSION}${NAME_SUFFIX}-static.tar.gz"
echo "               cd emsign-trust-check-${VERSION}${NAME_SUFFIX} && sudo ./scripts/install-offline.sh --docker \\"
echo "                 --image ../dist/emsign-trust-check-${VERSION}${NAME_SUFFIX}-docker-${ARCH}.tar.gz"
echo "     No Docker: sudo ./scripts/install-offline.sh        (static + systemd, python3 only)"
