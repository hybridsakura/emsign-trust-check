#!/usr/bin/env bash
#
# build-offline-bundle.sh — produce everything needed to deploy on an
# air-gapped (no Internet) network:
#
#   dist/emsign-trust-check-<ver>-docker-<arch>.tar.gz   image, load with `docker load`
#   dist/emsign-trust-check-<ver>-static.tar.gz          plain web root + scripts, no Docker
#   dist/SHA256SUMS                                      checksums for both
#
# Run from anywhere; requires Docker on the BUILD machine only.
#
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

VERSION="${1:-1.0.0}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

command -v docker >/dev/null 2>&1 || { echo "docker is required on the build machine" >&2; exit 1; }
mkdir -p dist

echo "==> building image emsign-trust-check:${VERSION}"
# Disable provenance/SBOM attestations: they turn the exported archive into a
# nested OCI index that older Docker versions (e.g. 20.10 on offline hosts)
# refuse to load. A flat single-platform image loads everywhere.
if docker buildx version >/dev/null 2>&1; then
  docker buildx build --provenance=false --sbom=false --platform "linux/${ARCH}" \
    -t "emsign-trust-check:${VERSION}" -t emsign-trust-check:latest --load .
else
  DOCKER_BUILDKIT=0 docker build -t "emsign-trust-check:${VERSION}" -t emsign-trust-check:latest .
fi

echo "==> exporting image (this is the only artifact offline hosts need for Docker mode)"
docker save "emsign-trust-check:${VERSION}" | gzip -9 > "dist/emsign-trust-check-${VERSION}-docker-${ARCH}.tar.gz"

echo "==> packing static bundle (works without Docker, only needs python3)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/emsign-trust-check-${VERSION}"
cp -r public scripts README.md LICENSE "$STAGE/emsign-trust-check-${VERSION}/"
tar -czf "dist/emsign-trust-check-${VERSION}-static.tar.gz" -C "$STAGE" "emsign-trust-check-${VERSION}"

echo "==> writing checksums"
( cd dist && sha256sum ./*.tar.gz > SHA256SUMS )

echo
echo "artifacts:"
ls -lh dist/
echo
echo "Deploy on an air-gapped host:"
echo "  1) copy dist/ over (USB / internal share)"
echo "  2) verify:   sha256sum -c SHA256SUMS            (in dist/)"
echo "  3) Docker:   tar xzf emsign-trust-check-${VERSION}-static.tar.gz"
echo "               cd emsign-trust-check-${VERSION} && sudo ./scripts/install-offline.sh --docker \\"
echo "                 --image ../dist/emsign-trust-check-${VERSION}-docker-${ARCH}.tar.gz"
echo "     No Docker: sudo ./scripts/install-offline.sh        (static + systemd, python3 only)"
