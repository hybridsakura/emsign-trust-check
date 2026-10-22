#!/usr/bin/env bash
#
# install-offline.sh — install emsign-trust-check on an air-gapped Linux host.
# No Internet access required: nothing is downloaded, nothing is resolved online.
#
# Two modes:
#   static (default) : copies the web root and runs it as a systemd service
#                      using python3's built-in http.server (no extra packages)
#   docker           : loads the bundled image tarball with `docker load`,
#                      then runs the container
#
# Examples:
#   sudo ./install-offline.sh
#   sudo ./install-offline.sh --port 9090
#   sudo ./install-offline.sh --docker --image ./dist/emsign-trust-check-1.0.0-docker-amd64.tar.gz
#
set -eu

MODE=static
PORT=8080
CANARY_PORT=8443
PREFIX=/opt/emsign-trust-check
IMAGE=""
SERVICE=emsign-trust-check

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) MODE=docker; shift ;;
    --static) MODE=static; shift ;;
    --port) PORT="$2"; shift 2 ;;
    --canary-port) CANARY_PORT="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

if [ "$(id -u)" != 0 ]; then
  echo "please run as root (needed for systemd / docker)" >&2
  exit 1
fi

echo "==> mode: $MODE, port: $PORT, prefix: $PREFIX"

if [ "$MODE" = docker ]; then
  command -v docker >/dev/null 2>&1 || { echo "docker not found; rerun without --docker for static mode" >&2; exit 1; }

  if [ -z "$IMAGE" ]; then
    IMAGE="$(ls -1 "$ROOT"/dist/*docker*.tar.gz 2>/dev/null | head -1 || true)"
  fi
  [ -n "$IMAGE" ] && [ -f "$IMAGE" ] || { echo "image tarball not found; pass --image <path>" >&2; exit 1; }

  echo "==> loading image from $IMAGE (no registry access needed)"
  LOAD_OUT="$(gunzip -c "$IMAGE" | docker load)"
  echo "$LOAD_OUT"
  # Use whatever tag the tarball actually carries (internet or LAN edition).
  IMAGE_TAG="$(printf '%s\n' "$LOAD_OUT" | sed -n 's/^Loaded image: //p' | tail -1)"
  [ -n "$IMAGE_TAG" ] || IMAGE_TAG="emsign-trust-check:latest"
  docker rm -f "$SERVICE" >/dev/null 2>&1 || true
  # 8443 only serves the TLS-enforcement self-check used by the LAN page.
  docker run -d --name "$SERVICE" -p "${PORT}:80" -p "${CANARY_PORT}:8443" \
    --restart unless-stopped "$IMAGE_TAG" >/dev/null
  echo "==> container started"
else
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found; install it from your offline repo, or use --docker" >&2; exit 1; }

  WWW="$PREFIX/www"
  echo "==> installing static site to $WWW"
  mkdir -p "$WWW"
  cp -r "$ROOT/public/." "$WWW/"
  cp -r "$ROOT/scripts" "$PREFIX/" 2>/dev/null || true
  cp "$ROOT/README.md" "$PREFIX/" 2>/dev/null || true

  cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=emSign trust check (static web UI)
After=network.target

[Service]
Type=simple
WorkingDirectory=${WWW}
ExecStart=/usr/bin/python3 -m http.server ${PORT} --bind 0.0.0.0 --directory ${WWW}
Restart=on-failure
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$SERVICE" >/dev/null
  echo "==> systemd service '$SERVICE' enabled and started"
fi

# ---------------------------------------------------------------------------
# Local verification — loopback only, works with no Internet access
# ---------------------------------------------------------------------------
echo "==> verifying on http://127.0.0.1:${PORT}/"
ok=0
for i in 1 2 3 4 5; do
  if curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${PORT}/" 2>/dev/null; then ok=1; break; fi
  sleep 1
done

if [ "$ok" = 1 ]; then
  echo "==> OK — open http://<this-host>:${PORT}/ from any intranet browser"
else
  echo "!! verification failed; check: systemctl status $SERVICE  /  docker logs $SERVICE" >&2
  exit 1
fi
