#!/usr/bin/env bash
#
# Fails if the web UI pulls any asset from the public Internet.
# The Linux/Docker build must work on a host with no outbound connectivity,
# so every script/style/image/font has to be same-origin or inline.
#
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# 1) External sub-resources: <script src>, <link href>, <img src>, <iframe src>, <source src>
hits="$(grep -nE '<(script|link|img|iframe|source)[^>]+(src|href)="https?://' public/*.html || true)"
if [ -n "$hits" ]; then
  echo "$hits"
  echo "::error::External sub-resource found — the page would break without Internet."
  fail=1
fi

# 2) CSS imports / url() pointing outside the site
css_hits="$(grep -nE '@import[^;]*https?://|url\(["'"'"']?https?://' public/*.html || true)"
if [ -n "$css_hits" ]; then
  echo "$css_hits"
  echo "::error::External CSS asset found — the page would break without Internet."
  fail=1
fi

# 3) Sanity: every download referenced by the pages must exist locally
for target in $(grep -oE 'href="downloads/[^"]+"' public/*.html | sed 's/.*href="//; s/"$//' | sort -u); do
  if [ ! -f "public/$target" ]; then
    echo "::error::Missing local download: public/$target"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "OK: no external assets; all referenced downloads exist locally."

# 4) The LAN page must answer on its own: Chinese by default, no button to press,
#    no instruction to download and run something.
LAN=public/lan.html
if [ ! -f "$LAN" ]; then
  echo "::error::$LAN is missing — the LAN edition has no page to build."
  exit 1
fi
lan_fail=0
check_lan() {
  if ! grep -qF "$2" "$LAN"; then
    echo "::error::$LAN must contain: $3"
    lan_fail=1
  fi
}
check_lan x 'lang="zh-CN"' 'Chinese as the default language'
check_lan x 'id="verdict"' 'a verdict block rendered without user action'
check_lan x "DOMContentLoaded" 'automatic start on load'
check_lan x '浏览器版本与封锁时间线' 'the version/timeline judgement'
check_lan x '浏览器证书校验强制力' 'the local TLS-enforcement self-check'

if grep -qE '<button' "$LAN"; then
  echo "::error::$LAN must not require a click to produce a result."
  lan_fail=1
fi
if grep -qE 'href="downloads/' "$LAN"; then
  echo "::error::$LAN must not push the operator to download a script."
  lan_fail=1
fi
if grep -qE '请下载|下载后运行|自行下载' "$LAN"; then
  echo "::error::$LAN must not ask the user to download anything."
  lan_fail=1
fi

if [ "$lan_fail" -ne 0 ]; then
  exit 1
fi

echo "OK: LAN page is self-contained, Chinese-first and click-free."

