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
