#!/usr/bin/env bash
#
# Fails when organisation- or industry-specific wording leaks into the
# open-source tree. The internal build keeps those strings in a git-ignored
# branding file, so the public repository must stay neutral.
#
set -euo pipefail

PATTERN='医院|患者|院内|科室|医疗|安庆|病历|HIS|PACS|[Hh]ospital'

cd "$(dirname "$0")/.."

hits="$(git grep -nEI "$PATTERN" -- . \
  ':!*.png' ':!*.jpg' ':!*.jpeg' ':!*.ico' \
  ':!dist' ':!*.zip' ':!*.tar.gz' \
  ':!scripts/check-no-industry-terms.sh' \
  ':!windows/TrustGuard/Branding/InternalBranding.local.cs' || true)"

if [ -n "$hits" ]; then
  echo "$hits"
  echo
  echo "::error::Industry/organisation-specific wording found in the public tree."
  echo "Move it into windows/TrustGuard/Branding/InternalBranding.local.cs (git-ignored)."
  exit 1
fi

echo "OK: no industry-specific wording in the open-source tree."
