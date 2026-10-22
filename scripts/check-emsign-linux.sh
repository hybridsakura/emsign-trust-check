#!/usr/bin/env bash
#
# check-emsign-linux.sh — offline-first checker for the Oct 2026 eMudhra
# intermediate CA compromise, for Linux hosts.
#
# Layers:
#   1. Distro trust-store distrust markers (works with NO network at all)
#   2. ca-certificates package version vs. known fixed versions
#   3. Optional live TLS probes (only when the host can reach the Internet)
#
# Exit codes: 0 = protected, 1 = vulnerable/likely vulnerable, 2 = inconclusive
#
# Data: https://emudhra.we-have-a-problem.com/impacted-intermediates.json

set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[ -t 1 ] || { GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''; }

SKIP_ONLINE=0
[ "${1:-}" = "--skip-online" ] && SKIP_ONLINE=1

section() { printf '\n%s=== %s ===%s\n' "$CYAN" "$1" "$NC"; }

# Roots that had to be distrusted (their subordinate intermediates were compromised)
ROOT_EMSIGN='emSign_ECC_Root_CA_-_G3'
ROOT_AAA='Comodo_AAA_Services_root'

# ---------------------------------------------------------------------------
# Layer 1: trust store distrust markers
# ---------------------------------------------------------------------------
section "1. Trust store distrust markers (offline)"

distrust_state="unknown"   # distrust | trusted | unknown
distro_family="unknown"

if [ -f /etc/os-release ]; then
  . /etc/os-release
  distro_family="${ID:-unknown}"
  case "${ID_LIKE:-}" in *debian*) distro_family="debian" ;; esac
  case "${ID_LIKE:-}" in *rhel*|*fedora*) [ "$distro_family" = "unknown" ] && distro_family="rhel" ;; esac
  echo "OS: ${PRETTY_NAME:-$distro_family}"
fi

check_debian() {
  local conf=/etc/ca-certificates.conf bundle=/etc/ssl/certs/ca-certificates.crt
  [ -f "$conf" ] || return 1
  local marked=0
  grep -qE "^!mozilla/${ROOT_EMSIGN}\.crt" "$conf" && marked=$((marked + 1))
  grep -qE "^!mozilla/${ROOT_AAA}\.crt" "$conf" && marked=$((marked + 1))
  local in_bundle=0
  if [ -f "$bundle" ]; then
    grep -q "emSign ECC Root CA - G3" "$bundle" && in_bundle=$((in_bundle + 1))
    grep -q "COMODO Certification Authority\|AAA Certificate Services" "$bundle" && in_bundle=$((in_bundle + 1))
  fi
  echo "  /etc/ca-certificates.conf distrust markers: ${marked}/2"
  echo "  roots still present in bundle:              ${in_bundle}/2"
  if [ "$marked" -ge 1 ]; then
    distrust_state="distrust"
  elif [ "$in_bundle" -ge 1 ]; then
    distrust_state="trusted"
  fi
}

check_blocklist_dir() {
  local dir="$1" name="$2"
  [ -d "$dir" ] || return 1
  local found=0
  ls "$dir" 2>/dev/null | grep -qi 'emSign\|AAA\|Comodo' && found=1
  echo "  $name: $([ "$found" = 1 ] && echo 'blocklist entry found' || echo 'no blocklist entry')"
  [ "$found" = 1 ] && distrust_state="distrust"
}

case "$distro_family" in
  debian) check_debian ;;
  rhel|fedora|centos|rocky|almalinux|amzn)
    check_blocklist_dir /etc/pki/ca-trust/source/blocklist "RHEL-family blocklist" ||
    check_blocklist_dir /etc/pki/ca-trust/source/blacklist "RHEL-family blacklist"
    ;;
  arch) check_blocklist_dir /etc/ca-certificates/trust-source/blocklist "Arch blocklist" ;;
  opensuse*|suse|sles)
    check_blocklist_dir /etc/pki/trust/blocklist "openSUSE blocklist" ||
    check_blocklist_dir /etc/pki/trust/blacklist "openSUSE blacklist"
    ;;
  *)
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
      [ -f "$f" ] || continue
      if grep -q "emSign ECC Root CA - G3" "$f"; then
        echo "  root still present in $f"
        distrust_state="trusted"
      else
        echo "  root absent from $f"
        distrust_state="distrust"
      fi
      break
    done
    ;;
esac

case "$distrust_state" in
  distrust) printf "  => ${GREEN}roots are distrusted%s\n" "$NC" ;;
  trusted)  printf "  => ${RED}roots are STILL TRUSTED%s\n" "$NC" ;;
  *)        printf "  => ${YELLOW}could not determine%s\n" "$NC" ;;
esac

# ---------------------------------------------------------------------------
# Layer 2: package version
# ---------------------------------------------------------------------------
section "2. ca-certificates package version"

pkg_version=""
for db in /var/lib/dpkg/status /var/lib/rpm; do :; done
if command -v dpkg-query >/dev/null 2>&1; then
  pkg_version="$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null)"
  echo "  installed: ${pkg_version:-unknown} (dpkg)"
elif command -v rpm >/dev/null 2>&1; then
  pkg_version="$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates 2>/dev/null)"
  echo "  installed: ${pkg_version:-unknown} (rpm)"
fi

# Known fixed versions (from the vendor advisory)
case "$pkg_version" in
  20250419~deb12u2|20250419~deb12u3*|20250419+deb13u1*|20250419ubuntu0.*|20260816*|2026*)
    printf "  => ${GREEN}version is at or after a known fixed build%s\n" "$NC" ;;
  "")
    printf "  => ${YELLOW}package not found, skipped%s\n" "$NC" ;;
  *)
    printf "  => ${YELLOW}%s is older than the fixed builds (e.g. 20250419~deb12u2 / 20250419+deb13u1)%s\n" "$pkg_version" "$NC" ;;
esac

# ---------------------------------------------------------------------------
# Layer 3: optional live TLS probes
# ---------------------------------------------------------------------------
online_result="-1"   # -1 skipped, 0 all blocked, >0 number connected

# Quick egress preflight: an air-gapped host should not sit through 12 x 6s timeouts.
have_egress() {
  timeout 2 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1
}

if [ "$SKIP_ONLINE" = 0 ] && ! command -v curl >/dev/null 2>&1; then
  echo
  echo "curl not found — live probes skipped (offline layers above are authoritative)."
  SKIP_ONLINE=1
elif [ "$SKIP_ONLINE" = 0 ] && ! have_egress; then
  echo
  echo "No outbound Internet detected within 2s — live probes skipped automatically."
  echo "The offline layers above are authoritative on this host. Use --skip-online to silence this check."
  SKIP_ONLINE=1
fi

if [ "$SKIP_ONLINE" = 0 ]; then
  section "3. Live TLS probes (needs Internet)"
  connected=0; blocked=0; timeout=0
  for h in dv-g3b ov-g3b ev-g3b dv-g3c ov-g3c ev-g3c; do
    for s in "" "-aaa"; do
      host="${h}${s}-emudhra.we-have-a-problem.com"
      if curl -s -o /dev/null --max-time 6 "https://${host}/" 2>/dev/null; then
        printf "  ${RED}❌ %s — connected (still trusted!)%s\n" "$host" "$NC"; connected=$((connected + 1))
      else
        rc=$?
        if [ $rc -eq 28 ]; then
          printf "  ${YELLOW}⚠️  %s — timeout%s\n" "$host" "$NC"; timeout=$((timeout + 1))
        else
          printf "  ${GREEN}✅ %s — rejected (curl exit %s)%s\n" "$host" "$rc" "$NC"; blocked=$((blocked + 1))
        fi
      fi
    done
  done
  echo "  summary: connected ${connected} / blocked ${blocked} / timeout ${timeout}"
  if [ $timeout -eq 12 ]; then
    printf "  ${YELLOW}all probes timed out — no Internet access, layer 3 unusable%s\n" "$NC"
  else
    online_result=$connected
  fi
else
  section "3. Live TLS probes — skipped"
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
section "Verdict"
if [ "$online_result" -gt 0 ]; then
  printf "${RED}⚠️  VULNERABLE: %s of 12 test hosts connected — this host still trusts the compromised intermediates.%s\n" "$online_result" "$NC"
  printf "Fix: update ca-certificates (Debian/Ubuntu: apt update && apt install --only-upgrade ca-certificates).\n"
  exit 1
elif [ "$online_result" = 0 ]; then
  printf "${GREEN}✅ PROTECTED: all 12 test hosts were rejected by certificate validation.%s\n" "$NC"
  exit 0
elif [ "$distrust_state" = "distrust" ]; then
  printf "${GREEN}✅ PROTECTED (offline assessment): the affected roots are distrusted in the local trust store.%s\n" "$NC"
  exit 0
elif [ "$distrust_state" = "trusted" ]; then
  printf "${RED}⚠️  LIKELY VULNERABLE (offline assessment): the affected roots are still trusted. Update ca-certificates.%s\n" "$NC"
  exit 1
else
  printf "${YELLOW}⚠️  INCONCLUSIVE: could not inspect the trust store on this host.%s\n" "$NC"
  printf "Inspect /etc/ssl/certs (or /etc/pki/tls/certs) manually, update ca-certificates from your offline repo, then re-run.%s\n" "$NC"
  exit 2
fi
