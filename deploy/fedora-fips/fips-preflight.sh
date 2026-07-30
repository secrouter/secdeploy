#!/usr/bin/env bash
# SecDeploy FIPS preflight — fail closed unless the host is genuinely FIPS-ready.
# Run automatically by `secdeploy deploy fedora-fips`; safe to run standalone.
set -euo pipefail

fail() { echo "FIPS preflight FAILED: $*" >&2; exit 1; }
ok()   { echo "  ✓ $*"; }

echo "SecDeploy FIPS preflight"

# 1. Kernel FIPS flag.
if [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" != "1" ]; then
  fail "kernel FIPS mode is not enabled — run 'sudo fips-mode-setup --enable' and reboot"
fi
ok "kernel: /proc/sys/crypto/fips_enabled = 1"

# 2. Distro FIPS state (Fedora/RHEL).
if command -v fips-mode-setup >/dev/null 2>&1; then
  if ! fips-mode-setup --check 2>/dev/null | grep -qi "FIPS mode is enabled"; then
    fail "fips-mode-setup reports FIPS mode is not enabled"
  fi
  ok "fips-mode-setup: FIPS mode is enabled"
else
  echo "  ! fips-mode-setup not found (non-Fedora/RHEL?) — relying on kernel flag" >&2
fi

# 3. OpenSSL FIPS provider active.
if command -v openssl >/dev/null 2>&1; then
  if ! openssl list -providers 2>/dev/null | grep -qi fips; then
    fail "OpenSSL FIPS provider is not active (check /etc/crypto-policies and openssl.cnf)"
  fi
  ok "openssl: FIPS provider active"
else
  fail "openssl not found — cannot confirm the FIPS provider"
fi

echo "FIPS preflight OK — host is FIPS-ready."
