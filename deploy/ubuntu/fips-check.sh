#!/usr/bin/env bash
# SecDeploy Ubuntu/Debian FIPS advisory check — WARNS, never aborts.
#
# Unlike deploy/fedora-fips/fips-preflight.sh (which FAILS CLOSED when the host isn't in FIPS
# mode — see that script), stock Ubuntu/Debian ship no in-tree FIPS-140-validated OpenSSL
# module. The only accredited path to a FIPS-validated crypto boundary on Ubuntu is Ubuntu
# Pro's `fips-updates` package (https://ubuntu.com/security/certifications/docs/fips) — a
# subscription entitlement, not something `secdeploy` can enable for you. Aborting every
# non-FIPS ubuntu deploy would make the target unusable for the (common) non-regulated case, so
# this step is advisory-only: it always exits 0 and simply prints what it found. Run standalone
# with `bash deploy/ubuntu/fips-check.sh`; `secdeploy deploy ubuntu` runs it automatically first.
#
# If your accreditation boundary REQUIRES a fail-closed FIPS check, use the `fedora-fips`
# target instead (see docs/fedora-fips.md) — ubuntu has no `--require-fips`-style escalation
# flag (fedora-fips has no such flag to mirror either; its preflight is unconditional).
set -uo pipefail   # deliberately NO -e — nothing in here may abort the deploy

warn() { echo "FIPS advisory: $*" >&2; }
ok()   { echo "  - $*"; }

echo "SecDeploy Ubuntu/Debian FIPS advisory check (non-fatal)"

fips_flag="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
if [ "$fips_flag" != "1" ]; then
  warn "kernel FIPS mode is NOT enabled (/proc/sys/crypto/fips_enabled != 1)."
  warn "this host is not running a FIPS-140-validated crypto boundary — proceeding anyway"
  warn "(the ubuntu target warns; it does not fail closed like fedora-fips does)."
  warn "accredited path: Ubuntu Pro's 'fips-updates' package — https://ubuntu.com/security/certifications/docs/fips"
  warn "  sudo pro attach <token> && sudo pro enable fips-updates   # then reboot"
  warn "for a fail-closed FIPS boundary today, use the fedora-fips target instead — see docs/ubuntu.md#fips."
else
  ok "kernel: /proc/sys/crypto/fips_enabled = 1"
  if command -v openssl >/dev/null 2>&1; then
    if openssl list -providers 2>/dev/null | grep -qi fips; then
      ok "openssl: FIPS provider active"
    else
      warn "kernel reports FIPS mode enabled, but no OpenSSL FIPS provider was detected."
      warn "verify Ubuntu Pro fips-updates is fully applied (a reboot is required after enabling it)."
    fi
  else
    warn "openssl not found — cannot confirm the FIPS provider"
  fi
fi

echo "FIPS advisory check complete (non-fatal) — see docs/ubuntu.md#fips."
exit 0
