#!/usr/bin/env bash
# Disposable software qualification of the shipping daemon and collector processes.
# No system installation, physical token, service manager, or production test hook.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(uname -s)" = Linux ] || { echo 'PKI recovery requires Linux' >&2; exit 2; }
for tool in go softhsm2-util pkcs11-tool; do
  command -v "$tool" >/dev/null || { echo "PKI recovery requires $tool" >&2; exit 2; }
done
# The harness selects only these software-token libraries and never accepts a
# bench module override. Check that dependency before building the processes.
if [ ! -f /usr/lib/softhsm/libsofthsm2.so ] && \
   [ ! -f /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so ] && \
   [ ! -f /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so ]; then
  echo 'PKI recovery requires the SoftHSM library' >&2
  exit 2
fi
STATE="$(mktemp -d)"
trap 'rm -rf -- "$STATE"' EXIT HUP INT TERM
chmod 0700 "$STATE"
go -C "$ROOT" build -race -o "$STATE/regalia-kms" ./cmd/regalia-kms
go -C "$ROOT" build -race -o "$STATE/regalia-audit-collector" ./cmd/regalia-audit-collector
go -C "$ROOT" test -race -c -o "$STATE/recovery.test" ./e2e
TMPDIR="$STATE" REGALIA_EXPECT_PKI_RECOVERY=1 REGALIA_PKI_RECOVERY_KMS="$STATE/regalia-kms" \
  REGALIA_PKI_RECOVERY_COLLECTOR="$STATE/regalia-audit-collector" \
  "$STATE/recovery.test" -test.v -test.count=1 -test.timeout=3m \
  -test.run '^TestShippingDaemonPKIReservationsSurviveSIGKILL$'
