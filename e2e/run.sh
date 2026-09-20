#!/usr/bin/env bash
# Reuse the established ceremony emulator and PicoHSM battery as the KMS
# integration substrate. The default is non-destructive Docker emulation.
#
# THE CEREMONY HALF LIVES IN ANOTHER REPOSITORY. The emulator and the staging battery are in
# regalia-ceremony (https://github.com/Digital-Frontier-LDA/regalia-ceremony). Point
# REGALIA_CEREMONY_DIR at a checkout of it to run the modes that need them; without it those modes
# refuse rather than silently doing less, because a mode that "passes" having skipped its substrate
# is the failure this whole battery exists to avoid. The KMS-only steps below always run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CEREMONY="${REGALIA_CEREMONY_DIR:-}"
need_ceremony() {
  # --plan prints what WOULD run; it must not require the substrate, or a reader cannot see the
  # plan without checking out the other repository first. Only an actual run needs it.
  if [ "$PLAN" = 1 ]; then
    # Show the path a reader would have to provide, rather than an empty string that reads as "/".
    [ -n "$CEREMONY" ] || CEREMONY="<REGALIA_CEREMONY_DIR>"
    return 0
  fi
  [ -n "$CEREMONY" ] && [ -d "$CEREMONY/qubes" ] && return 0
  echo "REFUSING mode '$MODE': it runs the ceremony emulator/battery, which lives in" >&2
  echo "regalia-ceremony. Set REGALIA_CEREMONY_DIR to a checkout of that repository." >&2
  exit 2
}
MODE=docker
PLAN=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --plan) PLAN=1; shift ;;
    -h|--help)
      echo "usage: $0 [--mode docker|native-vm|pico-gate|pico-nightly|cosmos-hardware|cosmos-devnet] [--plan]"
      exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

run() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  [ "$PLAN" = 1 ] || "$@"
}

run go -C "$ROOT" test -race ./...
run go -C "$ROOT" vet ./...
run env GOWORK=off go -C "$ROOT/adapters/sops" test -race ./...
run env GOWORK=off go -C "$ROOT/adapters/sops" vet ./...
run "$ROOT/e2e/softhsm-pkcs11.sh"

case "$MODE" in
  docker)
    need_ceremony
    run "$CEREMONY/qubes/emulator/build.sh" ceremony-emu
    run docker run --rm --privileged ceremony-emu all-tests
    ;;
  native-vm)
    [ "$(uname -s)" = Linux ] || { echo "native-vm mode requires disposable Debian/Linux" >&2; exit 2; }
    need_ceremony
    run sudo -E "$CEREMONY/qubes/emulator/run-tests.sh"
    ;;
  pico-gate)
    need_ceremony
    run "$CEREMONY/qubes/scripts/hsm-staging-ci.sh" --tier gate
    ;;
  pico-nightly)
    [ "${REGALIA_ALLOW_DESTRUCTIVE_PICO:-}" = YES ] || {
      echo "REFUSING destructive Pico run: set REGALIA_ALLOW_DESTRUCTIVE_PICO=YES" >&2
      exit 2
    }
    [ -n "${HSM_CI_SERIAL:-}" ] || { echo "REFUSING destructive Pico run without HSM_CI_SERIAL" >&2; exit 2; }
    need_ceremony
    run "$CEREMONY/qubes/scripts/hsm-staging-ci.sh" --tier nightly
    ;;
  cosmos-hardware)
    run "$ROOT/e2e/cosmos-hardware-sign-verify.sh"
    ;;
  cosmos-devnet)
    run "$ROOT/e2e/cosmos-simapp-tx.sh"
    ;;
  *) echo "unsupported mode: $MODE" >&2; exit 2 ;;
esac
