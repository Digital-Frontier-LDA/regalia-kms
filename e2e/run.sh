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

# WHAT KIND OF EVIDENCE DID THIS PRODUCE? A run used to end in a list of "ok" lines that say
# nothing about whether a real token was involved. The difference is the whole subject of
# regalia#435 and #439: a SoftHSM pass and a Nitrokey pass look identical in the log and mean
# entirely different things, and the qualification record is assembled by people reading these
# logs. Each arm declares its class, and the run prints them together at the end.
#
#   software   pure Go and host tooling; no token of any kind
#   emulated   a SoftHSM token or the ceremony emulator standing in for hardware
#   physical   a real token, named by serial
#
# A mode that could be either says so per-arm rather than picking the flattering one.
EVIDENCE=()
evidence() { EVIDENCE+=("$1|$2"); }   # evidence <class> <what it covers>

summarise_evidence() {
  # THE EXIT STATUS DECIDES THE HEADING. The trap runs on failure too, and a list of arms printed
  # under "EVIDENCE PRODUCED" after `set -e` aborted mid-run is a record of things that did not
  # happen. Under --plan nothing ran at all.
  local status=$?
  local heading
  if [ "$PLAN" = 1 ]; then
    heading="EVIDENCE THIS PLAN WOULD PRODUCE (nothing ran)"
  elif [ "$status" -ne 0 ]; then
    heading="RUN FAILED (exit $status) — THE ARMS BELOW DID NOT ALL COMPLETE"
  else
    heading="EVIDENCE PRODUCED"
  fi
  printf '\n\033[1m========== %s ==========\033[0m\n' "$heading"
  local physical=0 entry class what
  for entry in ${EVIDENCE[@]+"${EVIDENCE[@]}"}; do
    class="${entry%%|*}"; what="${entry#*|}"
    case "$class" in
      physical) physical=1; printf '  \033[32mPHYSICAL\033[0m  %s\n' "$what";;
      emulated) printf '  \033[33mEMULATED\033[0m  %s\n' "$what";;
      *)        printf '  SOFTWARE  %s\n' "$what";;
    esac
  done
  if [ "$status" -ne 0 ] && [ "$PLAN" != 1 ]; then
    printf '\n  A FAILED RUN PRODUCES NO EVIDENCE. The lines above say what this mode covers when\n'
    printf '  it completes, not what it established. Do not record any of it.\n'
    return
  fi
  if [ "$PLAN" != 1 ] && [ "$physical" -eq 0 ]; then
    printf '\n  NOTHING HERE TOUCHED A REAL TOKEN. Do not file this as hardware qualification\n'
    printf '  evidence: SoftHSM and the emulator model the interface, not the device, and every\n'
    printf '  divergence that has cost us time was a place where they differ.\n'
  fi
}
trap summarise_evidence EXIT

evidence software "go test -race ./... and go vet, KMS and the sops adapter"
run go -C "$ROOT" test -race ./...
run go -C "$ROOT" vet ./...
run env GOWORK=off go -C "$ROOT/adapters/sops" test -race ./...
run env GOWORK=off go -C "$ROOT/adapters/sops" vet ./...
evidence emulated "PKCS#11 plumbing and KMS policy against a disposable SoftHSM token"
run "$ROOT/e2e/softhsm-pkcs11.sh"

case "$MODE" in
  docker)
    evidence emulated "the ceremony emulator suite, in Docker"
    need_ceremony
    run "$CEREMONY/qubes/emulator/build.sh" ceremony-emu
    run docker run --rm --privileged ceremony-emu all-tests
    ;;
  native-vm)
    evidence emulated "the ceremony emulator suite, natively"
    [ "$(uname -s)" = Linux ] || { echo "native-vm mode requires disposable Debian/Linux" >&2; exit 2; }
    need_ceremony
    run sudo -E "$CEREMONY/qubes/emulator/run-tests.sh"
    ;;
  pico-gate)
    evidence physical "the PicoHSM staging gate tier${HSM_CI_SERIAL:+ (serial $HSM_CI_SERIAL)}"
    # A YubiKey in the run is a SECOND physical device, and the record must name it separately:
    # "a real token was involved" does not say which, and the gate's PIV arm skips silently
    # without HSM_CI_YUBIKEY_SERIAL — so a run without one must not read as covering it.
    [ -n "${HSM_CI_YUBIKEY_SERIAL:-}" ] \
      && evidence physical "YubiKey PIV 9A read-only qualification (serial $HSM_CI_YUBIKEY_SERIAL)"
    need_ceremony
    run "$CEREMONY/qubes/scripts/hsm-staging-ci.sh" --tier gate
    ;;
  pico-nightly)
    evidence physical "the DESTRUCTIVE PicoHSM nightly tier${HSM_CI_SERIAL:+ (serial $HSM_CI_SERIAL)}"
    [ "${REGALIA_ALLOW_DESTRUCTIVE_PICO:-}" = YES ] || {
      echo "REFUSING destructive Pico run: set REGALIA_ALLOW_DESTRUCTIVE_PICO=YES" >&2
      exit 2
    }
    [ -n "${HSM_CI_SERIAL:-}" ] || { echo "REFUSING destructive Pico run without HSM_CI_SERIAL" >&2; exit 2; }
    need_ceremony
    run "$CEREMONY/qubes/scripts/hsm-staging-ci.sh" --tier nightly
    ;;
  cosmos-hardware)
    # The token this signs with is named by module+slot/label, not by serial, so the serial is
    # read back and reported: "a real token" is not evidence unless the record says WHICH.
    evidence physical "Cosmos SignDoc signed by a real token (${REGALIA_COSMOS_PKCS11_TOKEN_LABEL:-slot ${REGALIA_COSMOS_PKCS11_SLOT:-?}} via ${REGALIA_COSMOS_PKCS11_MODULE:-?})"
    run "$ROOT/e2e/cosmos-hardware-sign-verify.sh"
    ;;
  cosmos-devnet)
    # NOT hardware evidence, and the README says so: this arm proves a disposable node accepts a
    # transaction signed with the SDK's OWN test keyring. regalia#439's first acceptance criterion
    # — a node accepting a transaction signed through the KMS path — is not what this run shows.
    evidence emulated "a disposable Cosmos node accepting a MsgSend signed by the SDK's test keyring (NOT the KMS)"
    run "$ROOT/e2e/cosmos-simapp-tx.sh"
    ;;
  *) echo "unsupported mode: $MODE" >&2; exit 2 ;;
esac
