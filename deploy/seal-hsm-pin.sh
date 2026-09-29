#!/usr/bin/env bash
# seal-hsm-pin.sh — seal ONE Nitrokey's user PIN to this KMS guest's TPM2, as the systemd encrypted
# credential regalia-kms loads (ADR-0002 D2; PIN-CUSTODY.md). Run ONCE per site, as root, on the guest,
# with the card attached, typing the PIN from the sealed paper PIN card.
#
#   sudo deploy/seal-hsm-pin.sh --id hsm-site-a --serial DENK0404144 --pcrs 7+11 [--replace]
#
# What it does, and refuses:
#   1. the credential is named "<id>.pin" INSIDE the blob. systemd checks that embedded name against
#      the LoadCredentialEncrypted= ID; the command PIN-CUSTODY.md used to document named nothing, so
#      the name defaulted to the file name and the service died with 243/CREDENTIALS (measured,
#      systemd 257, 2026-09-29);
#   2. TPM2 only, bound to the PCR set you name. There is no default: the set is chosen at
#      commissioning and recorded as guest.credential_tpm2_pcrs in the Proxmox evidence;
#   3. the card must be attached, be the serial you name, and have 3 user-PIN tries left (a lower
#      count means PINs were tried; find out why before sealing anything);
#   4. the PIN is typed twice, hidden (or read from stdin when stdin is not a terminal), must be 6-16
#      digits, and is TESTED on the card before sealing. A correct PIN resets the counter; a wrong one
#      spends ONE try, and nothing is sealed;
#   5. the blob is decrypted back and compared before it is installed; an existing credential is
#      only replaced with --replace, and the old one is kept as <file>.prev-<UTC time>.
# The PIN never reaches argv or the environment of a logged command; it is cleared on exit.
#
# BENCH ONLY: --bench-host-key seals with systemd's host key instead of the TPM (a guest without a
# TPM cannot be production). The record then says BENCH. REGALIA_CREDSTORE overrides the credstore
# directory, for tests.
set -uo pipefail
ID=""; SERIAL=""; PCRS=""; REPLACE=0; BENCH=0
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
CREDSTORE="${REGALIA_CREDSTORE:-/etc/credstore.encrypted}"
fail(){ printf 'seal-hsm-pin: FAIL: %s\n' "$*" >&2; exit 1; }
say(){ printf 'seal-hsm-pin: %s\n' "$*" >&2; }
while [ $# -gt 0 ]; do case "$1" in
  --id) ID="${2:-}"; shift 2;; --serial) SERIAL="${2:-}"; shift 2;; --pcrs) PCRS="${2:-}"; shift 2;;
  --replace) REPLACE=1; shift;; --bench-host-key) BENCH=1; shift;;
  -h|--help) sed -n '2,30p' "$0"; exit 0;; *) fail "unknown argument '$1' (see --help)";; esac; done

[[ "$ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || fail "--id must be lower-case words joined by '-', e.g. hsm-site-a"
[[ "$SERIAL" =~ ^DENK[0-9]{7}$ ]] || fail "--serial must be a Nitrokey serial like DENK0404144"
if [ "$BENCH" = 1 ]; then
  [ -z "$PCRS" ] || fail "--bench-host-key and --pcrs are exclusive: the host key has no PCR binding"
  KEYARGS=(--with-key=host); say "BENCH: sealing with the host key, NOT the TPM. This credential is not production."
else
  [[ "$PCRS" =~ ^[0-9]{1,2}(\+[0-9]{1,2})*$ ]] || fail "--pcrs is required, e.g. 7+11: the PCR set recorded at commissioning (no default)"
  KEYARGS=(--with-key=tpm2 "--tpm2-pcrs=$PCRS")
fi
[ "$(id -u)" = 0 ] || fail "run as root (sudo): systemd-creds and the credstore need it"
for t in systemd-creds opensc-tool pkcs11-tool sha256sum; do command -v "$t" >/dev/null || fail "$t is required"; done
if [ "$BENCH" = 0 ]; then systemd-creds has-tpm2 >/dev/null 2>&1 || fail "no usable TPM2 on this guest (systemd-creds has-tpm2)"; fi
NAME="$ID.pin"; DEST="$CREDSTORE/regalia-kms-$ID.pin"
if [ -e "$DEST" ] && [ "$REPLACE" = 0 ]; then fail "$DEST exists; pass --replace to rotate it (the old one is kept)"; fi

# ---- the card: attached, the right serial, a full counter --------------------------------------------
reader=""; while read -r line; do
  case "$line" in *"($SERIAL"*) [ -z "$reader" ] || fail "$SERIAL appears in more than one reader"; reader="$(awk '{print $1}' <<< "$line")";; esac
done < <(opensc-tool -l 2>/dev/null | grep -E '^[0-9]+[[:space:]]+Yes[[:space:]]' || true)
[ -n "$reader" ] || fail "no card $SERIAL attached (opensc-tool -l)"
tries(){ opensc-tool --reader "$reader" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
  | grep -oE 'SW1=0x63, SW2=0xC[0-9A-F]' | tail -1 | sed 's/.*0xC//'; }
t="$(tries)"; [ "$t" = 3 ] || fail "$SERIAL has ${t:-an unreadable number of} user-PIN tries left, not 3: someone has tried PINs; investigate before sealing"
slot="$(pkcs11-tool --module "$MODULE" -L 2>/dev/null | sed -n "s/^Slot [0-9]* (\(0x[0-9a-f]*\)): .*($SERIAL.*/\1/p" | head -1)"
[ -n "$slot" ] || fail "PKCS#11 cannot see $SERIAL"
say "card $SERIAL: reader $reader, PKCS#11 slot $slot, 3 tries left"

# ---- the PIN ---------------------------------------------------------------------------------------
PIN=""; PIN2=""; trap 'PIN=""; PIN2=""' EXIT
if [ -t 0 ]; then
  read -r -s -p "User PIN for $SERIAL, from the PIN card (hidden): " PIN; echo >&2
  read -r -s -p "Again: " PIN2; echo >&2
  [ "$PIN" = "$PIN2" ] || fail "the two entries differ; nothing was sealed"
else
  IFS= read -r PIN || true
fi
[[ "$PIN" =~ ^[0-9]{6,16}$ ]] || fail "a SmartCard-HSM user PIN here is 6-16 digits; nothing was sealed"
if ! err="$(PKCS11_PIN="$PIN" pkcs11-tool --module "$MODULE" --slot "$slot" --login --pin env:PKCS11_PIN --list-objects 2>&1 >/dev/null)"; then
  # Report what the counter SAYS, not what a failure usually means: OpenSC refuses some PINs itself
  # (e.g. CKR_DATA_LEN_RANGE, the wrong length for this card) without the card ever seeing them.
  left="$(tries)"; rv="$(grep -oE 'CKR_[A-Z_]+' <<< "$err" | head -1)"
  if [ "$left" = 3 ]; then fail "the PIN never reached $SERIAL (${rv:-login failed}): no try spent, still 3. Nothing was sealed. Check the PIN card"; fi
  fail "$SERIAL REFUSED this PIN (${rv:-login failed}): ${left:-an unknown number of} tries left. Nothing was sealed. Check the PIN card"
fi
say "the PIN opens $SERIAL (counter back at $(tries))"

# ---- seal, check, install ----------------------------------------------------------------------------
mkdir -p "$CREDSTORE" && chmod 700 "$CREDSTORE" || fail "cannot prepare $CREDSTORE"
tmp="$(mktemp "$CREDSTORE/.seal-XXXXXX")" || fail "cannot create a temporary file in $CREDSTORE"
trap 'PIN=""; PIN2=""; rm -f "$tmp"' EXIT
printf '%s' "$PIN" | systemd-creds encrypt "${KEYARGS[@]}" --name="$NAME" - "$tmp" 2>/dev/null \
  || fail "systemd-creds encrypt failed; nothing was installed"
back="$(systemd-creds decrypt --name="$NAME" "$tmp" - 2>/dev/null | sha256sum)"
[ "$back" = "$(printf '%s' "$PIN" | sha256sum)" ] || fail "the sealed blob does not decrypt back to the PIN; nothing was installed"
if [ -e "$DEST" ]; then mv "$DEST" "$DEST.prev-$(date -u +%Y%m%dT%H%M%SZ)" || fail "cannot keep the old credential"; fi
chmod 600 "$tmp" && mv "$tmp" "$DEST" || fail "cannot install $DEST"
PIN=""; PIN2=""

cat <<REC
SEALED
  credential id : $NAME
  file          : $DEST
  sha256        : $(sha256sum "$DEST" | cut -d' ' -f1)
  card          : $SERIAL
  key           : $([ "$BENCH" = 1 ] && echo "host (BENCH, not production)" || echo "tpm2, PCRs $PCRS")
  sealed at     : $(date -u +%FT%TZ)
Service drop-in line (/etc/systemd/system/regalia-kms.service.d/credentials.conf):
  LoadCredentialEncrypted=$NAME:$DEST
REC
