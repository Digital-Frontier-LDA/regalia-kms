#!/usr/bin/env bash
# seal-hsm-pin.sh — seal ONE Nitrokey's user PIN to this KMS guest's TPM2, as the systemd encrypted
# credential regalia-kms loads (ADR-0002 D2; PIN-CUSTODY.md). Run ONCE per site, as root, on the guest,
# with the card attached, typing the PIN from the sealed paper PIN card.
#
#   sudo deploy/seal-hsm-pin.sh --id hsm-site-a --serial DENK0404144 --pcrs 7 [--retries 10] [--replace]
#   sudo deploy/seal-hsm-pin.sh --id pico-staging --serial ESP41D722E2 --pcrs 7   (Pico HSM: staging only)
#   sudo deploy/seal-hsm-pin.sh --id yubikey-site-a --yubikey 36345471 --pcrs 7 [--retries 3]
#       the same for the PIV PIN of a YubiKey the KMS uses unattended (ADR-0002 D2; touch never): its
#       counter is read from PIV metadata (ykman), the PIN is tested through ykcs11.
#
# What it does, and refuses:
#   1. the credential is named "<id>.pin" INSIDE the blob. systemd checks that embedded name against
#      the LoadCredentialEncrypted= ID; the command PIN-CUSTODY.md used to document named nothing, so
#      the name defaulted to the file name and the service died with 243/CREDENTIALS (measured,
#      systemd 257, 2026-09-29);
#   2. TPM2 only, bound to the PCR set you name. There is no default: the set is chosen at
#      commissioning and recorded as guest.credential_tpm2_pcrs in the Proxmox evidence;
#   3. the card must be attached, be the serial you name, and have its FULL user-PIN counter left:
#      --retries, default 10, the production posture (a 10-digit PIN with a 10-try counter,
#      regalia PLAN.md 1.3). A lower count means PINs were tried; find out why before sealing;
#   4. the PIN is typed twice, hidden (or read from stdin when stdin is not a terminal), must be 6-16
#      digits, and is TESTED on the card before sealing. A correct PIN resets the counter; a wrong one
#      spends ONE try, and nothing is sealed;
#   5. the blob is decrypted back and compared before it is installed; an existing credential is
#      only replaced with --replace, and the old one is kept as <file>.prev-<UTC time>.
# The PIN never reaches argv or the environment of a logged command; it is cleared on exit.
#
# TPM IMPORT (ADR-0002 D21): the PIN can arrive ENCRYPTED to this host's TPM, so it is never typed here
# or carried in clear. Two extra modes:
#   sudo deploy/seal-hsm-pin.sh --init-import-key [--import-handle 0x81000101] [--import-pub FILE]
#       once, at commissioning: creates an RSA-3072 decryption key INSIDE the TPM (fixedTPM,
#       fixedParent, sensitiveDataOrigin: generated there, never leaves), persists it at the handle,
#       and writes its public key (PEM) and SHA-256 fingerprint. Copy the fingerprint BY HAND at the
#       console: the ceremony checks the public key against it before encrypting a PIN to it.
#   sudo deploy/seal-hsm-pin.sh --id … --serial … --pcrs … --from-blob pin-<site>.blob
#       the ceremony's RSA-OAEP (SHA-256) blob; the TPM decrypts it, then every check below runs as for
#       a typed PIN (card, counter, tested on the card, sealed, read back). A blob made for another
#       TPM, or altered, fails to decrypt and no card try is spent.
#
# BENCH ONLY: --bench-host-key seals with systemd's host key instead of the TPM (a guest without a
# TPM cannot be production). The record then says BENCH. REGALIA_CREDSTORE overrides the credstore
# directory, for tests.
set -uo pipefail
ID=""; SERIAL=""; YUBIKEY=""; PCRS=""; REPLACE=0; BENCH=0; RETRIES=""
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
CREDSTORE="${REGALIA_CREDSTORE:-/etc/credstore.encrypted}"
fail(){ printf 'seal-hsm-pin: FAIL: %s\n' "$*" >&2; exit 1; }
say(){ printf 'seal-hsm-pin: %s\n' "$*" >&2; }
INIT_IMPORT=0; FROM_BLOB=""; IMPORT_HANDLE="0x81000101"; IMPORT_PUB="/root/regalia-pin-import.pub.pem"; REPLACE_IMPORT=0
# A value-taking option with no value must fail, not loop: without set -e a failed `shift 2` would
# leave the argument in place and the loop would spin forever.
need(){ [ $# -ge 2 ] && [ -n "$2" ] || fail "$1 needs a value"; }
while [ $# -gt 0 ]; do case "$1" in
  --id) need "$@"; ID="$2"; shift 2;; --serial) need "$@"; SERIAL="$2"; shift 2;; --pcrs) need "$@"; PCRS="$2"; shift 2;;
  --yubikey) need "$@"; YUBIKEY="$2"; shift 2;;
  --replace) REPLACE=1; shift;; --bench-host-key) BENCH=1; shift;; --retries) need "$@"; RETRIES="$2"; shift 2;;
  --init-import-key) INIT_IMPORT=1; shift;; --replace-import-key) REPLACE_IMPORT=1; shift;;
  --from-blob) need "$@"; FROM_BLOB="$2"; shift 2;; --import-handle) need "$@"; IMPORT_HANDLE="$2"; shift 2;;
  --import-pub) need "$@"; IMPORT_PUB="$2"; shift 2;;
  -h|--help) sed -n '2,45p' "$0"; exit 0;; *) fail "unknown argument '$1' (see --help)";; esac; done
[[ "$IMPORT_HANDLE" =~ ^0x81[0-9a-fA-F]{6}$ ]] || fail "--import-handle must be a persistent handle, 0x81xxxxxx"

# ---- commissioning: the TPM-resident import key ---------------------------------------------------
if [ "$INIT_IMPORT" = 1 ]; then
  [ "$(id -u)" = 0 ] || fail "run as root (sudo)"
  for t in tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol tpm2_readpublic tpm2_flushcontext openssl; do
    command -v "$t" >/dev/null || fail "$t is required (tpm2-tools, openssl)"; done
  # Production goes through the kernel resource manager (/dev/tpmrm0, the tpm2-tools default), which
  # gives each connection its own transient objects and cleans them up: nothing to flush globally,
  # and flushing all transient objects or sessions (-t / -s) on a shared TPM would break other users.
  # A raw /dev/tpm0 has no resource manager and is refused. Only a PRIVATE simulator named in
  # TPM2TOOLS_TCTI (swtpm, mssim: the test's own TPM) has no manager and needs the transient objects
  # that each tool call leaves behind flushed between steps.
  case "${TPM2TOOLS_TCTI:-}" in
    *tpm0|*"/dev/tpm0"*) fail "TPM2TOOLS_TCTI points at /dev/tpm0 (no resource manager); use /dev/tpmrm0" ;;
  esac
  work="$(mktemp -d)"
  flush_own(){ local c; for c in "$work"/*.ctx; do [ -f "$c" ] && tpm2_flushcontext "$c" >/dev/null 2>&1; done
    case "${TPM2TOOLS_TCTI:-}" in swtpm*|mssim*) tpm2_flushcontext -t >/dev/null 2>&1 ;; esac; }
  trap 'flush_own; rm -rf "$work"' EXIT
  if tpm2_readpublic -Q -c "$IMPORT_HANDLE" >/dev/null 2>&1; then
    [ "$REPLACE_IMPORT" = 1 ] || fail "the TPM already holds a key at $IMPORT_HANDLE; pass --replace-import-key to make a new one (PIN blobs made for the old key stop working)"
    tpm2_evictcontrol -Q -C o -c "$IMPORT_HANDLE" >/dev/null || fail "cannot remove the old key at $IMPORT_HANDLE"
  fi
  flush_own
  tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb -c "$work/primary.ctx" || fail "tpm2_createprimary failed"
  tpm2_create -Q -C "$work/primary.ctx" -G rsa3072 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' \
    -u "$work/k.pub" -r "$work/k.priv" || fail "tpm2_create failed"
  flush_own
  tpm2_load -Q -C "$work/primary.ctx" -u "$work/k.pub" -r "$work/k.priv" -c "$work/k.ctx" || fail "tpm2_load failed"
  tpm2_evictcontrol -Q -C o -c "$work/k.ctx" "$IMPORT_HANDLE" >/dev/null || fail "cannot persist the key at $IMPORT_HANDLE"
  flush_own
  # tpm2_readpublic creates the file 0660 whatever the umask; it is a public key, readable by anyone.
  tpm2_readpublic -Q -c "$IMPORT_HANDLE" -f pem -o "$IMPORT_PUB" && chmod 0644 "$IMPORT_PUB" || fail "cannot export the public key"
  fp="$(openssl pkey -pubin -in "$IMPORT_PUB" -outform der | sha256sum | cut -d' ' -f1)"
  cat <<REC
IMPORT KEY CREATED (inside this TPM; the private half never leaves it)
  handle        : $IMPORT_HANDLE
  public key    : $IMPORT_PUB   (copy it to the ceremony laptop; it is not secret)
  sha256 (DER)  : $fp
Write the fingerprint down BY HAND from this console. The ceremony refuses a public key whose
fingerprint does not match what you wrote.
REC
  exit 0
fi

[[ "$ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || fail "--id must be lower-case words joined by '-', e.g. hsm-site-a"
# Two devices: a Nitrokey HSM (--serial DENK…, PIN tested through OpenSC) or a YubiKey whose PIV PIN
# the KMS uses unattended (--yubikey <serial>, PIN tested through ykcs11). Same sealing either way.
if [ -n "$YUBIKEY" ]; then
  [ -z "$SERIAL" ] || fail "--serial (Nitrokey) and --yubikey are exclusive: one device per credential"
  [[ "$YUBIKEY" =~ ^[0-9]{7,10}$ ]] || fail "--yubikey must be a YubiKey serial, e.g. 36345471"
  KIND=yubikey; SERIAL="$YUBIKEY"; RETRIES="${RETRIES:-3}"
  MODULE="${YKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/libykcs11.so}"
  [[ "$RETRIES" =~ ^([1-9]|1[0-5])$ ]] || fail "--retries is the YubiKey's PIV PIN counter, 1-15"
else
  # A Nitrokey HSM 2 (production, ADR-0002 D1) or a Pico HSM (staging only: the same SmartCard-HSM
  # applet and PIN/counter commands, so the same checks apply; its serial is 11 upper-case hex/letters).
  if [[ "$SERIAL" =~ ^DENK[0-9]{7}$ ]]; then KIND=nitrokey
  elif [[ "$SERIAL" =~ ^[0-9A-Z]{11}$ ]]; then KIND=pico; say "STAGING: $SERIAL is a Pico HSM; production PINs belong to a Nitrokey (ADR-0002 D1)."
  else fail "--serial must be a Nitrokey (DENK0404144) or Pico HSM (ESP41D722E2) serial, or use --yubikey <serial>"; fi
  RETRIES="${RETRIES:-10}"
  [[ "$RETRIES" =~ ^([1-9]|1[0-5])$ ]] || fail "--retries is the card's configured user-PIN counter, 1-15"
fi
if [ "$BENCH" = 1 ]; then
  [ -z "$PCRS" ] || fail "--bench-host-key and --pcrs are exclusive: the host key has no PCR binding"
  KEYARGS=(--with-key=host); say "BENCH: sealing with the host key, NOT the TPM. This credential is not production."
else
  [[ "$PCRS" =~ ^[0-9]{1,2}(\+[0-9]{1,2})*$ ]] || fail "--pcrs is required, e.g. 7: the PCR set recorded at commissioning (no default)"
  # Bound directly, PCR 10 (IMA) can never unseal: systemd decrypts the credential before regalia-kms
  # runs. PCR 11 (the kernel image) changes at every kernel update and would strand the PIN; it is
  # usable only through a signed PCR policy, which this script does not provision.
  case "+$PCRS+" in *+10+*|*+11+*) fail "--pcrs must not include 10 (IMA) or 11 (kernel image): bind 7 (deploy/baremetal/README.md, section 3)";; esac
  KEYARGS=(--with-key=tpm2 "--tpm2-pcrs=$PCRS")
fi
[ "$(id -u)" = 0 ] || fail "run as root (sudo): systemd-creds and the credstore need it"
for t in systemd-creds opensc-tool pkcs11-tool sha256sum; do command -v "$t" >/dev/null || fail "$t is required"; done
if [ "$KIND" = yubikey ]; then
  command -v ykman >/dev/null || fail "ykman is required for --yubikey (yubikey-manager)"
  [ -r "$MODULE" ] || fail "ykcs11 is required for --yubikey ($MODULE; package ykcs11, or set YKCS11_MODULE)"
fi
if [ -n "$FROM_BLOB" ]; then
  [ -r "$FROM_BLOB" ] || fail "--from-blob: cannot read $FROM_BLOB"
  command -v tpm2_rsadecrypt >/dev/null || fail "tpm2_rsadecrypt is required for --from-blob (tpm2-tools)"
fi
if [ "$BENCH" = 0 ]; then systemd-creds has-tpm2 >/dev/null 2>&1 || fail "no usable TPM2 on this guest (systemd-creds has-tpm2)"; fi
NAME="$ID.pin"; DEST="$CREDSTORE/regalia-kms-$ID.pin"
if [ -e "$DEST" ] && [ "$REPLACE" = 0 ]; then fail "$DEST exists; pass --replace to rotate it (the old one is kept)"; fi

# ---- a blob is decrypted FIRST, before any card is touched ------------------------------------------
# A blob made for another host's TPM, or altered, is refused here without reading a card at all.
PIN=""; PIN2=""; trap 'PIN=""; PIN2=""' EXIT
if [ -n "$FROM_BLOB" ]; then
  # Decrypted inside the TPM; the PIN goes straight into this variable, never to a file or argv.
  PIN="$(tpm2_rsadecrypt -c "$IMPORT_HANDLE" -s oaep -o /dev/stdout "$FROM_BLOB" 2>/dev/null | tr -d '\0')" \
    || PIN=""
  [ -n "$PIN" ] || fail "the TPM could not decrypt $FROM_BLOB: made for another host's TPM, altered, or the import key at $IMPORT_HANDLE is gone. No card was touched; nothing was sealed"
  say "PIN decrypted by the TPM from $FROM_BLOB"
fi

# ---- the card: attached, the right serial, a full counter --------------------------------------------
if [ "$KIND" = yubikey ]; then
  ykman list --serials 2>/dev/null | grep -qx "$SERIAL" || fail "no YubiKey $SERIAL attached (ykman list --serials)"
  # PIN metadata (firmware 5.3+): read without verifying anything, so it spends no try.
  tries(){ ykman --device "$SERIAL" piv info 2>/dev/null | sed -n 's/^PIN tries remaining: *\([0-9]*\)\/.*/\1/p'; }
  reader="ykman --device $SERIAL"
  slot="$(pkcs11-tool --module "$MODULE" -L 2>/dev/null | awk -v s="#$SERIAL" '/^Slot [0-9]+ \(0x/{sl=$3} index($0,s){gsub(/[():]/,"",sl); print sl; exit}')"
else
reader=""; while read -r line; do
  case "$line" in *"($SERIAL"*) [ -z "$reader" ] || fail "$SERIAL appears in more than one reader"; reader="$(awk '{print $1}' <<< "$line")";; esac
done < <(opensc-tool -l 2>/dev/null | grep -E '^[0-9]+[[:space:]]+Yes[[:space:]]' || true)
[ -n "$reader" ] || fail "no card $SERIAL attached (opensc-tool -l)"
# The count is the LOW NIBBLE of 63Cx, in hex: a 10-try card answers 63CA. Printed in decimal.
tries(){ local x; x="$(opensc-tool --reader "$reader" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
  | grep -oE 'SW1=0x63, SW2=0xC[0-9A-F]' | tail -1 | sed 's/.*0xC//')"; [ -n "$x" ] && printf '%d' "0x$x"; }
slot="$(pkcs11-tool --module "$MODULE" -L 2>/dev/null | sed -n "s/^Slot [0-9]* (\(0x[0-9a-f]*\)): .*($SERIAL.*/\1/p" | head -1)"
fi
t="$(tries)"; [ "$t" = "$RETRIES" ] || fail "$SERIAL has ${t:-an unreadable number of} user-PIN tries left, not its full $RETRIES: someone has tried PINs (or pass the card's real --retries); investigate before sealing"
[ -n "$slot" ] || fail "PKCS#11 cannot see $SERIAL"
say "card $SERIAL: reader $reader, PKCS#11 slot $slot, $t tries left (full)"

# ---- the PIN ---------------------------------------------------------------------------------------
if [ -n "$FROM_BLOB" ]; then
  : # decrypted above, before any card was touched
elif [ -t 0 ]; then
  read -r -s -p "User PIN for $SERIAL, from the PIN card (hidden): " PIN; echo >&2
  read -r -s -p "Again: " PIN2; echo >&2
  [ "$PIN" = "$PIN2" ] || fail "the two entries differ; nothing was sealed"
else
  IFS= read -r PIN || true
fi
if [ "$KIND" = yubikey ]; then
  [[ "$PIN" =~ ^[0-9]{6,8}$ ]] || fail "a YubiKey PIV PIN here is 6-8 digits; nothing was sealed"
else
  [[ "$PIN" =~ ^[0-9]{6,16}$ ]] || fail "a SmartCard-HSM user PIN here is 6-16 digits; nothing was sealed"
fi
if ! err="$(PKCS11_PIN="$PIN" pkcs11-tool --module "$MODULE" --slot "$slot" --login --pin env:PKCS11_PIN --list-objects 2>&1 >/dev/null)"; then
  # Report what the counter SAYS, not what a failure usually means: OpenSC refuses some PINs itself
  # (e.g. CKR_DATA_LEN_RANGE, the wrong length for this card) without the card ever seeing them.
  left="$(tries)"; rv="$(grep -oE 'CKR_[A-Z_]+' <<< "$err" | head -1)"
  if [ "$left" = "$RETRIES" ]; then fail "the PIN never reached $SERIAL (${rv:-login failed}): no try spent, still $RETRIES. Nothing was sealed. Check the PIN card"; fi
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
# The old credential stays IN PLACE until the new one replaces it in one rename: moving it aside
# first would leave the service with no credential (243 at its next start) if the install failed.
if [ -e "$DEST" ]; then cp -p "$DEST" "$DEST.prev-$(date -u +%Y%m%dT%H%M%SZ)" || fail "cannot keep a copy of the old credential; nothing was changed"; fi
chmod 600 "$tmp" && mv -f "$tmp" "$DEST" || fail "cannot install $DEST; the previous credential (if any) is still in place"
PIN=""; PIN2=""

cat <<REC
SEALED
  credential id : $NAME
  file          : $DEST
  sha256        : $(sha256sum "$DEST" | cut -d' ' -f1)
  device        : $KIND $SERIAL
  key           : $([ "$BENCH" = 1 ] && echo "host (BENCH, not production)" || echo "tpm2, PCRs $PCRS")
  sealed at     : $(date -u +%FT%TZ)
Service drop-in line (/etc/systemd/system/regalia-kms.service.d/credentials.conf):
  LoadCredentialEncrypted=$NAME:$DEST
REC
