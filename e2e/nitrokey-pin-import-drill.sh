#!/usr/bin/env bash
# nitrokey-pin-import-drill.sh — (Nitrokey HSM PIN, or a YubiKey's PIV PIN) the PIN reaches a host's TPM ENCRYPTED, never typed or carried in
# clear (ADR-0002 D21): seal-hsm-pin.sh --init-import-key on "host A", the ceremony-side encryption
# (openssl RSA-OAEP SHA-256, exactly what step 0 does), then seal-hsm-pin.sh --from-blob on host A
# against a REAL Nitrokey. Two software TPMs (swtpm) stand in for two hosts' TPMs; the sealing itself
# uses the bench host key (this bench has no TPM for systemd-creds; the TPM2 seal is #46's).
#
#   sudo -v && NK_PIN=… e2e/nitrokey-pin-import-drill.sh <serial> <retries>
#
#   A  a blob made for A's TPM seals, and the sealed credential reads back as the PIN
#   B  a blob made for B's TPM is refused on A, and no card try is spent
#   C  an altered blob is refused, and no card try is spent
#   D  --init-import-key refuses to replace an existing key without --replace-import-key
# The card keeps its PIN and contents; its counter is checked at full before and after.
set -uo pipefail
SERIAL="${1:?serial: a Nitrokey (DENK0404144) or a YubiKey (36345471)}"; RETRIES="${2:?the full PIN counter of the device, e.g. 3}"
# A Nitrokey serial selects the HSM path; a numeric one selects a YubiKey's PIV PIN (--yubikey).
case "$SERIAL" in DENK*) DEV=(--serial "$SERIAL");; *) DEV=(--yubikey "$SERIAL");; esac
HERE="$(cd "$(dirname "$0")/.." && pwd)"; SEAL="$HERE/deploy/seal-hsm-pin.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
die(){ printf 'drill: %s\n' "$*" >&2; exit 2; }
[ -n "${NK_PIN:-}" ] || die "NK_PIN must hold the card's user PIN (environment, never argv)"
for t in swtpm tpm2_createprimary tpm2_rsadecrypt openssl systemd-creds opensc-tool pkcs11-tool; do command -v "$t" >/dev/null || die "$t is required"; done
sudo -n true 2>/dev/null || die "needs sudo (seal-hsm-pin.sh runs as root); run 'sudo -v' first"

W="$(mktemp -d)"; CRED="$W/credstore"
cleanup(){ for p in "$W"/swtpm-*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done; sudo rm -rf "$W"; }
trap cleanup EXIT
# UNIX SOCKETS, NOT TCP PORTS (see e2e/pin-import-swtpm.sh): no collision with another run on the machine.
tpm(){ local name="$1"; mkdir -p "$W/$name"
  swtpm socket --tpm2 --tpmstate "dir=$W/$name" --server "type=unixio,path=$W/$name.sock" --ctrl "type=unixio,path=$W/$name.sock.ctrl" \
    --flags not-need-init,startup-clear --daemon --pid "file=$W/swtpm-$name.pid" || die "swtpm $name did not start"; }
tpm A; tpm B; sleep 1
TA="swtpm:path=$W/A.sock"; TB="swtpm:path=$W/B.sock"
seal(){ local tcti="$1"; shift; sudo env TPM2TOOLS_TCTI="$tcti" REGALIA_CREDSTORE="$CRED" "$SEAL" "$@" 2>&1; }
tries(){ local r
  if [ "${DEV[0]}" = --yubikey ]; then ykman --device "$SERIAL" piv info 2>/dev/null | sed -n 's/^PIN tries remaining: *\([0-9]*\)\/.*/\1/p'; return; fi
  r="$(opensc-tool -l 2>/dev/null | awk -v s="($SERIAL" 'index($0,s){print $1; exit}')"
  opensc-tool --reader "$r" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
  | grep -oE 'SW1=0x63, SW2=0xC[0-9A-F]' | tail -1 | sed 's/.*0xC//' | xargs -I{} printf '%d' 0x{}; }
encrypt(){ printf '%s' "$NK_PIN" | openssl pkeyutl -encrypt -pubin -inkey "$1" -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out "$2"; }

[ "$(tries)" = "$RETRIES" ] || die "$SERIAL is not at its full $RETRIES tries ($(tries)); investigate first"

hdr "commissioning: an import key inside each host's TPM"
out="$(seal "$TA" --init-import-key --import-pub "$W/A.pub.pem")" && grep -q 'IMPORT KEY CREATED' <<< "$out" \
  && P "host A: import key created, public key exported" || F "host A init failed: $out"
out="$(seal "$TB" --init-import-key --import-pub "$W/B.pub.pem")" && P "host B: import key created" || F "host B init failed: $out"
fpA="$(openssl pkey -pubin -in "$W/A.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"
grep -q "$fpA" <<< "$(seal "$TA" --init-import-key --import-pub "$W/A2.pub.pem" 2>&1; true)" && F "D: a second init replaced the key silently" \
  || { out="$(seal "$TA" --init-import-key --import-pub "$W/A2.pub.pem")"; grep -q 'already holds a key' <<< "$out" && P "D: a second --init-import-key is refused without --replace-import-key" || F "D: no refusal: $out"; }

hdr "the ceremony side: the PIN encrypted to each host's public key"
encrypt "$W/A.pub.pem" "$W/pin-A.blob" && encrypt "$W/B.pub.pem" "$W/pin-B.blob" && P "blobs made (RSA-OAEP SHA-256, $(wc -c < "$W/pin-A.blob") bytes)" || F "encryption failed"
grep -qF "$NK_PIN" "$W/pin-A.blob" && F "the PIN is visible in the blob" || P "the blob does not contain the PIN"

hdr "B: a blob made for another host's TPM is refused"
out="$(seal "$TA" --id drill-import "${DEV[@]}" --retries "$RETRIES" --bench-host-key --from-blob "$W/pin-B.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'could not decrypt' <<< "$out" && P "refused: $(grep -o 'could not decrypt[^:]*' <<< "$out" | head -1)" || F "a blob for B was accepted on A: $out"
[ "$(tries)" = "$RETRIES" ] && P "no card try was spent" || F "a try was spent: $(tries) left"

hdr "C: an altered blob is refused"
# Flip one byte unconditionally (XOR with 0xFF), and prove the copy now differs.
python3 -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[100]^=0xFF; open(sys.argv[2],"wb").write(b)' "$W/pin-A.blob" "$W/bad.blob"
cmp -s "$W/pin-A.blob" "$W/bad.blob" && F "the altered blob is identical to the original"
out="$(seal "$TA" --id drill-import "${DEV[@]}" --retries "$RETRIES" --bench-host-key --from-blob "$W/bad.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'could not decrypt' <<< "$out" && P "an altered blob is refused" || F "an altered blob was accepted: $out"
[ "$(tries)" = "$RETRIES" ] && P "no card try was spent" || F "a try was spent: $(tries) left"

hdr "A: the right blob is decrypted by the TPM, tested on the card, sealed and read back"
out="$(seal "$TA" --id drill-import "${DEV[@]}" --retries "$RETRIES" --bench-host-key --from-blob "$W/pin-A.blob")"; rc=$?
[ "$rc" = 0 ] && grep -q '^SEALED' <<< "$out" && P "sealed from the blob" || F "seal from blob failed: $out"
grep -q 'PIN decrypted by the TPM' <<< "$out" && P "the PIN came from the TPM, not a prompt" || F "no TPM decryption reported"
back="$(sudo systemd-creds decrypt --name=drill-import.pin "$CRED/regalia-kms-drill-import.pin" - 2>/dev/null | sha256sum)"
[ "$back" = "$(printf '%s' "$NK_PIN" | sha256sum)" ] && P "the sealed credential reads back as the card's PIN" || F "sealed credential does not match the PIN"
grep -qF "$NK_PIN" <<< "$out" && F "the PIN appeared in the output" || P "the PIN never appears in the output"
[ "$(tries)" = "$RETRIES" ] && P "the card ends at its full $RETRIES tries" || F "the card ends at $(tries)"

echo; echo "pin-import drill ($SERIAL): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
