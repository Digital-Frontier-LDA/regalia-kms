#!/usr/bin/env bash
# nitrokey-pin-import-drill.sh — (Nitrokey HSM PIN, or a YubiKey's PIV PIN) the PIN reaches a host's TPM ENCRYPTED, never typed or carried in
# clear (ADR-0002 D21): seal-hsm-pin.sh --init-import-key on "host A", the ceremony-side wrapping
# (a v2 blob: tpm2_duplicate --tcti none to the ECC P-256 import key, as step 0 does; #671), then
# seal-hsm-pin.sh --from-blob on host A
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
# A Nitrokey is the ONLY card OpenSC sees during the drill, and every step that can present the PIN is
# gated on its serial (e2e/lib/bench_cards.sh, regalia-kms#174). A YubiKey is reached by ykman --device
# <serial>, which is gated by construction.
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
for t in swtpm tpm2_createprimary tpm2_duplicate tpm2_import tpm2_unseal openssl systemd-creds opensc-tool pkcs11-tool; do command -v "$t" >/dev/null || die "$t is required"; done
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
# #702: each software TPM gets its EK and AK (as enrol init makes them) and the verifier's credential to them, with no
# TPM; --init-import-key opens it, then has the AK certify the key. Inline (e2e/lib/import-key-cert.sh's ikc_ready): a
# drill sources no script but the bench gate library (tests/test_e2e_card_isolation.py)
for h in A B; do mkdir -p "$W/id$h"
  TPM2TOOLS_TCTI="swtpm:path=$W/$h.sock" python3 -Es "$HERE/deploy/baremetal/attest.py" node-init --out "$W/id$h" >/dev/null 2>&1 \
    && (cd "$HERE" && python3 -Es -m deploy.baremetal.importkey challenge --ek-public "$W/id$h/ek.pub" --ak-public "$W/id$h/ak.pub" \
      --credential "$W/id$h/cred.bin" --keep "$W/id$h/keep.json") >/dev/null || die "host $h: cannot make the EK, AK and credential (#702)"
done
CA=(--ak-credential "$W/idA/cred.bin" --certification "$W/A.cert.json"); CB=(--ak-credential "$W/idB/cred.bin" --certification "$W/B.cert.json")
# shellcheck source=lib/bench_cards.sh
. "$HERE/e2e/lib/bench_cards.sh"
if [ "${DEV[0]}" = --serial ]; then
  bench_isolate "$W/opensc.conf" "${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}" "$SERIAL" || die "cannot isolate $SERIAL in OpenSC"
fi
# seal-hsm-pin.sh presents the PIN to the card (it tests it before sealing). Under sudo it gets the
# isolated OpenSC configuration, and it is not run unless the one card visible is this serial.
seal(){ local tcti="$1"; shift
  if [ "${DEV[0]}" = --serial ]; then bench_gate "$SERIAL" || { echo "drill: $SERIAL is not the one card visible: seal-hsm-pin.sh not run"; return 97; }; fi
  # The same module and configuration the gate looked through.
  sudo env TPM2TOOLS_TCTI="$tcti" REGALIA_CREDSTORE="$CRED" ${OPENSC_CONF:+OPENSC_CONF="$OPENSC_CONF"} \
    ${HSM_PKCS11_MODULE:+HSM_PKCS11_MODULE="$HSM_PKCS11_MODULE"} "$SEAL" "$@" 2>&1; }
tries(){ local r
  if [ "${DEV[0]}" = --yubikey ]; then ykman --device "$SERIAL" piv info 2>/dev/null | sed -n 's/^PIN tries remaining: *\([0-9]*\)\/.*/\1/p'; return; fi
  r="$(opensc-tool -l 2>/dev/null | awk -v s="($SERIAL" 'index($0,s){print $1; exit}')"
  opensc-tool --reader "$r" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
  | grep -oE 'SW1=0x63, SW2=0xC[0-9A-F]' | tail -1 | sed 's/.*0xC//' | xargs -I{} printf '%d' 0x{}; }
# The v2 blob, as ceremony step 0 makes it: inlined, not sourced, from e2e/lib/pin-blob-v2.sh (keep the two
# identical), because a real-card drill sources nothing the card-isolation check does not read
# (tests/test_e2e_card_isolation.py).
# The DER SubjectPublicKeyInfo of an uncompressed P-256 point: these 26 bytes, 04, X (32), Y (32).
PIN_P256_SPKI_PREFIX=3059301306072a8648ce3d020106082a8648ce3d030107034200
# The import key's template, as seal-hsm-pin.sh --init-import-key creates it, marshalled up to the point:
# type ECC, nameAlg SHA-256, attributes fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|
# restricted|decrypt (0x00030472), empty authPolicy, symmetric AES-128-CFB, scheme NULL, curve NIST P-256,
# kdf NULL. The size (0x005a, 90) is that of the whole TPMT_PUBLIC with a 32-byte X and Y.
PIN_PARENT_TEMPLATE=005a0023000b000304720000000600800043001000030010
PIN_BLOB_HEADER="regalia-pin-blob v2 tpm2-import nist-p256 sha256="

pin_hex_to_bin(){ printf '%b' "$(sed 's/../\\x&/g' <<< "$1")"; }

pin_parent_tpm2b(){
  local hex
  hex="$(openssl pkey -pubin -in "$1" -outform der 2>/dev/null | od -An -tx1 -v | tr -d ' \n')" || return 1
  [ "${#hex}" = 182 ] && [ "${hex:0:54}" = "${PIN_P256_SPKI_PREFIX}04" ] || { echo "pin-blob: $1 is not a P-256 public key" >&2; return 1; }
  pin_hex_to_bin "${PIN_PARENT_TEMPLATE}0020${hex:54:64}0020${hex:118:64}" > "$2"
}

pin_blob_v2(){
  local pem="$1" out="$2" d="$3" fp
  rm -f "$out"
  fp="$(openssl pkey -pubin -in "$pem" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1)" || return 1
  pin_parent_tpm2b "$pem" "$d/parent.tpm2b" || return 1
  # tpm2_duplicate seeks its input, so the PIN is a file (the caller's private directory), removed at once
  (umask 077; cat > "$d/pin")
  tpm2_duplicate --tcti none -U "$d/parent.tpm2b" -G keyedhash -k "$d/pin" -a 'userwithauth|noda' \
    -u "$d/obj.pub" -r "$d/obj.dpriv" -s "$d/obj.seed" >/dev/null 2>&1; local rc=$?
  rm -f "$d/pin"
  [ "$rc" = 0 ] || { echo "pin-blob: tpm2_duplicate failed" >&2; return 1; }
  { printf '%s%s\n' "$PIN_BLOB_HEADER" "$fp"; cat "$d/obj.pub" "$d/obj.dpriv" "$d/obj.seed"; } > "$out"
  rm -f "$d/obj.pub" "$d/obj.dpriv" "$d/obj.seed" "$d/parent.tpm2b"
}
mkdir -p "$W/cer"; chmod 700 "$W/cer"
encrypt(){ printf '%s' "$NK_PIN" | pin_blob_v2 "$1" "$2" "$W/cer"; }

[ "$(tries)" = "$RETRIES" ] || die "$SERIAL is not at its full $RETRIES tries ($(tries)); investigate first"

hdr "commissioning: an import key inside each host's TPM"
out="$(seal "$TA" --init-import-key "${CA[@]}" --import-pub "$W/A.pub.pem")" && grep -q 'IMPORT KEY CREATED' <<< "$out" \
  && P "host A: import key created, public key exported" || F "host A init failed: $out"
out="$(seal "$TB" --init-import-key "${CB[@]}" --import-pub "$W/B.pub.pem")" && P "host B: import key created" || F "host B init failed: $out"
fpA="$(openssl pkey -pubin -in "$W/A.pub.pem" -outform der | sha256sum | cut -d' ' -f1)"
grep -q "$fpA" <<< "$(seal "$TA" --init-import-key "${CA[@]}" --import-pub "$W/A2.pub.pem" 2>&1; true)" && F "D: a second init replaced the key silently" \
  || { out="$(seal "$TA" --init-import-key "${CA[@]}" --import-pub "$W/A2.pub.pem")"; grep -q 'already holds a key' <<< "$out" && P "D: a second --init-import-key is refused without --replace-import-key" || F "D: no refusal: $out"; }

hdr "the ceremony side: the PIN wrapped to each host's import key (v2 blob)"
encrypt "$W/A.pub.pem" "$W/pin-A.blob" && encrypt "$W/B.pub.pem" "$W/pin-B.blob" && P "blobs made (v2, TPM2 duplication to P-256, $(wc -c < "$W/pin-A.blob") bytes)" || F "wrapping failed"
grep -qF "$NK_PIN" "$W/pin-A.blob" && F "the PIN is visible in the blob" || P "the blob does not contain the PIN"

hdr "B: a blob made for another host's TPM is refused"
out="$(seal "$TA" --id drill-import "${DEV[@]}" --retries "$RETRIES" --bench-host-key --from-blob "$W/pin-B.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'was made for the import key' <<< "$out" && P "refused: $(grep -o 'was made for the import key[^:]*' <<< "$out" | head -1)" || F "a blob for B was accepted on A: $out"
[ "$(tries)" = "$RETRIES" ] && P "no card try was spent" || F "a try was spent: $(tries) left"

hdr "C: an altered blob is refused"
# Flip one byte unconditionally (XOR with 0xFF), and prove the copy now differs.
python3 -I -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[200]^=0xFF; open(sys.argv[2],"wb").write(b)' "$W/pin-A.blob" "$W/bad.blob"
cmp -s "$W/pin-A.blob" "$W/bad.blob" && F "the altered blob is identical to the original"
out="$(seal "$TA" --id drill-import "${DEV[@]}" --retries "$RETRIES" --bench-host-key --from-blob "$W/bad.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'TPM could not import' <<< "$out" && P "an altered blob is refused" || F "an altered blob was accepted: $out"
[ "$(tries)" = "$RETRIES" ] && P "no card try was spent" || F "a try was spent: $(tries) left"

hdr "A: the right blob is imported and unsealed by the TPM, tested on the card, sealed and read back"
out="$(seal "$TA" --id drill-import "${DEV[@]}" --retries "$RETRIES" --bench-host-key --from-blob "$W/pin-A.blob")"; rc=$?
[ "$rc" = 0 ] && grep -q '^SEALED' <<< "$out" && P "sealed from the blob" || F "seal from blob failed: $out"
grep -q 'PIN unsealed by the TPM' <<< "$out" && P "the PIN came from the TPM, not a prompt" || F "no TPM unseal reported"
back="$(sudo systemd-creds decrypt --name=drill-import.pin "$CRED/regalia-kms-drill-import.pin" - 2>/dev/null | sha256sum)"
[ "$back" = "$(printf '%s' "$NK_PIN" | sha256sum)" ] && P "the sealed credential reads back as the card's PIN" || F "sealed credential does not match the PIN"
grep -qF "$NK_PIN" <<< "$out" && F "the PIN appeared in the output" || P "the PIN never appears in the output"
[ "$(tries)" = "$RETRIES" ] && P "the card ends at its full $RETRIES tries" || F "the card ends at $(tries)"

echo; echo "pin-import drill ($SERIAL): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
