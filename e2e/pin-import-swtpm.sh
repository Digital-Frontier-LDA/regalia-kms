#!/usr/bin/env bash
# pin-import-swtpm.sh — seal-hsm-pin.sh's TPM-import half against a software TPM (swtpm), no card:
# it runs in CI on every change, where the hardware drill (nitrokey-pin-import-drill.sh) cannot.
#
#   sudo -v && e2e/pin-import-swtpm.sh
#
#   1  --init-import-key creates a persistent RSA-3072 key inside the TPM and exports its public key
#      (0644) and SHA-256 fingerprint; a second run is refused without --replace-import-key, and
#      --replace-import-key makes a DIFFERENT key
#   2  a blob made the ceremony's way (openssl RSA-OAEP SHA-256) for THIS TPM decrypts, and the
#      script goes on to look for the card (and stops there: there is none)
#   3  a blob for ANOTHER TPM, and an altered blob, are refused BEFORE any card is looked at
#   4  --pcrs with 10 (IMA) or 11 (kernel image) is refused
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; SEAL="$HERE/deploy/seal-hsm-pin.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
for t in swtpm tpm2_createprimary tpm2_rsadecrypt openssl systemd-creds; do
  command -v "$t" >/dev/null || { echo "pin-import-swtpm: $t is required (swtpm, tpm2-tools, openssl, systemd)"; exit 2; }
done
sudo -n true 2>/dev/null || { echo "pin-import-swtpm: needs sudo"; exit 2; }
W="$(mktemp -d)"
stop(){ for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done; }
trap 'stop; sudo rm -rf "$W"' EXIT
# UNIX SOCKETS, NOT TCP PORTS: fixed ports collide when two runs share a machine (seen 2026-10-02), and a
# free port's +1 control port is never reserved. Each TPM gets <dir>/<name>.sock and .sock.ctrl.
tpm(){ mkdir -p "$W/$1"; swtpm socket --tpm2 --tpmstate "dir=$W/$1" --server "type=unixio,path=$W/$1.sock" \
  --ctrl "type=unixio,path=$W/$1.sock.ctrl" --flags not-need-init,startup-clear --daemon --pid "file=$W/$1.pid" \
    || { echo "pin-import-swtpm: swtpm $1 did not start (socket $W/$1.sock; a long TMPDIR can exceed the 108-byte limit)"; exit 2; }
  local _; for _ in $(seq 1 50); do [ -S "$W/$1.sock" ] && return 0; sleep 0.1; done
  echo "pin-import-swtpm: swtpm $1's socket never appeared"; exit 2; }
tpm A; tpm B
TA="swtpm:path=$W/A.sock"; TB="swtpm:path=$W/B.sock"
# NO CARD, AND NO BENCH: seal-hsm-pin.sh goes on to look for the card (opensc-tool, pkcs11-tool, as root).
# In CI there is no reader; on a machine with tokens attached, a default OpenSC config would enumerate
# every card as root and leave a YubiKey's PIV applet selected (that cost three PIV PIN tries on
# 2026-10-02 elsewhere). Every reader is ignored (every PC/SC reader name contains a space).
printf 'app default {\n  ignored_readers = " ";\n}\n' > "$W/opensc-none.conf"
seal(){ local tcti="$1"; shift; sudo env TPM2TOOLS_TCTI="$tcti" REGALIA_CREDSTORE="$W/cred" OPENSC_CONF="$W/opensc-none.conf" "$SEAL" "$@" 2>&1; }
fp(){ openssl pkey -pubin -in "$1" -outform der | sha256sum | cut -d' ' -f1; }
PIN="7310048261"
enc(){ printf '%s' "$PIN" | openssl pkeyutl -encrypt -pubin -inkey "$1" -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out "$2"; }

hdr "1  the import key"
out="$(seal "$TA" --init-import-key --import-pub "$W/A.pem")" && grep -q 'IMPORT KEY CREATED' <<< "$out" \
  && P "created inside TPM A" || F "init failed: $out"
[ "$(stat -c %a "$W/A.pem")" = 644 ] && P "public key exported 0644" || F "public key mode $(stat -c %a "$W/A.pem")"
grep -q "$(fp "$W/A.pem")" <<< "$out" && P "the printed fingerprint is the sha256 of the exported key" || F "fingerprint mismatch"
out="$(seal "$TA" --init-import-key --import-pub "$W/A2.pem")"; rc=$?
[ "$rc" != 0 ] && grep -q 'already holds a key' <<< "$out" && P "a second init is refused (exit $rc)" || F "a second init was not refused: $out"
fp1="$(fp "$W/A.pem")"
out="$(seal "$TA" --init-import-key --replace-import-key --import-pub "$W/A3.pem")"
[ "$(fp "$W/A3.pem")" != "$fp1" ] && P "--replace-import-key makes a different key" || F "replace kept the same key"
APUB="$W/A3.pem"   # the current key of TPM A (the files are root-owned; never copy over them)
seal "$TB" --init-import-key --import-pub "$W/B.pem" >/dev/null || F "TPM B init failed"

hdr "2  a blob for this TPM decrypts (then the script looks for the card)"
enc "$APUB" "$W/a.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/a.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'PIN decrypted by the TPM' <<< "$out" && grep -q 'no card DENK0000001 attached' <<< "$out" \
  && P "decrypted by the TPM, then stopped at the card check (no card in CI)" || F "unexpected: $out"
grep -qF "$PIN" <<< "$out" && F "the PIN appeared in the output" || P "the PIN never appears in the output"

hdr "3  wrong or altered blobs are refused before any card is looked at"
enc "$W/B.pem" "$W/b.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/b.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'could not decrypt' <<< "$out" && ! grep -q 'no card' <<< "$out" && P "a blob for TPM B is refused on A, before the card check (exit $rc)" || F "B's blob: $out"
python3 -I -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[100]^=0xFF; open(sys.argv[2],"wb").write(b)' "$W/a.blob" "$W/bad.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/bad.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'could not decrypt' <<< "$out" && ! grep -q 'no card' <<< "$out" && P "an altered blob is refused before the card check (exit $rc)" || F "altered blob: $out"

hdr "4  a PIN is never bound to PCR 10 (IMA) or 11 (kernel image) directly"
for p in 7+10 7+11 11; do
  out="$(seal "$TA" --id t --serial DENK0000001 --pcrs "$p")"; rc=$?
  [ "$rc" != 0 ] && grep -q 'must not include 10 (IMA) or 11' <<< "$out" && P "--pcrs $p refused (exit $rc)" || F "--pcrs $p: $out"
done

echo; echo "pin-import-swtpm: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
