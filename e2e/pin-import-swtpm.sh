#!/usr/bin/env bash
# pin-import-swtpm.sh — seal-hsm-pin.sh's TPM-import half against a software TPM (swtpm), no card:
# it runs in CI on every change, where the hardware drill (nitrokey-pin-import-drill.sh) cannot.
#
#   sudo -v && e2e/pin-import-swtpm.sh
#
#   1  --init-import-key creates a persistent ECC P-256 storage key inside the TPM (exactly the import
#      template: restricted|decrypt, AES-128-CFB, noda) and exports its public key (0644) and SHA-256
#      fingerprint; a second run is refused without --replace-import-key, and --replace-import-key
#      makes a DIFFERENT key; the parent public area the ceremony rebuilds from the PEM is the TPM's,
#      byte for byte
#   2  a v2 blob made the ceremony's way (tpm2_duplicate --tcti none, no TPM) for THIS TPM imports,
#      loads and unseals, and the script goes on to look for the card (and stops there: there is none);
#      the sealed object's public unique is not SHA-256(PIN) and differs between two blobs of one PIN;
#      a blob sealing a value that is not a PIN is refused before the card is looked for
#   3  refused BEFORE any card is looked at: a blob for ANOTHER TPM (by its label, and relabelled as
#      this host's), an altered, truncated or padded blob, an RSA-OAEP blob from before #671 (with a
#      message saying so), and an unknown format version
#   4  --pcrs with 10 (IMA) or 11 (kernel image) is refused
#   5  #242: with the owner authorization set, --init-import-key needs it; --from-blob does NOT
#      (TPM2_Import authorizes the parent key, not the owner hierarchy)
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; SEAL="$HERE/deploy/seal-hsm-pin.sh"
# shellcheck source=e2e/lib/pin-blob-v2.sh
. "$HERE/e2e/lib/pin-blob-v2.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
for t in swtpm tpm2_createprimary tpm2_duplicate tpm2_import tpm2_unseal openssl systemd-creds python3; do
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
# OpenSC ignores a reader whose name CONTAINS an ignored_readers entry: the match is by SUBSTRING,
# so the single space below matches every reader name. If OpenSC ever matched by equality, this would
# ignore nothing and the cards would be enumerated again (regalia-kms#174).
printf 'app default {\n  ignored_readers = " ";\n}\n' > "$W/opensc-none.conf"
seal(){ local tcti="$1"; shift; sudo env TPM2TOOLS_TCTI="$tcti" REGALIA_CREDSTORE="$W/cred" OPENSC_CONF="$W/opensc-none.conf" "$SEAL" "$@" 2>&1; }
fp(){ openssl pkey -pubin -in "$1" -outform der | sha256sum | cut -d' ' -f1; }
PIN="7310048261"
mkdir -p "$W/cer"; chmod 700 "$W/cer"     # the "ceremony laptop"'s RAM workdir
enc(){ printf '%s' "$PIN" | pin_blob_v2 "$1" "$2" "$W/cer"; }
nocard(){ ! grep -q 'no card' <<< "$1"; }

hdr "1  the import key"
out="$(seal "$TA" --init-import-key --import-pub "$W/A.pem")" && grep -q 'IMPORT KEY CREATED' <<< "$out" \
  && P "created inside TPM A" || F "init failed: $out"
y="$(TPM2TOOLS_TCTI="$TA" tpm2_readpublic -c 0x81000101 2>/dev/null)"
attrs="$(awk '/^attributes:/{getline; print $2}' <<< "$y" | tr '|' '\n' | sort | paste -sd'|' -)"
[ "$attrs" = "decrypt|fixedparent|fixedtpm|noda|restricted|sensitivedataorigin|userwithauth" ] \
  && grep -q 'NIST p256' <<< "$y" && grep -q '^sym-keybits: 128' <<< "$y" && grep -A1 '^sym-mode:' <<< "$y" | grep -q cfb \
  && P "ECC P-256 storage key, AES-128-CFB, exactly $attrs" || F "template: $y"
[ "$(stat -c %a "$W/A.pem")" = 644 ] && P "public key exported 0644" || F "public key mode $(stat -c %a "$W/A.pem")"
grep -q "$(fp "$W/A.pem")" <<< "$out" && P "the printed fingerprint is the sha256 of the exported key" || F "fingerprint mismatch"
out="$(seal "$TA" --init-import-key --import-pub "$W/A2.pem")"; rc=$?
[ "$rc" != 0 ] && grep -q 'already holds a key' <<< "$out" && P "a second init is refused (exit $rc)" || F "a second init was not refused: $out"
fp1="$(fp "$W/A.pem")"
out="$(seal "$TA" --init-import-key --replace-import-key --import-pub "$W/A3.pem")"
[ "$(fp "$W/A3.pem")" != "$fp1" ] && P "--replace-import-key makes a different key" || F "replace kept the same key"
APUB="$W/A3.pem"   # the current key of TPM A (the files are root-owned; never copy over them)
seal "$TB" --init-import-key --import-pub "$W/B.pem" >/dev/null || F "TPM B init failed"
TPM2TOOLS_TCTI="$TA" tpm2_readpublic -Q -c 0x81000101 -f tss -o "$W/A.tss" 2>/dev/null
pin_parent_tpm2b "$APUB" "$W/A.rebuilt" && cmp -s "$W/A.tss" "$W/A.rebuilt" \
  && P "the parent public area rebuilt from the PEM and the pinned template is the TPM's, byte for byte" || F "rebuilt parent differs from the TPM's"

hdr "2  a v2 blob for this TPM is imported and unsealed (then the script looks for the card)"
enc "$APUB" "$W/a.blob" || F "the ceremony-side blob could not be made"
head -c 113 "$W/a.blob" | grep -q "^regalia-pin-blob v2 tpm2-import nist-p256 sha256=$(fp "$APUB")$" \
  && P "v2 header names the import key's fingerprint ($(wc -c < "$W/a.blob") bytes in all)" || F "header: $(head -c 113 "$W/a.blob")"
grep -qF "$PIN" "$W/a.blob" && F "the PIN is visible in the blob" || P "the PIN is not visible in the blob"
[ "$(sudo sh -c "ls '$W/cer'")" = "" ] && P "nothing is left in the ceremony workdir (no PIN file)" || F "left in the workdir: $(ls "$W/cer")"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/a.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'PIN unsealed by the TPM' <<< "$out" && grep -q 'no card DENK0000001 attached' <<< "$out" \
  && P "imported, loaded and unsealed by the TPM, then stopped at the card check (no card in CI)" || F "unexpected: $out"
grep -qF "$PIN" <<< "$out" && F "the PIN appeared in the output" || P "the PIN never appears in the output"
TPM2TOOLS_TCTI="$TA" tpm2_getcap handles-transient 2>/dev/null | grep -q 0x80 && F "transient objects left in TPM A" || P "no transient object left in TPM A"
# the unsealed bytes are exactly the PIN: the same import by hand
d="$W/byhand"; mkdir -p "$d"; python3 -I -c '
import sys; b=open(sys.argv[1],"rb").read()[114:]; o=0
for n in ("pub","dpriv","seed"):
    s=int.from_bytes(b[o:o+2],"big"); open(sys.argv[2]+"/"+n,"wb").write(b[o:o+2+s]); o+=2+s' "$W/a.blob" "$d"
got="$(export TPM2TOOLS_TCTI="$TA"; tpm2_import -Q -C 0x81000101 -u "$d/pub" -i "$d/dpriv" -s "$d/seed" -r "$d/priv" && tpm2_flushcontext -t \
  && tpm2_load -Q -C 0x81000101 -u "$d/pub" -r "$d/priv" -c "$d/o.ctx" && tpm2_unseal -c "$d/o.ctx" | od -An -tx1 | tr -d ' \n'; tpm2_flushcontext -t)"
[ "$got" = "$(printf '%s' "$PIN" | od -An -tx1 | tr -d ' \n')" ] && P "TPM2_Unseal gives exactly the PIN's bytes, no newline" || F "unsealed bytes $got"
# the sealed object's public area is in the clear in the blob: its `unique` must not let a PIN be checked
# against it (it is H(seedValue || PIN), the seedValue being secret and fresh in each blob), so it is not
# SHA-256(PIN), and two blobs of the same PIN carry different values
uniq(){ python3 -I -c '
import sys; b=open(sys.argv[1],"rb").read()[114:]
# TPM2B_PUBLIC: size, type KEYEDHASH, nameAlg SHA-256, attributes, empty authPolicy, scheme NULL, unique (32)
assert b[2:6]==bytes.fromhex("0008000b") and b[10:16]==bytes.fromhex("000000100020"), "not a sealed object public area"
print(b[16:48].hex())' "$1"; }
enc "$APUB" "$W/a2.blob" || F "a second blob of the same PIN could not be made"
ua="$(uniq "$W/a.blob")"; ua2="$(uniq "$W/a2.blob")"
[ "${#ua}" = 64 ] && [ "$ua" != "$(printf '%s' "$PIN" | sha256sum | cut -d' ' -f1)" ] \
  && [ "$ua" != "$(printf '%s\n' "$PIN" | sha256sum | cut -d' ' -f1)" ] \
  && P "the sealed object's public unique is not SHA-256(PIN)" || F "unique: ${ua:-unreadable} (SHA-256(PIN) or not parsed)"
[ "${#ua2}" = 64 ] && [ "$ua" != "$ua2" ] && P "two blobs of the same PIN have different unique values" || F "two blobs, unique $ua and ${ua2:-unreadable}"
# a well-made blob of a value that is not a PIN: refused once unsealed, before the card is looked for
printf '12ab5' | pin_blob_v2 "$APUB" "$W/notpin.blob" "$W/cer" || F "the not-a-PIN blob could not be made"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/notpin.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'is not a SmartCard-HSM user PIN' <<< "$out" && ! grep -q 'no card DENK0000001' <<< "$out" && ! grep -qF '12ab5' <<< "$out" \
  && P "a blob sealing a value that is not a PIN is refused before the card check, the value not printed (exit $rc)" || F "not a PIN: $out"

hdr "3  wrong, altered and old blobs are refused before any card is looked at"
enc "$W/B.pem" "$W/b.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/b.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'was made for the import key' <<< "$out" && nocard "$out" && P "a blob for TPM B is refused on A by its label, before the card check (exit $rc)" || F "B's blob: $out"
# B's blob relabelled with A's fingerprint: only the TPM can refuse it now
{ printf '%s%s\n' "$PIN_BLOB_HEADER" "$(fp "$APUB")"; tail -c +115 "$W/b.blob"; } > "$W/b-as-a.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/b-as-a.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'TPM could not import' <<< "$out" && nocard "$out" && P "B's blob relabelled as A's is refused by TPM A's import, before the card check (exit $rc)" || F "relabelled: $out"
alter(){ python3 -I -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[int(sys.argv[3])]^=0xFF; open(sys.argv[2],"wb").write(b)' "$@"; }
for at in 120 200 $(( $(wc -c < "$W/a.blob") - 5 )); do      # the public area, the duplicate, the seed
  alter "$W/a.blob" "$W/bad.blob" "$at"
  out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/bad.blob")"; rc=$?
  [ "$rc" != 0 ] && grep -qE 'could not (import|unseal)|cannot load|truncated' <<< "$out" && nocard "$out" && P "a byte altered at $at is refused before the card check (exit $rc)" || F "altered at $at: $out"
done
head -c $(( $(wc -c < "$W/a.blob") - 10 )) "$W/a.blob" > "$W/short.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/short.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'truncated' <<< "$out" && nocard "$out" && P "a truncated blob is refused (exit $rc)" || F "truncated: $out"
{ cat "$W/a.blob"; printf 'x'; } > "$W/long.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/long.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'bytes after its three parts' <<< "$out" && nocard "$out" && P "a blob with bytes appended is refused (exit $rc)" || F "padded: $out"
# format 1, as step 0 wrote it before #671: RSA-OAEP SHA-256 to an RSA-3072 key (a throwaway one here)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$W/old.key" 2>/dev/null
printf '%s' "$PIN" | openssl pkeyutl -encrypt -inkey "$W/old.key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256 -out "$W/old.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/old.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'RSA-OAEP PIN blob' <<< "$out" && grep -q 'format 1, before regalia-kms#671' <<< "$out" && grep -q 'ceremony step 0' <<< "$out" \
  && nocard "$out" && P "an RSA-OAEP blob from before #671 is refused, saying what it is and what to do (exit $rc)" || F "old blob: $out"
{ printf 'regalia-pin-blob v3 something\n'; tail -c +115 "$W/a.blob"; } > "$W/v3.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/v3.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'format v3, which this seal-hsm-pin.sh does not read' <<< "$out" && nocard "$out" && P "an unknown format version is refused (exit $rc)" || F "v3: $out"
printf 'not a blob at all\n' > "$W/junk.blob"
out="$(seal "$TA" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/junk.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'is not a PIN blob' <<< "$out" && nocard "$out" && P "a file that is no blob is refused (exit $rc)" || F "junk: $out"
out="$(seal "/dev/tpm0" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/a.blob")"; rc=$?
[ "$rc" != 0 ] && grep -q 'no resource manager' <<< "$out" && nocard "$out" && P "--from-blob refuses the raw /dev/tpm0 (exit $rc)" || F "raw tpm0: $out"

hdr "4  a PIN is never bound to PCR 10 (IMA) or 11 (kernel image) directly"
for p in 7+10 7+11 11; do
  out="$(seal "$TA" --id t --serial DENK0000001 --pcrs "$p")"; rc=$?
  [ "$rc" != 0 ] && grep -q 'must not include 10 (IMA) or 11' <<< "$out" && P "--pcrs $p refused (exit $rc)" || F "--pcrs $p: $out"
done

hdr "5  #242: with the TPM's owner authorization set, the import key only with the envelope's value (--ownerauth-stdin)"
tpm C; TC="swtpm:path=$W/C.sock"
hex(){ python3 -I -c 'import secrets; print(secrets.token_hex(32))'; }
OA="$(hex)"                                                     # a throwaway owner authorization, set as enrol ownerauth would
printf 'hex:%s' "$OA" > "$W/oa.auth"
TPM2TOOLS_TCTI="$TC" tpm2_changeauth -c o "file:$W/oa.auth" || F "could not set TPM C's owner authorization"
rm -f "$W/oa.auth"
out="$(seal "$TC" --init-import-key --import-pub "$W/C.pem" </dev/null)"; rc=$?
[ "$rc" != 0 ] && grep -q 'tpm2_createprimary failed' <<< "$out" && P "without the value, the TPM refuses the owner hierarchy (exit $rc)" || F "no value: $out"
out="$(printf '%s\n' "$OA" | seal "$TC" --init-import-key --import-pub "$W/C.pem" --ownerauth-stdin)"
grep -q 'IMPORT KEY CREATED' <<< "$out" && P "with the envelope's value on standard input, the key is made" || F "with the value: $out"
grep -qF "$OA" <<< "$out" && F "the owner authorization appeared in the output" || P "the owner authorization never appears in the output"
fpc="$(fp "$W/C.pem")"
out="$(printf '%s\n' "$(hex)" | seal "$TC" --init-import-key --replace-import-key --import-pub "$W/C2.pem" --ownerauth-stdin)"; rc=$?
[ "$rc" != 0 ] && grep -q 'cannot remove the old key' <<< "$out" && P "a wrong value is refused by the TPM (exit $rc)" || F "wrong value: $out"
TPM2TOOLS_TCTI="$TC" tpm2_readpublic -Q -c 0x81000101 -f pem -o "$W/C-after.pem" 2>/dev/null
[ "$(fp "$W/C-after.pem")" = "$fpc" ] && P "the key made with the right value is still there" || F "the key changed after a wrong value"
out="$(printf 'not-hex\n' | seal "$TC" --init-import-key --replace-import-key --import-pub "$W/C3.pem" --ownerauth-stdin)"; rc=$?
[ "$rc" != 0 ] && grep -q 'does not hold 64 lowercase hex' <<< "$out" && P "a value not in the envelope's form is refused before the TPM (exit $rc)" || F "bad form: $out"
enc "$W/C.pem" "$W/c.blob"
out="$(seal "$TC" --id t --serial DENK0000001 --bench-host-key --from-blob "$W/c.blob" </dev/null)"; rc=$?
[ "$rc" != 0 ] && grep -q 'PIN unsealed by the TPM' <<< "$out" && grep -q 'no card DENK0000001 attached' <<< "$out" \
  && P "--from-blob needs NO owner authorization: TPM2_Import authorizes the parent key, not the hierarchy" || F "from-blob with owner auth set: $out"
left="$(sudo sh -c 'ls -d /run/regalia-ownerauth.* 2>/dev/null')"
[ -z "$left" ] && P "no owner-authorization file is left on /run" || F "left on /run: $left"

echo; echo "pin-import-swtpm: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
