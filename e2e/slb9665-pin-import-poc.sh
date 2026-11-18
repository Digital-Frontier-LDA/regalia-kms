#!/usr/bin/env bash
# slb9665-pin-import-poc.sh — does THIS TPM take the #671 Option B PIN import (PIN-IMPORT-DESIGN.md)?
# Written for the DL360 Gen9's Infineon SLB9665. NOT RUN on any physical TPM yet: the owner must
# authorise the run on a named host.
#
#   sudo e2e/slb9665-pin-import-poc.sh --transient-only           on the host, through /dev/tpmrm0
#   TPM2TOOLS_TCTI=swtpm:path=… e2e/slb9665-pin-import-poc.sh --transient-only    (a software TPM, to try the script)
#
# What it does, every object TRANSIENT, under the NULL hierarchy:
#   1  tpm2_testparms rsa2048 rsa3072 ecc256 ecc384 (read-only)
#   2  reads TPM2_PT_LOCKOUT_COUNTER (read-only)
#   3  a primary storage key under the NULL hierarchy (TPM_RH_NULL: no authorization, gone at reboot)
#   4  under it, a child with EXACTLY the import key's template (ECC P-256, AES-128-CFB,
#      fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda), loaded, NOT persisted
#   5  a v2 blob of a TEST value (not a PIN) made the ceremony's way, offline (tpm2_duplicate --tcti none),
#      from the child's PEM and the pinned template; the rebuilt parent compared with the TPM's, byte for byte;
#      the sealed object's public unique is not SHA-256 of the value, and differs between two blobs of it
#   6  TPM2_Import + TPM2_Load + TPM2_Unseal under the child: the test value back, exactly
#   7  a relabelled and an altered blob: TPM2_Import must refuse both
#   8  TPM2_PT_LOCKOUT_COUNTER read again: it must not have moved
#
# TPM STATE IT CHANGES: transient object slots only, for the run (the kernel resource manager flushes
# them when each tool exits; nothing is flushed globally), and the TPM's RNG is drawn on. It does NOT:
# make or evict a persistent handle (0x81000101 or any other), write NV, use or need the owner,
# endorsement, platform or lockout authorization, change the dictionary-attack settings, or clear
# anything. No authorization is ever presented, so no failed try can be counted. On a raw /dev/tpm0
# (no resource manager) it refuses to run.
# What commissioning (seal-hsm-pin.sh --init-import-key) changes instead, for comparison: persistent handle
# 0x81000101 (TPM2_EvictControl under the owner hierarchy: NV), with the owner authorization if one is set
# (--ownerauth-stdin, #242). --from-blob needs no hierarchy authorization (TPM2_Import authorizes the parent key).
set -uo pipefail
export LC_ALL=C
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=e2e/lib/pin-blob-v2.sh
. "$HERE/e2e/lib/pin-blob-v2.sh"
pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
die(){ printf 'slb9665-poc: %s\n' "$*" >&2; exit 2; }
[ "${1:-}" = --transient-only ] || die "pass --transient-only to confirm the scope above (read the header first)"
case "${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}" in
  *tpm0|*"/dev/tpm0"*) die "TPM2TOOLS_TCTI points at /dev/tpm0 (no resource manager): transient objects would stay behind; use /dev/tpmrm0" ;;
esac
for t in tpm2_testparms tpm2_getcap tpm2_createprimary tpm2_create tpm2_load tpm2_readpublic tpm2_duplicate tpm2_import \
         tpm2_unseal tpm2_flushcontext openssl python3; do command -v "$t" >/dev/null || die "$t is required (tpm2-tools, openssl, python3)"; done
W="$(mktemp -d)"; chmod 700 "$W"; mkdir -p "$W/cer"
# a private simulator has no resource manager: flush what this run made (never with a real TPM, where -t is global)
sim_flush(){ case "${TPM2TOOLS_TCTI:-}" in swtpm*|mssim*) tpm2_flushcontext -t >/dev/null 2>&1 ;; esac; }
trap 'sim_flush; rm -rf "$W"' EXIT
counter(){ tpm2_getcap properties-variable 2>/dev/null | awk '/^TPM2_PT_LOCKOUT_COUNTER:/{print $2}'; }
echo "slb9665-poc: TCTI ${TPM2TOOLS_TCTI:-device:/dev/tpmrm0 (default)}; $(tpm2_getcap properties-fixed 2>/dev/null \
  | awk '/TPM2_PT_MANUFACTURER:/{getline; m=$2} /TPM2_PT_FIRMWARE_VERSION_1:/{getline; f=$2} END{print "manufacturer " m ", firmware " f}')"

echo "1  tpm2_testparms"
for p in rsa2048 rsa3072 ecc256 ecc384; do
  if tpm2_testparms "$p" >/dev/null 2>&1; then echo "     $p supported"; else echo "     $p NOT supported"; fi
done
tpm2_testparms ecc256:aes128cfb >/dev/null 2>&1 && P "ecc256 with AES-128-CFB is supported (the import key's parameters)" \
  || { F "ecc256:aes128cfb is not supported: Option B cannot run on this TPM"; echo; echo "slb9665-poc: $pass passed, $fail failed"; exit 1; }

echo "2  dictionary-attack counter before"; before="$(counter)"; echo "     TPM2_PT_LOCKOUT_COUNTER $before"

echo "3, 4  a transient parent with the import key's template, under the NULL hierarchy"
tpm2_createprimary -Q -C n -g sha256 -G ecc256:aes128cfb \
  -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' -c "$W/primary.ctx" \
  && P "transient primary under TPM_RH_NULL" || F "tpm2_createprimary -C n failed"
sim_flush    # (a simulator only: each tool reloads the saved contexts below from their files)
tpm2_create -Q -C "$W/primary.ctx" -G ecc256:aes128cfb -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda' \
  -u "$W/k.pub" -r "$W/k.priv" && P "the import key's template is accepted by TPM2_Create" || F "tpm2_create (the import key's template) failed"
sim_flush
tpm2_load -Q -C "$W/primary.ctx" -u "$W/k.pub" -r "$W/k.priv" -c "$W/k.ctx" && P "loaded (transient, not persisted)" || F "tpm2_load failed"
sim_flush
tpm2_readpublic -Q -c "$W/k.ctx" -f pem -o "$W/k.pem" && tpm2_readpublic -Q -c "$W/k.ctx" -f tss -o "$W/k.tss" || F "tpm2_readpublic failed"
echo "     fingerprint (the by-hand one, for this throwaway key): $(openssl pkey -pubin -in "$W/k.pem" -outform der | sha256sum | cut -d' ' -f1)"

echo "5  a v2 blob of a test value, made the ceremony's way (offline)"
pin_parent_tpm2b "$W/k.pem" "$W/k.rebuilt" && cmp -s "$W/k.tss" "$W/k.rebuilt" \
  && P "the pinned template rebuilt from the PEM is this TPM's public area, byte for byte" || F "the rebuilt parent differs from this TPM's"
VALUE="0123456789"     # a test value, never a real PIN
printf '%s' "$VALUE" | pin_blob_v2 "$W/k.pem" "$W/t.blob" "$W/cer" && P "blob made ($(wc -c < "$W/t.blob") bytes)" || F "blob not made"
# the sealed object's public area travels in the clear: its unique is H(seedValue || value), so it is not
# SHA-256(value) and differs between two blobs of the same value (offline: tpm2_duplicate --tcti none, no TPM)
uniq(){ python3 -I -c '
import sys; b=open(sys.argv[1],"rb").read()[114:]
assert b[2:6]==bytes.fromhex("0008000b") and b[10:16]==bytes.fromhex("000000100020"), "not a sealed object public area"
print(b[16:48].hex())' "$1" 2>/dev/null; }
printf '%s' "$VALUE" | pin_blob_v2 "$W/k.pem" "$W/t2.blob" "$W/cer" || F "a second blob not made"
u1="$(uniq "$W/t.blob")"; u2="$(uniq "$W/t2.blob")"
[ "${#u1}" = 64 ] && [ "$u1" != "$(printf '%s' "$VALUE" | sha256sum | cut -d' ' -f1)" ] \
  && P "the sealed object's public unique is not SHA-256 of the value" || F "unique: ${u1:-unreadable}"
[ "${#u2}" = 64 ] && [ "$u1" != "$u2" ] && P "two blobs of the same value have different unique values" || F "unique $u1 and ${u2:-unreadable}"

split(){ python3 -I -c '
import sys; b=open(sys.argv[1],"rb").read()[114:]; o=0
for n in ("pub","dpriv","seed"):
    s=int.from_bytes(b[o:o+2],"big"); open(sys.argv[2]+"/"+n,"wb").write(b[o:o+2+s]); o+=2+s' "$1" "$2"; }
open_blob(){ local d="$W/o"; rm -rf "$d"; mkdir -p "$d"; split "$1" "$d"
  tpm2_import -Q -C "$W/k.ctx" -u "$d/pub" -i "$d/dpriv" -s "$d/seed" -r "$d/priv" 2>/dev/null || { sim_flush; return 1; }
  sim_flush; tpm2_load -Q -C "$W/k.ctx" -u "$d/pub" -r "$d/priv" -c "$d/x.ctx" 2>/dev/null || { sim_flush; return 1; }
  sim_flush; tpm2_unseal -c "$d/x.ctx" 2>/dev/null; local rc=$?; sim_flush; return $rc; }
echo "6  TPM2_Import + TPM2_Load + TPM2_Unseal"
got="$(open_blob "$W/t.blob" | od -An -tx1 | tr -d ' \n')"
[ "$got" = "$(printf '%s' "$VALUE" | od -An -tx1 | tr -d ' \n')" ] && P "unsealed exactly the test value" || F "unsealed bytes: ${got:-none}"

echo "7  refusals"
tpm2_createprimary -Q -C n -g sha256 -G ecc256:aes128cfb -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' \
  -c "$W/p2.ctx" 2>/dev/null; sim_flush
tpm2_create -Q -C "$W/p2.ctx" -G ecc256:aes128cfb -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda' \
  -u "$W/k2.pub" -r "$W/k2.priv" && sim_flush && tpm2_load -Q -C "$W/p2.ctx" -u "$W/k2.pub" -r "$W/k2.priv" -c "$W/k2.ctx" \
  && sim_flush && tpm2_readpublic -Q -c "$W/k2.ctx" -f pem -o "$W/k2.pem" || F "a second transient key could not be made"
printf '%s' "$VALUE" | pin_blob_v2 "$W/k2.pem" "$W/other.blob" "$W/cer"
{ head -c 114 "$W/t.blob"; tail -c +115 "$W/other.blob"; } > "$W/relabelled.blob"
open_blob "$W/relabelled.blob" >/dev/null && F "a blob for another key, relabelled, was imported" || P "a blob for another key, relabelled as this one's, is refused by TPM2_Import"
python3 -I -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[200]^=0xFF; open(sys.argv[2],"wb").write(b)' "$W/t.blob" "$W/altered.blob"
open_blob "$W/altered.blob" >/dev/null && F "an altered blob was imported" || P "an altered blob is refused by TPM2_Import"

echo "8  dictionary-attack counter after"; after="$(counter)"; echo "     TPM2_PT_LOCKOUT_COUNTER $after"
[ -n "$before" ] && [ "$before" = "$after" ] && P "the counter did not move ($before)" || F "the counter moved: $before -> $after"

echo; echo "slb9665-poc: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
