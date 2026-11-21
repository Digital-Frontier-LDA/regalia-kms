#!/usr/bin/env bash
# import-key-certify-swtpm.sh — #702: the PIN import key, certified by the EK-bound AK (TPM2_Certify), against two
# software TPMs (swtpm). A is the host being commissioned, B is another machine's TPM. No hardware.
#
#   sudo -v && e2e/import-key-certify-swtpm.sh
#
#   0  a certified key passes: seal-hsm-pin.sh --init-import-key opens the verifier's credential, makes the key and has
#      the AK certify it; deploy/baremetal/importkey.py verify accepts it with no TPM
#   each refusal below names its check (the REFUSED line starts with it), and with that check disabled the case fails
#   (e2e/import-key-certify-mutants.sh):
#   a  binding     a SOFTWARE P-256 key whose fingerprint is the one shown, certified in software by a software "AK"
#                  under the real EK's Name: refused, the AK is not proven to be in the TPM with that EK
#   b  ek          a key certified by ANOTHER TPM's AK (B's whole certification, its challenge answered by B): refused,
#                  the EK is not the one recorded for this host at intake
#   c  name        a valid certification by this AK of a DIFFERENT object (another key in TPM A): refused, the
#                  certified Name is not the import key's
#   d  missing     no certification on record: refused, a fingerprint alone cannot tell a TPM key from a software key
#   e  (a probe, not one of #702's cases) a software key's public area loaded into TPM A with TPM2_LoadExternal and
#      handed to TPM2_Certify: the TPM refuses, or the verifier refuses it at `parent`; which one is printed
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; SEAL="$HERE/deploy/seal-hsm-pin.sh"
# shellcheck source=e2e/lib/import-key-cert.sh
. "$HERE/e2e/lib/import-key-cert.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
for t in swtpm tpm2_createek tpm2_createak tpm2_makecredential tpm2_certify tpm2_loadexternal tpm2_createprimary openssl python3; do
  command -v "$t" >/dev/null || { echo "import-key-certify-swtpm: $t is required (swtpm, tpm2-tools, openssl, python3)"; exit 2; }
done
sudo -n true 2>/dev/null || { echo "import-key-certify-swtpm: needs sudo (seal-hsm-pin.sh runs as root)"; exit 2; }
W="$(mktemp -d)"
[ "${#W}" -le 80 ] || { echo "import-key-certify-swtpm: $W is too long for a unix socket path; set TMPDIR to a shorter one"; exit 2; }
stop(){ for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done; }
trap 'stop; sudo rm -rf "$W"' EXIT
tpm(){ mkdir -p "$W/$1"; swtpm socket --tpm2 --tpmstate "dir=$W/$1" --server "type=unixio,path=$W/$1.sock" \
  --ctrl "type=unixio,path=$W/$1.sock.ctrl" --flags not-need-init,startup-clear --daemon --pid "file=$W/$1.pid" \
    || { echo "import-key-certify-swtpm: swtpm $1 did not start"; exit 2; }
  local _; for _ in $(seq 1 50); do [ -S "$W/$1.sock" ] && return 0; sleep 0.1; done
  echo "import-key-certify-swtpm: swtpm $1's socket never appeared"; exit 2; }
seal(){ local tcti="$1"; shift; sudo env TPM2TOOLS_TCTI="$tcti" "$SEAL" "$@" 2>&1; }
fp(){ openssl pkey -pubin -in "$1" -outform der | sha256sum | cut -d' ' -f1; }
ver(){ (cd "$HERE" && python3 -Es -m deploy.baremetal.importkey verify "$@" 2>&1); }
forge(){ python3 -I "$HERE/e2e/lib/import_key_forge.py" "$HERE" "$@"; }
# refused <check> <output>: refused, by THAT check (importkey.py's refusals start with the check's name)
refused(){ grep -q "^REFUSED: $1: " <<< "$2" && ! grep -q '^VERIFIED' <<< "$2"; }

tpm A; tpm B
TA="swtpm:path=$W/A.sock"; TB="swtpm:path=$W/B.sock"
ikc_ready "$TA" "$W/idA" && ikc_ready "$TB" "$W/idB" || { echo "import-key-certify-swtpm: cannot make the EKs and AKs"; exit 2; }
EKA="$(cat "$W/idA/ek.name")"    # host A's EK Name, as intake records it (the EK certificate's, on a real host)

hdr "0  a certified import key passes"
out="$(seal "$TA" --init-import-key --ak-credential "$W/idA/cred.bin" --certification "$W/A.cert.json" --import-pub "$W/A.pem")"
grep -q 'IMPORT KEY CREATED' <<< "$out" && grep -q "certification : $W/A.cert.json" <<< "$out" \
  && P "TPM A: the import key made and certified by its AK" || F "TPM A init: $out"
out="$(seal "$TB" --init-import-key --ak-credential "$W/idB/cred.bin" --certification "$W/B.cert.json" --import-pub "$W/B.pem")"
grep -q 'IMPORT KEY CREATED' <<< "$out" && P "TPM B: the same, for another machine" || F "TPM B init: $out"
FPA="$(fp "$W/A.pem")"
out="$(ver --certification "$W/A.cert.json" --keep "$W/idA/keep.json" --ek-name "$EKA" --fingerprint "$FPA")"
grep -q "^VERIFIED .*\"fingerprint\": \"$FPA\"" <<< "$out" && P "verified with no TPM: signature, AK-EK binding, signer, Name, parent, attributes, template" \
  || F "the certified key was refused: $out"
python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert sorted(d) == ["ak_public", "answer", "certify", "ek_public", "import_public", "schema", "signature"], sorted(d)' "$W/A.cert.json" \
  && P "the certification records the import key, the certify blob, its signature, and the AK's binding to the EK (EK, AK, answer)" \
  || F "the certification document's fields"

hdr "a  a software P-256 key with a matching fingerprint"
FPS="$(forge software "$W/A.cert.json" "$W/a.cert.json" "$W/a.import.pub")" || F "cannot forge (a)"
out="$(ver --certification "$W/a.cert.json" --keep "$W/idA/keep.json" --ek-name "$EKA" --fingerprint "$FPS")"
refused binding "$out" && P "refused by binding: a software AK under the real EK's Name is not the AK the credential was opened for" \
  || F "(a) software key: $out"

hdr "b  a key certified by another TPM's AK"
FPB="$(fp "$W/B.pem")"
out="$(ver --certification "$W/B.cert.json" --keep "$W/idB/keep.json" --ek-name "$EKA" --fingerprint "$FPB")"
refused ek "$out" && P "refused by ek: B's genuine certification (and B's answered challenge) is not host A's EK" || F "(b) another TPM: $out"

hdr "c  a valid certification of a different Name"
# another key in TPM A, with the import key's template, a child of a storage key like it; certified by A's AK
( export TPM2TOOLS_TCTI="$TA"; d="$W/c"; mkdir -p "$d"
  tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' -c "$d/p.ctx" \
  && tpm2_flushcontext -t && tpm2_create -Q -C "$d/p.ctx" -G ecc256:aes128cfb -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda' \
       -u "$d/k.pub" -r "$d/k.priv" && tpm2_flushcontext -t \
  && tpm2_load -Q -C "$d/p.ctx" -u "$d/k.pub" -r "$d/k.priv" -c "$d/k.ctx" && tpm2_flushcontext -t \
  && tpm2_certify -Q -c "$d/k.ctx" -C 0x81010002 -g sha256 -o "$d/certify" -s "$d/sig" -f plain; rc=$?; tpm2_flushcontext -t; exit $rc ) \
  || F "(c) cannot certify another key in TPM A"
forge swap "$W/A.cert.json" "$W/c/certify" "$W/c/sig" "$W/c.cert.json" || F "cannot build (c)"
out="$(ver --certification "$W/c.cert.json" --keep "$W/idA/keep.json" --ek-name "$EKA" --fingerprint "$FPA")"
refused name "$out" && P "refused by name: this AK's valid certification of another key is not the import key's" || F "(c) different Name: $out"

hdr "d  a missing certification"
out="$(ver --keep "$W/idA/keep.json" --ek-name "$EKA" --fingerprint "$FPA")"
refused missing "$out" && P "refused by missing: the fingerprint alone is not accepted" || F "(d) no certification: $out"

hdr "e  probe: a software key loaded with TPM2_LoadExternal, certified by A's AK"
for h in n o; do
  d="$W/e$h"; mkdir -p "$d"
  if ! TPM2TOOLS_TCTI="$TA" tpm2_loadexternal -Q -C "$h" -u "$W/a.import.pub" -c "$d/ext.ctx" 2>"$d/err"; then
    P "hierarchy $h: the TPM refuses to load the software key's public area with the import template ($(tr '\n' ' ' < "$d/err" | cut -c1-120))"
  elif ! TPM2TOOLS_TCTI="$TA" tpm2_certify -Q -c "$d/ext.ctx" -C 0x81010002 -g sha256 -o "$d/certify" -s "$d/sig" -f plain 2>"$d/err"; then
    P "hierarchy $h: loaded, but the TPM refuses to certify it ($(tr '\n' ' ' < "$d/err" | cut -c1-120))"
  else
    forge swap "$W/A.cert.json" "$d/certify" "$d/sig" "$d/e.cert.json" "$W/a.import.pub" || F "cannot build (e)"
    out="$(ver --certification "$d/e.cert.json" --keep "$W/idA/keep.json" --ek-name "$EKA" --fingerprint "$FPS")"
    refused parent "$out" && P "hierarchy $h: the TPM CERTIFIED the loaded software key; the verifier refuses it by parent" \
      || F "hierarchy $h: a software key loaded with TPM2_LoadExternal and certified by the AK: $out"
  fi
  TPM2TOOLS_TCTI="$TA" tpm2_flushcontext -t >/dev/null 2>&1
done

echo; echo "import-key-certify-swtpm: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
