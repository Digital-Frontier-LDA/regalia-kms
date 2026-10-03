#!/usr/bin/env bash
# uki-build.sh — the boot image of a KMS host, built, signed and replayed on a software TPM.
# regalia-kms#57. The tools are real (ukify, systemd-measure, sbsign, OpenSSL's pkcs11 engine, systemd-creds,
# swtpm); the keys are TEST keys made here and named as such; nothing is booted.
#
#   e2e/uki-build.sh
#
#   1  the build is reproducible: two builds give the same image and the same record, and the record's
#      PCR 11 values are systemd-measure's
#   2  the image is signed twice over PCR 11 (one key per boot phase) and once for Secure Boot, with the
#      keys in files and with the same keys inside a PKCS#11 token (SoftHSM): the PCR signatures are the
#      same either way, and the signed image verifies against its record
#   3  refusals: a changed input, a PIN in a key URI, one key for two roles, a tampered image
#   4  THE POINT. A software TPM measures the image's sections as systemd-stub would, then the phases.
#      Its PCR 11 is the record's value for the initrd phase, then for the booted phase. A secret sealed
#      to the initrd-phase key opens in the initrd with the image's own signature and not once booted;
#      a secret sealed to the system-phase key opens once booted and not in the initrd; neither opens
#      on another image
#   5  the measurement set printed for a host is one the measurement document accepts
#
# NOT HERE: a boot. That the firmware and systemd-stub of a real machine measure these sections in this
# order is systemd's documented behaviour and this script's assumption; the first boot of such an image
# is the unlock test's (#66) and then a DL360 (#65). No hardware token is used: SoftHSM stands for it.
# The initrd is whatever INITRD names, or a stand-in: the real one is built by #66's dracut module.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
MEASURE="$(command -v systemd-measure || echo /usr/lib/systemd/systemd-measure)"
STUB="${STUB:-/usr/lib/systemd/boot/efi/linuxx64.efi.stub}"
ENGINE="${ENGINE:-$(ls /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so 2>/dev/null)}"
SOFTHSM="${SOFTHSM:-$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so 2>/dev/null | head -1)}"
for t in ukify sbsign sbverify openssl softhsm2-util swtpm tpm2_pcrextend tpm2_pcrread systemd-creds "$MEASURE" python3; do
  command -v "$t" >/dev/null || { echo "uki-build: $t is required (systemd-ukify, sbsigntool, softhsm2, swtpm, tpm2-tools, systemd)"; exit 2; }
done
[ -f "$STUB" ] && [ -f "$ENGINE" ] && [ -f "$SOFTHSM" ] || { echo "uki-build: needs systemd-boot-efi (the stub), libengine-pkcs11-openssl and softhsm2"; exit 2; }
SUDO=""; [ "$(id -u)" = 0 ] || { sudo -n true 2>/dev/null || { echo "uki-build: needs root or sudo (systemd-creds with a TPM)"; exit 2; }; SUDO="sudo"; }
LINUX="${LINUX:-$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1)}"
[ -r "$LINUX" ] || { echo "uki-build: no kernel image (set LINUX)"; exit 2; }
echo "uki-build: $(ukify --version), $("$MEASURE" --version | head -1), sbsign $(sbsign --version 2>&1 | grep -oE '[0-9]+\.[0-9.]+' | head -1), kernel $LINUX"
W="$(mktemp -d)"; cd "$HERE" || exit 2
stop(){ [ -f "$W/tpm.pid" ] || return 0; TPM2TOOLS_TCTI="$D" tpm2_shutdown -c >/dev/null 2>&1; kill "$(cat "$W/tpm.pid")" 2>/dev/null; rm -f "$W/tpm.pid"; }
trap 'stop; $SUDO rm -rf "$W"' EXIT
D="swtpm:path=$W/tpm.sock"
uki(){ python3 -Es -m deploy.baremetal.uki "$@"; }
field(){ python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(v)' "$1" "$2"; }

# ---- inputs and TEST keys ------------------------------------------------------------------------------
UNAME="$(basename "$LINUX" | sed 's/^vmlinuz-//')"
if [ -n "${INITRD:-}" ]; then cp "$INITRD" "$W/initrd"; else
  mkdir "$W/ird"; printf '#!/bin/sh\n' > "$W/ird/init"; (cd "$W/ird" && printf 'init\n' | cpio --quiet -o -H newc 2>/dev/null) > "$W/initrd"; fi
printf 'root=/dev/mapper/root ro quiet systemd.import_credentials=no\n' > "$W/cmdline"
printf 'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Regalia KMS host (TEST image)"\n' > "$W/os-release"
for k in initrd system secure-boot other; do
  openssl genrsa -out "$W/TEST-$k.key" 2048 2>/dev/null
  openssl rsa -in "$W/TEST-$k.key" -pubout -out "$W/TEST-$k.pub" 2>/dev/null
  openssl req -new -x509 -key "$W/TEST-$k.key" -out "$W/TEST-$k.crt" -subj "/CN=TEST $k key, not for production/" -days 30 2>/dev/null
done
IN=(--linux "$LINUX" --initrd "$W/initrd" --cmdline "$W/cmdline" --os-release "$W/os-release" --uname "$UNAME" --stub "$STUB" --pcrpkey "$W/TEST-system.pub")
FILEKEYS=(--initrd-key "$W/TEST-initrd.key" --initrd-cert "$W/TEST-initrd.crt" --system-key "$W/TEST-system.key" --system-cert "$W/TEST-system.crt"
          --secure-boot-key "$W/TEST-secure-boot.key" --secure-boot-cert "$W/TEST-secure-boot.crt")

hdr "1  the build is reproducible, and its PCR 11 is systemd-measure's"
out="$(uki build "${IN[@]}" --name test-image --out "$W/a" 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -s "$W/a/test-image.unsigned.efi" ] && P "built: $(sed -n 1p <<< "$out")" || F "build failed (exit $rc): $out"
uki build "${IN[@]}" --name test-image --out "$W/b" >/dev/null 2>&1
cmp -s "$W/a/test-image.unsigned.efi" "$W/b/test-image.unsigned.efi" && cmp -s "$W/a/test-image.record.json" "$W/b/test-image.record.json" \
  && P "a second build gives the same image and the same record, byte for byte" || F "two builds differ"
REC="$W/a/test-image.record.json"
[ "$(sha256sum "$W/a/test-image.unsigned.efi" | cut -d' ' -f1)" = "$(field "$REC" unsigned_sha256)" ] && P "the record names the image by its SHA-256" || F "the record's hash is not the image's"
i11="$(field "$REC" pcr11.initrd)"; s11="$(field "$REC" pcr11.system)"
[ "${#i11}" = 64 ] && [ "${#s11}" = 64 ] && [ "$i11" != "$s11" ] && P "one image, two PCR 11 values: initrd ${i11:0:16}…, system ${s11:0:16}…" || F "the record's PCR 11 values: '$i11' '$s11'"
# the same prediction, asked of ukify itself (its --measure runs systemd-measure over the image it builds, for every phase)
theirs="$(ukify build --config /dev/null --linux "$LINUX" --initrd "$W/initrd" --cmdline "root=/dev/mapper/root ro quiet systemd.import_credentials=no" --os-release "@$W/os-release" \
  --uname "$UNAME" --stub "$STUB" --pcrpkey "$W/TEST-system.pub" --tools "$(dirname "$MEASURE")" --measure --output "$W/ukify-own.efi" 2>/dev/null | sed -n 's/^11:sha256=//p')"
grep -qx "$i11" <<< "$theirs" && grep -qx "$s11" <<< "$theirs" && P "ukify --measure predicts both values for the image it builds from the same inputs" \
  || F "ukify --measure says '$(tr '\n' ' ' <<< "$theirs")', the record $i11 and $s11"
printf 'root=/dev/mapper/root ro quiet systemd.import_credentials=no rd.luks.uuid=0\n' > "$W/cmdline-bad"
out="$(uki build "${IN[@]:0:4}" --cmdline "$W/cmdline-bad" "${IN[@]:6}" --name x --out "$W/x" 2>&1)"; rc=$?
[ "$rc" = 1 ] && grep -q "holds 'rd.luks.uuid=0'" <<< "$out" && [ ! -e "$W/x/x.unsigned.efi" ] && P "a command line that unlocks a disk by itself is refused, nothing built" || F "bad command line: exit $rc: $out"

hdr "2  two PCR signatures and a Secure Boot signature; keys in files, then in a PKCS#11 token"
out="$(uki sign "${IN[@]}" --record "$REC" --second-record "$W/b/test-image.record.json" --out "$W/a" "${FILEKEYS[@]}" 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -s "$W/a/test-image.efi" ] && P "signed with file keys" || F "sign failed (exit $rc): $out"
SIGNED="$W/a/test-image.signed.json"
out="$(uki verify --image "$W/a/test-image.efi" --record "$SIGNED" --initrd-pub "$W/TEST-initrd.crt" --system-pub "$W/TEST-system.pub" --secure-boot-cert "$W/TEST-secure-boot.crt" 2>&1)"; rc=$?
[ "$rc" = 0 ] && grep -q '^VERIFIED test-image' <<< "$out" && P "the signed image verifies against its record (sections, both PCR signatures, Secure Boot)" || F "verify (exit $rc): $out"
sbverify --cert "$W/TEST-secure-boot.crt" "$W/a/test-image.efi" >/dev/null 2>&1 && P "sbverify accepts the Secure Boot signature" || F "sbverify refuses the image"
[ "$(field "$SIGNED" signed.pcr_signatures.initrd.pkfp)" != "$(field "$SIGNED" signed.pcr_signatures.system.pkfp)" ] && P "the two PCR signatures are by two keys" || F "one key signed both phases"
# the token: SoftHSM, the same three keys imported, used through OpenSSL's pkcs11 engine. The PIN is in the
# engine's configuration file here because nobody is at a terminal; with a real token the engine asks for it.
export SOFTHSM2_CONF="$W/softhsm2.conf"; mkdir "$W/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$W/tokens" > "$SOFTHSM2_CONF"
TESTPIN="648219"
softhsm2-util --init-token --free --label TEST-IMAGE --so-pin 12345678 --pin "$TESTPIN" >/dev/null
n=10; for k in initrd system secure-boot; do n=$((n+1)); openssl pkcs8 -topk8 -nocrypt -in "$W/TEST-$k.key" -out "$W/TEST-$k.p8" 2>/dev/null
  softhsm2-util --import "$W/TEST-$k.p8" --token TEST-IMAGE --label "$k" --id "$n" --pin "$TESTPIN" >/dev/null; done
cat > "$W/engine.cnf" <<EOF
openssl_conf = openssl_init
[openssl_init]
engines = engine_sect
[engine_sect]
pkcs11 = pkcs11_sect
[pkcs11_sect]
engine_id = pkcs11
dynamic_path = $ENGINE
MODULE_PATH = $SOFTHSM
PIN = $TESTPIN
init = 0
EOF
TOKSERIAL="$(softhsm2-util --show-slots | awk '/Serial number:/{s=$3} /Label:[[:space:]]*TEST-IMAGE/{print s; exit}')"
[ -n "$TOKSERIAL" ] || { echo "uki-build: cannot read the test token's serial"; exit 2; }
uri(){ printf 'pkcs11:serial=%s;token=TEST-IMAGE;object=%s;type=private' "$TOKSERIAL" "$1"; }
TOKENKEYS=(--key-source engine:pkcs11 --initrd-key "$(uri initrd)" --initrd-cert "$W/TEST-initrd.crt" --system-key "$(uri system)" --system-cert "$W/TEST-system.crt"
           --secure-boot-key "$(uri secure-boot)" --secure-boot-cert "$W/TEST-secure-boot.crt")
out="$(OPENSSL_CONF="$W/engine.cnf" uki sign "${IN[@]}" --record "$REC" --second-record "$W/b/test-image.record.json" --out "$W/t" "${TOKENKEYS[@]}" 2>&1)"; rc=$?
[ "$rc" = 0 ] && [ -s "$W/t/test-image.efi" ] && P "signed with the keys inside a PKCS#11 token (pkcs11 engine)" || F "token sign failed (exit $rc): $out"
if [ -s "$W/t/test-image.signed.json" ]; then
  [ "$(field "$SIGNED" signed.pcr_signatures)" = "$(field "$W/t/test-image.signed.json" signed.pcr_signatures)" ] && P "the token's PCR signatures are for the same keys and policies as the files'" || F "token and file signatures differ"
  uki verify --image "$W/t/test-image.efi" --record "$W/t/test-image.signed.json" --initrd-pub "$W/TEST-initrd.pub" --system-pub "$W/TEST-system.pub" \
    --secure-boot-cert "$W/TEST-secure-boot.crt" >/dev/null 2>&1 && P "the token-signed image verifies" || F "the token-signed image does not verify"
else F "no token-signed record"; F "no token-signed image to verify"; fi

hdr "3  refusals"
no(){ local what="$1" msg="$2" out rc; shift 2; out="$("$@" 2>&1)"; rc=$?
  [ "$rc" = 1 ] && grep -q -- "$msg" <<< "$out" && P "$what" || F "$what: exit $rc: $out"; }
cp "$W/initrd" "$W/initrd-2"; printf 'x' >> "$W/initrd-2"
no "an input that is not the record's is refused" "the input --initrd is not the one the record was built from" \
  uki sign "${IN[@]:0:2}" --initrd "$W/initrd-2" "${IN[@]:4}" --record "$REC" --second-record "$W/b/test-image.record.json" --out "$W/r1" "${FILEKEYS[@]}"
no "a PIN in a key URI is refused" "names .pin-value., which is not one of" \
  uki sign "${IN[@]}" --record "$REC" --second-record "$W/b/test-image.record.json" --out "$W/r2" --key-source engine:pkcs11 --initrd-key "$(uri initrd);pin-value=$TESTPIN" "${TOKENKEYS[@]:4}"
no "one key for both phases is refused" "must be three different keys" \
  uki sign "${IN[@]}" --record "$REC" --second-record "$W/b/test-image.record.json" --out "$W/r3" --initrd-key "$W/TEST-system.key" --initrd-cert "$W/TEST-system.crt" "${FILEKEYS[@]:4}"
no "a system key that is not the image's is refused" "is not for the key the image carries" \
  uki sign "${IN[@]}" --record "$REC" --second-record "$W/b/test-image.record.json" --out "$W/r4" "${FILEKEYS[@]:0:4}" --system-key "$W/TEST-other.key" --system-cert "$W/TEST-other.crt" "${FILEKEYS[@]:8}"
[ ! -e "$W/r1/test-image.efi" ] && [ ! -e "$W/r2/test-image.efi" ] && [ ! -e "$W/r3/test-image.efi" ] && [ ! -e "$W/r4/test-image.efi" ] \
  && P "no refused signing left an image behind" || F "a refused signing wrote an image"
cp "$W/a/test-image.efi" "$W/tampered.efi"; printf 'x' >> "$W/tampered.efi"
no "a changed file is not the image the record names" "the image is not the file the record names" \
  uki verify --image "$W/tampered.efi" --record "$SIGNED" --initrd-pub "$W/TEST-initrd.pub" --system-pub "$W/TEST-system.pub" --secure-boot-cert "$W/TEST-secure-boot.crt"
no "the unsigned image does not pass for the signed one" "the image is not the file the record names" \
  uki verify --image "$W/a/test-image.unsigned.efi" --record "$SIGNED" --initrd-pub "$W/TEST-initrd.pub" --system-pub "$W/TEST-system.pub" --secure-boot-cert "$W/TEST-secure-boot.crt"
no "other keys than the record's are refused" "is not the one the record names" \
  uki verify --image "$W/a/test-image.efi" --record "$SIGNED" --initrd-pub "$W/TEST-other.pub" --system-pub "$W/TEST-system.pub" --secure-boot-cert "$W/TEST-secure-boot.crt"

hdr "4  a software TPM measures the image; its own signatures open a secret in the right phase only"
export TPM2TOOLS_TCTI="$D"
# The sections as systemd-stub measures them, from the SIGNED image: "name-digest content-digest" per section.
python3 -IB - "$HERE" "$W/a/test-image.efi" > "$W/extends" <<'EOF'
import sys; sys.path.append(sys.argv.pop(1))
import hashlib, sys
from deploy.baremetal import uki
for name, content in uki.measured(uki.read(sys.argv[1])).items():
    print(hashlib.sha256(b"." + name.encode() + b"\0").hexdigest(), hashlib.sha256(content).hexdigest())
EOF
python3 -IB - "$HERE" "$W/a/test-image.efi" > "$W/pcrsig.json" <<'EOF'
import sys; sys.path.append(sys.argv.pop(1))
import sys
from deploy.baremetal import uki
sys.stdout.write(dict(uki.sections(uki.read(sys.argv[1])))[".pcrsig"].rstrip(b"\0").decode())
EOF
ext(){ tpm2_pcrextend "$1:sha256=$2" >/dev/null; }
pcr11(){ tpm2_pcrread sha256:11 | awk '/11 *:/{print tolower(substr($NF,3))}'; }
# boot [mangle]: a fresh TPM, PCR 7 a Secure Boot stand-in, PCR 11 the image's sections, then enter-initrd
boot(){ local a b
  stop; mkdir -p "$W/state"
  swtpm socket --tpm2 --tpmstate "dir=$W/state" --server "type=unixio,path=$W/tpm.sock" --ctrl "type=unixio,path=$W/tpm.sock.ctrl" \
    --flags not-need-init,startup-clear --daemon --pid "file=$W/tpm.pid"
  for _ in $(seq 1 30); do tpm2_pcrread sha256:7 >/dev/null 2>&1 && break; sleep 0.3; done
  ext 7 "$(printf 'secure-boot-state' | sha256sum | cut -d' ' -f1)"
  while read -r a b; do ext 11 "$a"; ext 11 "$b"; done < "$W/extends"
  [ -z "${1:-}" ] || ext 11 "$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"
  ext 11 "$(printf 'enter-initrd' | sha256sum | cut -d' ' -f1)"; }
up(){ local p; for p in leave-initrd sysinit ready; do ext 11 "$(printf '%s' "$p" | sha256sum | cut -d' ' -f1)"; done; }
seal(){ printf 'the %s secret' "$1" | $SUDO systemd-creds encrypt --with-key=tpm2-with-public-key --tpm2-device="$D" --tpm2-pcrs=7 \
  --tpm2-public-key="$W/TEST-$1.pub" --tpm2-public-key-pcrs=11 --name="$1" - "$W/$1.cred" 2>"$W/seal.err"; }
opens(){ [ "$($SUDO systemd-creds decrypt --tpm2-device="$D" --tpm2-signature="$W/pcrsig.json" --name="$1" "$W/$1.cred" - 2>/dev/null)" = "the $1 secret" ]; }
lockouts(){ tpm2_getcap properties-variable | awk '/TPM2_PT_LOCKOUT_COUNTER/{print $2}'; }

boot
[ "$(pcr11)" = "$i11" ] && P "in the initrd the TPM's PCR 11 is the record's initrd value" || F "PCR 11 is $(pcr11), the record says $i11"
seal initrd && seal system && P "two secrets sealed: one to the initrd-phase key, one to the system-phase key (PCR 7 direct, PCR 11 signed)" || F "sealing failed: $(cat "$W/seal.err")"
opens initrd && P "initrd phase: the initrd-phase secret opens with the image's own signature" || F "initrd phase: the initrd-phase secret does not open"
opens system && F "initrd phase: the system-phase secret opened" || P "initrd phase: the system-phase secret does not open"
up
[ "$(pcr11)" = "$s11" ] && P "once booted the TPM's PCR 11 is the record's system value" || F "PCR 11 is $(pcr11), the record says $s11"
opens system && P "booted: the system-phase secret opens with the image's own signature" || F "booted: the system-phase secret does not open"
opens initrd && F "booted: the initrd-phase secret opened" || P "booted: the initrd-phase secret does not open any more"
boot; up
opens system && P "after a reboot into the same image the same blob opens again, with no re-sealing" || F "after a reboot the secret does not open"
boot "another image"
[ "$(pcr11)" != "$i11" ] && ! opens initrd && P "another image, initrd phase: nothing opens" || F "another image opened the initrd-phase secret"
up
opens system && F "another image opened the system-phase secret" || P "another image, booted: nothing opens"
[ "$(lockouts)" = "0x0" ] && P "none of those refusals counted as a failed authorization (lockout counter 0)" || F "lockout counter is $(lockouts)"

hdr "5  the measurement set of this image for a host"
printf '{"0": "%s", "7": "%s"}' "$(printf '00%.0s' $(seq 32))" "$(printf '77%.0s' $(seq 32))" > "$W/pcrs.json"
mkdir -p "$W/esp/loader/credentials"; printf 'test-node\n' > "$W/esp/loader/credentials/regalia.node-id.cred"
uki set --record "$SIGNED" --label test-image --tpm-firmware-version 2019102300163636 --pcrs "$W/pcrs.json" --esp "$W/esp" > "$W/set.json" 2>"$W/set.err"
python3 -IB - "$HERE" "$W/set.json" "$i11" "$s11" <<'EOF' && P "the set gives PCR 11 per phase from the record, and a measurement document accepts it" || F "the set: $(cat "$W/set.err" "$W/set.json")"
import sys; sys.path.append(sys.argv.pop(1))
import json, sys
from deploy.baremetal import measurements
entry = json.load(open(sys.argv[1]))
assert entry["phases"] == {"initrd": {"11": sys.argv[2]}, "system": {"11": sys.argv[3]}}, entry
measurements.version({"schema": measurements.SCHEMA, "name": "v1", "nodes": {n: {"accepted": [entry]} for n in "abc"}})
EOF

echo
echo "uki-build: image $(field "$SIGNED" signed.image_sha256) (unsigned $(field "$REC" unsigned_sha256)), kernel $UNAME"
echo "uki-build: $pass passed, $fail failed"
[ "$fail" = 0 ]
