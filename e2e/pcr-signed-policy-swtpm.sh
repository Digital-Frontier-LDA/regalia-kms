#!/usr/bin/env bash
# pcr-signed-policy-swtpm.sh — seal-hsm-pin.sh's signed PCR 11 policy (#57) against a software TPM
# (swtpm). The TPM, systemd-creds and systemd-measure are real; the CARD is a stub (two scripts that
# answer as a Nitrokey with a full counter and one PIN), since no token is attached in CI and the card
# half has its own hardware drills (nitrokey-pin-custody-drill.sh, nitrokey-pin-import-drill.sh).
#
#   sudo -v && e2e/pcr-signed-policy-swtpm.sh
#
# A "boot" here is a restart of the swtpm (PCRs back to zero, same TPM seed), then PCR 7 extended
# with a Secure Boot stand-in and PCR 11 extended the way systemd-stub and systemd-pcrphase do it for
# a UKI: each section's name and content, then the boot phases.
#
#   0  the instrument: the replayed PCR 11 equals what `systemd-measure calculate` predicts
#   1  refusals before any card is looked at: a direct PCR 11, a signed PCR other than 11, no key, a
#      key that is not RSA, a signature by another key, a signature for nothing, --bench-host-key
#   2  the PIN is sealed under PCR 7 + signed PCR 11; the record names the signing key by the same
#      fingerprint the signature file carries
#   3  the installed blob opens with this boot's signature, and not with none, an empty one, or
#      another key's
#   4  a kernel update signed by the same key opens the SAME blob, with no re-sealing
#   5  a kernel nobody signed, a kernel signed by another key, a changed PCR 7, and a boot phase the
#      signature does not cover do not
#   6  host_probe.py reads that binding back from the installed blob's header, and a blob whose
#      header was edited to claim another binding does not open
#   7  why the script checks the binding: systemd-creds --with-key=tpm2 ignores the public key
#   8  the host-key half (#75): the same blob does not open without the host key, or with another
#      disk's, on the image it was sealed on, on an updated one, or on a retired one; the TPM half
#      alone never retires an image, which is why a TPM-only credential is refused
#   9  the same through the script with NO signed policy (--pcrs 7 alone): host+tpm2, not tpm2
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; SEAL="$HERE/deploy/seal-hsm-pin.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
MEASURE="$(command -v systemd-measure || echo /usr/lib/systemd/systemd-measure)"
for t in swtpm tpm2_pcrextend tpm2_pcrread openssl systemd-creds "$MEASURE"; do
  command -v "$t" >/dev/null || { echo "pcr-signed-policy-swtpm: $t is required (swtpm, tpm2-tools, openssl, systemd)"; exit 2; }
done
sudo -n true 2>/dev/null || { echo "pcr-signed-policy-swtpm: needs sudo"; exit 2; }
echo "pcr-signed-policy-swtpm: $(systemd-creds --version | head -1), swtpm $(swtpm --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
W="$(mktemp -d)"; cd "$W" || exit 2
# An orderly TPM2_Shutdown first: the TPM counts a restart without one as a failed authorization try.
stop(){ [ -f "$W/tpm.pid" ] || return 0; tpm2_shutdown -c >/dev/null 2>&1; kill "$(cat "$W/tpm.pid")" 2>/dev/null; rm -f "$W/tpm.pid"; }
trap 'stop; sudo rm -rf "$W"' EXIT
# A unix socket in this run's own directory: no fixed port, so runs do not meet each other.
D="swtpm:path=$W/tpm.sock"; export TPM2TOOLS_TCTI="$D"
PIN="7310048261"; SERIAL="DENK0000001"; PHASES="enter-initrd leave-initrd sysinit ready"

# ---- the stub card ---------------------------------------------------------------------------------
mkdir -p "$W/stub"
cat > "$W/stub/opensc-tool" <<STUB
#!/bin/sh
case " \$* " in *" -l "*) printf 'Nr.  Card  Features  Name\n0    Yes             Stub reader ($SERIAL) 00 00\n';;
  *) echo "Received (SW1=0x63, SW2=0xCA)";; esac
STUB
cat > "$W/stub/pkcs11-tool" <<STUB
#!/bin/sh
case " \$* " in *" -L "*) echo "Slot 0 (0x0): Stub reader ($SERIAL) 00 00";; *) [ "\$PKCS11_PIN" = "$PIN" ];; esac
STUB
chmod 755 "$W/stub/opensc-tool" "$W/stub/pkcs11-tool"
# The host key is this run's own file, never the machine's (/var/lib/systemd/credential.secret):
# systemd reads SYSTEMD_CREDENTIAL_SECRET. other.secret stands for another host's disk.
HK="$W/host.secret"
for k in host other; do sudo env SYSTEMD_CREDENTIAL_SECRET="$W/$k.secret" systemd-creds setup >/dev/null 2>&1 \
  || { echo "pcr-signed-policy-swtpm: systemd-creds setup failed for $k.secret"; exit 2; }; done
seal(){ printf '%s\n' "$PIN" | sudo env PATH="$W/stub:$PATH" REGALIA_TPM2_DEVICE="$D" REGALIA_CREDSTORE="$W/cred" \
  SYSTEMD_CREDENTIAL_SECRET="$HK" "$SEAL" --id t --serial "$SERIAL" "$@" 2>&1; }
BLOB="$W/cred/regalia-kms-t.pin"
open(){ sudo env SYSTEMD_CREDENTIAL_SECRET="$HK" systemd-creds decrypt --tpm2-device="$D" --name=t.pin "$@" "$BLOB" - 2>/dev/null; }

# ---- keys, kernels, signatures -----------------------------------------------------------------------
key(){ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null && openssl pkey -in "$1.key" -pubout -out "$1.pub"; }
key pcr; key other
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key 2>/dev/null; openssl pkey -in ec.key -pubout -out ec.pub
echo "root=/dev/mapper/root_crypt ro" > cmdline
for k in 1 2 3; do head -c 65536 /dev/urandom > "linux$k"; head -c 65536 /dev/urandom > "initrd$k"; done
uki(){ printf -- '--linux=linux%s --cmdline=cmdline --initrd=initrd%s' "$1" "$1"; }
# sign <kernel> <key> <out> [phase path]: the default is the path a running service sees.
sign(){ # shellcheck disable=SC2046
  "$MEASURE" sign $(uki "$1") --bank=sha256 --private-key="$2.key" --public-key="$2.pub" \
    --phase="${4:-enter-initrd:leave-initrd:sysinit:ready}" > "$3" 2>/dev/null; }
sign 1 pcr sig1.json; sign 2 pcr sig2.json; sign 3 other sig3-other.json; sign 1 other sig1-other.json
echo '{}' > nosig.json
pkfp(){ openssl rsa -pubin -in "$1" -RSAPublicKey_out -outform der 2>/dev/null | sha256sum | cut -d' ' -f1; }

# ---- a boot ------------------------------------------------------------------------------------------
ext(){ tpm2_pcrextend "$1:sha256=$2" >/dev/null; }
# boot <kernel> [pcr7 seed] [phases]
boot(){ local k="$1" s
  stop; mkdir -p "$W/state"
  swtpm socket --tpm2 --tpmstate "dir=$W/state" --server "type=unixio,path=$W/tpm.sock" \
    --ctrl "type=unixio,path=$W/tpm.sock.ctrl" --flags not-need-init,startup-clear --daemon --pid "file=$W/tpm.pid"
  for _ in 1 2 3 4 5 6 7 8 9 10; do tpm2_pcrread sha256:7 >/dev/null 2>&1 && break; sleep 0.3; done
  ext 7 "$(printf '%s' "${2:-secure-boot-state}" | sha256sum | cut -d' ' -f1)"
  for s in linux cmdline initrd; do
    ext 11 "$(printf '.%s\0' "$s" | sha256sum | cut -d' ' -f1)"
    case "$s" in cmdline) ext 11 "$(sha256sum cmdline | cut -d' ' -f1)";; *) ext 11 "$(sha256sum "$s$k" | cut -d' ' -f1)";; esac
  done
  for s in ${3:-$PHASES}; do ext 11 "$(printf '%s' "$s" | sha256sum | cut -d' ' -f1)"; done; }
pcr11(){ tpm2_pcrread sha256:11 | awk '/11 *:/{print tolower(substr($NF,3))}'; }

hdr "0  the instrument: the replayed boot is the boot systemd-measure signs"
boot 1
# shellcheck disable=SC2046
want="$("$MEASURE" calculate $(uki 1) --bank=sha256 --phase=enter-initrd:leave-initrd:sysinit:ready 2>/dev/null | sed -n 's/^11:sha256=//p')"
[ -n "$want" ] && [ "$(pcr11)" = "$want" ] && P "PCR 11 in the TPM = systemd-measure calculate ($want)" || F "PCR 11 is $(pcr11), systemd-measure predicts ${want:-nothing}"

hdr "1  refusals, before any card is looked at"
no(){ local what="$1" msg="$2" out rc; shift 2; out="$(seal "$@")"; rc=$?
  [ "$rc" != 0 ] && grep -q -- "$msg" <<< "$out" && ! grep -q 'tries left (full)' <<< "$out" && ! sudo test -e "$BLOB" \
    && P "$what (exit $rc)" || F "$what: $out"; }
no "a direct PCR 11 is still refused" 'must not include 10 (IMA) or 11' --pcrs 7+11 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11 --tpm2-signature sig1.json
no "a signed PCR other than 11 is refused" 'must be 11' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 7 --tpm2-signature sig1.json
no "a public key with no signed PCR named is refused (no default)" 'must be 11' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-signature sig1.json
no "signed PCRs with no public key are refused" 'need --tpm2-public-key' --pcrs 7 --tpm2-public-key-pcrs 11
no "a key that is not RSA is refused" 'not an RSA public key' --pcrs 7 --tpm2-public-key ec.pub --tpm2-public-key-pcrs 11 --tpm2-signature sig1.json
no "a signature made by another key is refused" 'holds no signature by' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11 --tpm2-signature sig1-other.json
no "a signature file with no signature is refused" 'holds no signature by' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11 --tpm2-signature nosig.json
no "--bench-host-key with a signed policy is refused" 'are exclusive' --bench-host-key --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11
# Signed by the right key, but for kernel 2 while kernel 1 runs: only the TPM can tell.
no "a signature by the right key for another kernel is refused" 'for the PCR 11 of the RUNNING boot' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11 --tpm2-signature sig2.json
if [ -e /etc/systemd/tpm2-pcr-signature.json ] || [ -e /run/systemd/tpm2-pcr-signature.json ] || [ -e /usr/lib/systemd/tpm2-pcr-signature.json ]; then
  echo "  SKIP no signature anywhere (this host boots a UKI with its own)"
else no "with no signature for this boot anywhere, nothing is sealed" 'not a UKI with a signed PCR policy' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11; fi

hdr "2  sealing under PCR 7 + signed PCR 11"
# The running boot is kernel 3, which the PCR key never signed.
boot 3
no "on a kernel the key never signed, nothing is sealed" 'for the PCR 11 of the RUNNING boot' --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11 --tpm2-signature sig1.json
boot 1
out="$(seal --pcrs 7 --tpm2-public-key pcr.pub --tpm2-public-key-pcrs 11 --tpm2-signature sig1.json)"; rc=$?
[ "$rc" = 0 ] && grep -q '^SEALED' <<< "$out" && sudo test -s "$BLOB" && P "sealed and installed" || F "seal failed (exit $rc): $out"
grep -q 'host key + tpm2, PCRs 7 (TEST TPM' <<< "$out" && grep -q 'signed PCRs   : 11' <<< "$out" && P "the record: the host key and the TPM, PCR 7 direct, PCR 11 signed, and a TEST TPM" || F "record: $out"
grep -q "(TEST host key $HK, not production)" <<< "$out" && P "the record says the host key is a test one" || F "record does not name the test host key: $out"
# This run's directory is not on dm-crypt, and systemd says so; the record must repeat it.
grep -q 'WARNING       : the host key is NOT on encrypted media' <<< "$out" && P "the record warns that the host key is not on encrypted media (so: not production)" || F "no encrypted-media warning: $out"
[ "$(sudo cat "$BLOB" | base64 -d | head -c 16 | od -An -tx1 | tr -d ' \n')" = af4950a849134eb1a73846304ff30c05 ] \
  && P "the blob's key type is host+tpm2-with-public-key (af4950a8…)" || F "the installed blob has another key type"
fp="$(pkfp pcr.pub)"; grep -q "pkfp          : $fp" <<< "$out" && grep -q "\"pkfp\":\"$fp\"" sig1.json \
  && P "the record's key fingerprint is the pkfp in the signature file" || F "fingerprint $fp not in both the record and sig1.json"
# Tried, not guessed from the path: the blob is opened once more the way the service will, with no
# signature named. Here systemd's own directories hold none for this boot, so the record must warn.
grep -q "WARNING       : opened with sig1.json, but NOT by systemd's own lookup" <<< "$out" && P "the record warns that systemd's own signature lookup, the one the service uses, does not open the blob" || F "no warning though systemd's own lookup cannot open the blob: $out"
grep -qF "$PIN" <<< "$out" && F "the PIN appeared in the output" || P "the PIN never appears in the output"
sudo sh -c "ls -A '$W/cred'" | grep -qv '^regalia-kms-t\.pin$' && F "temporary files left in the credstore" || P "no temporary file left in the credstore"

hdr "3  the installed blob, on the boot it was sealed on"
yes(){ [ "$(open "${@:2}")" = "$PIN" ] && P "$1" || F "$1: did not open"; }
not(){ local o; o="$(open "${@:2}")"; [ $? != 0 ] && [ -z "$o" ] && P "$1" || F "$1: it opened"; }
yes "opens with this boot's signature" --tpm2-signature=sig1.json
not "does not open with an empty signature file" --tpm2-signature=nosig.json
not "does not open with another key's signature for the same kernel" --tpm2-signature=sig1-other.json
not "does not open with a signature for another kernel" --tpm2-signature=sig2.json

hdr "4  a kernel update signed by the same key: the same blob, no re-sealing"
before="$(sudo sha256sum "$BLOB" | cut -d' ' -f1)"
boot 2
yes "kernel 2 opens the blob sealed under kernel 1" --tpm2-signature=sig2.json
not "kernel 2 does not open it with kernel 1's signature" --tpm2-signature=sig1.json
[ "$(sudo sha256sum "$BLOB" | cut -d' ' -f1)" = "$before" ] && P "the blob is byte for byte the one sealed before the update" || F "the blob changed"

hdr "5  what must not open it"
boot 3
not "a kernel nobody signed (kernel 1's signature)" --tpm2-signature=sig1.json
not "a kernel signed by another key" --tpm2-signature=sig3-other.json
boot 1 another-secure-boot-state
not "the signed kernel under a different PCR 7" --tpm2-signature=sig1.json
boot 1 secure-boot-state "$PHASES shutdown"
not "the signed kernel past the phases the signature covers (shutdown)" --tpm2-signature=sig1.json
boot 1 secure-boot-state "enter-initrd"
not "the signed kernel still in the initrd (a signature for the running system only)" --tpm2-signature=sig1.json
boot 1
yes "control: the signed kernel, PCR 7 and phase as sealed, opens again" --tpm2-signature=sig1.json
# A TPM in dictionary-attack lockout refuses everything, which would make every refusal above pass
# for the wrong reason (it did, until stop() shut the TPM down in order: three killed swtpms = three
# failed tries = lockout, at swtpm's default limit of 3).
tpm2_getcap properties-variable 2>/dev/null | grep -q 'TPM2_PT_LOCKOUT_COUNTER: 0x0$' \
  && P "the TPM's lockout counter is still 0: no refusal above was a lockout" || F "the TPM counted failed tries: the refusals above prove nothing"

hdr "6  host_probe reads the binding from the blob, and a header that lies does not open"
# deploy/baremetal/host_probe.py (pin_credentials_sealed_as_recorded) reads what a blob is sealed to
# from its header. Here on the blob the script installed, not on a fixture.
header="$(sudo cat "$BLOB" | PYTHONPATH="$HERE" python3 -c 'import sys
from deploy.baremetal import host_probe
direct, signed, pkfp = host_probe.credential_header(sys.stdin.read())
print("+".join(map(str, direct)), "+".join(map(str, signed)), pkfp)')"
[ "$header" = "7 11 $fp" ] && P "the installed blob's header: PCR 7 direct, PCR 11 signed, by the key in the record" || F "host_probe read '$header', want '7 11 $fp'"
# The header is only worth reading if systemd refuses a blob whose header was edited: drop PCR 7 from
# the direct mask (offset 48), then drop PCR 11 from the signed mask, and try to open each.
sudo cat "$BLOB" | python3 -c 'import base64, struct, sys
raw = bytearray(base64.b64decode(sys.stdin.read()))
at = (32 + struct.unpack_from("<I", raw, 24)[0] + 7) & ~7
mask, _, _, blob, policy = struct.unpack_from("<QHHII", raw, at)
pk = (at + 20 + blob + policy + 7) & ~7
assert mask == 0x80 and struct.unpack_from("<Q", raw, pk)[0] == 0x800
a = bytearray(raw); struct.pack_into("<Q", a, at, 0); open("no-pcr7.cred", "w").write(base64.b64encode(a).decode())
b = bytearray(raw); struct.pack_into("<Q", b, pk, 0); open("no-pcr11.cred", "w").write(base64.b64encode(b).decode())' \
  || F "could not edit the blob's header"
for edited in no-pcr7 no-pcr11; do
  o="$(sudo env SYSTEMD_CREDENTIAL_SECRET="$HK" systemd-creds decrypt --tpm2-device="$D" --name=t.pin --tpm2-signature=sig1.json "$W/$edited.cred" - 2>/dev/null)"
  [ $? != 0 ] && [ -z "$o" ] && P "a blob whose header was edited ($edited) does not open" || F "$edited.cred opened: the header is not what binds the blob"
done
yes "control: the unedited blob still opens" --tpm2-signature=sig1.json

hdr "7  why the script checks the binding itself"
printf '%s' "$PIN" | sudo systemd-creds encrypt --with-key=tpm2 --tpm2-device="$D" --tpm2-pcrs=7 \
  --tpm2-public-key=pcr.pub --tpm2-public-key-pcrs=11 --name=t.pin - "$W/plain.cred" 2>/dev/null; rc=$?
if [ "$rc" != 0 ] || ! sudo test -s "$W/plain.cred"; then
  F "the control blob could not be made (systemd-creds encrypt --with-key=tpm2 with a public key: exit $rc)"
elif [ "$(sudo systemd-creds decrypt --tpm2-device="$D" --tpm2-signature=nosig.json --name=t.pin "$W/plain.cred" - 2>/dev/null)" = "$PIN" ]; then
  P "systemd-creds --with-key=tpm2 ignores --tpm2-public-key: its blob opens with no signature (the script uses tpm2-with-public-key and tests for this)"
else
  echo "  NOTE this systemd's --with-key=tpm2 honours --tpm2-public-key; the script's check stays as a guard"
fi

# The same question for the key type the script uses when there is NO signed policy.
printf '%s' "$PIN" | sudo env SYSTEMD_CREDENTIAL_SECRET="$HK" systemd-creds encrypt --with-key=host+tpm2 --tpm2-device="$D" --tpm2-pcrs=7 \
  --tpm2-public-key=pcr.pub --tpm2-public-key-pcrs=11 --name=t.pin - "$W/plain-host.cred" 2>/dev/null
if [ "$(sudo env SYSTEMD_CREDENTIAL_SECRET="$HK" systemd-creds decrypt --tpm2-device="$D" --tpm2-signature=nosig.json --name=t.pin "$W/plain-host.cred" - 2>/dev/null)" = "$PIN" ]; then
  P "--with-key=host+tpm2 ignores --tpm2-public-key too: only the …-with-public-key types bind a signed policy"
else
  echo "  NOTE this systemd's --with-key=host+tpm2 honours --tpm2-public-key; the script's check stays as a guard"
fi

hdr "8  the host-key half: the PIN needs the root disk as well as the TPM (#75)"
# with <host key file> <signature>: open the installed blob with THAT host key in front of the same TPM.
with(){ sudo env SYSTEMD_CREDENTIAL_SECRET="$W/$1" systemd-creds decrypt --tpm2-device="$D" --name=t.pin "--tpm2-signature=$2" "$BLOB" - 2>/dev/null; }
closed(){ local o; o="$(with "$2" "$3")"; [ $? != 0 ] && [ -z "$o" ] && P "$1" || F "$1: it opened"; }
opened(){ [ "$(with "$2" "$3")" = "$PIN" ] && P "$1" || F "$1: did not open"; }
boot 1
opened "image 1, this disk's host key: opens" host.secret sig1.json
closed "image 1, the credential file copied to ANOTHER disk (another host key), same TPM: does not open" other.secret sig1.json
closed "image 1, no host key at all (the root disk is not unlocked): does not open" absent.secret sig1.json
sudo test -e "$W/absent.secret" && F "systemd created a host key while DECRYPTING: 'no host key' was not tested" || P "…and decrypting created no host key"
boot 2
opened "image 2 (an update, no reseal), this disk's host key: opens" host.secret sig2.json
closed "image 2, another disk's host key: does not open" other.secret sig2.json
# A signed policy has no counter: image 1 is "retired" only in the manifest, and the TPM half still
# accepts it. What stops it is that a retired image cannot unlock the root disk to reach the host key.
boot 1
opened "back on image 1 after the update: the TPM half still accepts it (a signed policy never retires an image)" host.secret sig1.json
closed "…but without the host key it does not open: retirement is the root disk's to enforce" absent.secret sig1.json
# Why host_probe refuses a TPM-only credential: what the script sealed before #75.
printf '%s' "$PIN" | sudo systemd-creds encrypt --with-key=tpm2-with-public-key --tpm2-device="$D" --tpm2-pcrs=7 \
  --tpm2-public-key=pcr.pub --tpm2-public-key-pcrs=11 --name=t.pin - "$W/tpm-only.cred" 2>/dev/null
[ "$(sudo env SYSTEMD_CREDENTIAL_SECRET="$W/absent.secret" systemd-creds decrypt --tpm2-device="$D" --name=t.pin --tpm2-signature=sig1.json "$W/tpm-only.cred" - 2>/dev/null)" = "$PIN" ] \
  && P "a TPM-only credential (the old form) opens on a signed image with NO host key: the gap" || F "the TPM-only control blob did not open"
refusal="$(sudo cat "$W/tpm-only.cred" | PYTHONPATH="$HERE" python3 -c 'import sys
from deploy.baremetal import host_probe
try: host_probe.credential_header(sys.stdin.read()); print("accepted")
except ValueError as e: print(e)')"
grep -q "the TPM alone, with no host key" <<< "$refusal" && P "host_probe refuses that credential and says to reseal it" || F "host_probe on a TPM-only blob: $refusal"
tpm2_getcap properties-variable 2>/dev/null | grep -q 'TPM2_PT_LOCKOUT_COUNTER: 0x0$' \
  && P "the TPM's lockout counter is still 0: no refusal in this section was a lockout" || F "the TPM counted failed tries: the refusals above prove nothing"

hdr "9  no signed policy: --pcrs 7 alone is sealed to the host key and the TPM too"
# The other branch of the script. A regression to --with-key=tpm2 there would seal to the TPM alone.
out="$(seal --pcrs 7 --replace)"; rc=$?
[ "$rc" = 0 ] && grep -q '^SEALED' <<< "$out" && P "sealed with --pcrs 7 and no public key" || F "unsigned seal failed (exit $rc): $out"
grep -q 'host key + tpm2, PCRs 7 (TEST TPM' <<< "$out" && ! grep -q 'signed PCRs' <<< "$out" && P "the record: the host key and the TPM, PCR 7, no signed policy" || F "record: $out"
[ "$(sudo cat "$BLOB" | base64 -d | head -c 16 | od -An -tx1 | tr -d ' \n')" = 93a894094874449090caf2fc93cab553 ] \
  && P "the blob's key type is host+tpm2 (93a89409…), not tpm2" || F "the unsigned blob has another key type"
plain(){ sudo env SYSTEMD_CREDENTIAL_SECRET="$W/$1" systemd-creds decrypt --tpm2-device="$D" --name=t.pin "$BLOB" - 2>/dev/null; }
[ "$(plain host.secret)" = "$PIN" ] && P "it opens with this disk's host key" || F "the unsigned blob did not open"
for k in other absent; do
  o="$(plain "$k.secret")"; [ $? != 0 ] && [ -z "$o" ] && P "it does not open with $k host key" || F "the unsigned blob opened with $k host key"
done
header="$(sudo cat "$BLOB" | PYTHONPATH="$HERE" python3 -c 'import sys
from deploy.baremetal import host_probe
direct, signed, pkfp = host_probe.credential_header(sys.stdin.read())
print("+".join(map(str, direct)), "+".join(map(str, signed)) or "-", pkfp or "-")')"
[ "$header" = "7 - -" ] && P "host_probe reads it as PCR 7, no signed policy" || F "host_probe read '$header', want '7 - -'"
boot 1 another-secure-boot-state
o="$(plain host.secret)"; [ $? != 0 ] && [ -z "$o" ] && P "under a different PCR 7 it does not open, host key or not" || F "the unsigned blob opened under another PCR 7"
tpm2_getcap properties-variable 2>/dev/null | grep -q 'TPM2_PT_LOCKOUT_COUNTER: 0x0$' \
  && P "the TPM's lockout counter is still 0" || F "the TPM counted failed tries: the refusals above prove nothing"

echo; echo "pcr-signed-policy-swtpm: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
