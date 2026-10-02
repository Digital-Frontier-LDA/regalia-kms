#!/usr/bin/env bash
# tpm-attest-swtpm.sh — deploy/baremetal/attest.py against two software TPMs (swtpm): node A is the
# enrolled node, B is another machine's TPM. No hardware, no root; it runs in CI on every change.
# regalia-kms#65 PoC 5.1 (AK enrollment), 5.4 (nonce -> quote, verified remotely), 5.5 (replay).
#
#   e2e/tpm-attest-swtpm.sh
#
#   1  enrollment: the AK is a restricted signing key and MakeCredential/ActivateCredential binds it to
#      the EK recorded at intake; an unknown node, another TPM's EK, another TPM's AK, an unrestricted
#      key and a silent re-enrollment are each refused
#   2  a fresh quote over the boot-session transcript is accepted
#   3  replay and substitution: a used nonce, an old quote under a new nonce, each transcript field
#      changed on its own, altered PCRs, a different PCR selection, another TPM's AK and altered bytes
#      are each refused
#   4  reboots (TPMS_CLOCK_INFO): a boot session never outlives a reboot, one boot carries one session,
#      and rolled-back TPM state is refused
#
# The PCR values are stand-ins extended by this script (PCRs 0 and 7). WHICH PCRs a DL360 must be held
# to is PoC 5.2/5.3, on the hardware.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ATTEST="$HERE/deploy/baremetal/attest.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
for t in swtpm tpm2_createek tpm2_createak tpm2_makecredential tpm2_quote openssl python3; do
  command -v "$t" >/dev/null || { echo "tpm-attest-swtpm: $t is required (swtpm, tpm2-tools, openssl, python3)"; exit 2; }
done
W="$(mktemp -d)"   # private sockets under it, no fixed ports: runs beside any other swtpm test
[ "${#W}" -le 80 ] || { echo "tpm-attest-swtpm: $W is too long for a unix socket path; set TMPDIR to a shorter one"; exit 2; }
stop(){ [ -f "$W/$1.pid" ] && kill "$(cat "$W/$1.pid")" 2>/dev/null; rm -f "$W/$1.pid"; sleep 0.3; }
trap 'stop A; stop B; rm -rf "$W"' EXIT
tcti(){ printf 'swtpm:path=%s' "$W/$1.sock"; }
M0="$(printf 'firmware stand-in' | sha256sum | cut -d' ' -f1)"; M7="$(printf 'secure boot stand-in' | sha256sum | cut -d' ' -f1)"
# one boot: TPM2_Startup(CLEAR) (resetCount + 1, PCRs zeroed), then the same measurements every time
boot(){ mkdir -p "$W/$1"; swtpm socket --tpm2 --tpmstate "dir=$W/$1" --server "type=unixio,path=$W/$1.sock" \
  --ctrl "type=unixio,path=$W/$1.sock.ctrl" --flags not-need-init,startup-clear --daemon --pid "file=$W/$1.pid"; sleep 0.5
  TPM2TOOLS_TCTI="$(tcti "$1")" tpm2_pcrextend "0:sha256=$M0" "7:sha256=$M7"; }
node(){ local t="$1"; shift; TPM2TOOLS_TCTI="$(tcti "$t")" python3 "$ATTEST" "$@" 2>&1; }
ver(){ local c="$1"; shift; python3 "$ATTEST" "$c" --policy "$W/policy.json" --state "$W/state.json" "$@" 2>&1; }
rnd(){ openssl rand -hex 32; }
ephemeral(){ openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -pubout -outform DER -out "$1"; }
# refused NAME REASON CMD...: the command must exit nonzero AND give that reason
refused(){ local name="$1" reason="$2" out rc; shift 2; out="$("$@")"; rc=$?
  [ "$rc" != 0 ] && grep -q -- "$reason" <<< "$out" && P "$name (exit $rc)" || F "$name: exit $rc: $out"; }
# quote TPM NODE-ID EPOCH SESSION KEYFILE NONCE [PCRS] -> $W/q.msg, $W/q.sig
# (a quote that was not made must fail the run: the arm after it would otherwise refuse the PREVIOUS quote)
quote(){ rm -f "$W/q.msg" "$W/q.sig"
  node "$1" node-quote --node-id "$2" --epoch "$3" --session-id "$4" --ephemeral-public "$5" --nonce "$6" \
    --pcrs "${7:-0,7}" --quote "$W/q.msg" --signature "$W/q.sig" && [ -s "$W/q.msg" ] && [ -s "$W/q.sig" ] || F "TPM $1 made no quote"; }
# verify EPOCH SESSION KEYFILE NONCE [QUOTE [SIG]], always as site-a
verify(){ ver verify --node-id site-a --epoch "$1" --session-id "$2" --ephemeral-public "$3" --nonce "$4" \
  --quote "${5:-$W/q.msg}" --signature "${6:-$W/q.sig}"; }

boot A; boot B
mkdir "$W/a" "$W/b"
node A node-init --out "$W/a" >/dev/null || F "node-init on A failed"
node B node-init --out "$W/b" >/dev/null || F "node-init on B failed"
# INTAKE: the verifier's reference values for site-a, read from TPM A while it is trusted
TPM2TOOLS_TCTI="$(tcti A)" python3 - "$HERE" "$W" <<'PY' || { echo "tpm-attest-swtpm: intake failed"; exit 1; }
import json, re, subprocess, sys
sys.path.insert(0, sys.argv[1])
from deploy.baremetal import attest
w = sys.argv[2]
cap = subprocess.run(["tpm2_getcap", "properties-fixed"], check=True, capture_output=True, text=True).stdout
fw = [int(re.search(r"TPM2_PT_FIRMWARE_VERSION_%d:\s+raw: (0x[0-9A-Fa-f]+)" % i, cap).group(1), 16) for i in (1, 2)]
pcr = subprocess.run(["tpm2_pcrread", "sha256:0,7"], check=True, capture_output=True, text=True).stdout
pcrs = {m.group(1): m.group(2).lower() for m in re.finditer(r"^\s+(\d+)\s*: 0x([0-9A-Fa-f]{64})$", pcr, re.M)}
assert sorted(pcrs) == ["0", "7"], pcr
ek = attest.name_of(attest.public_area(open(w + "/a/ek.pub", "rb").read(), "EK")).hex()
json.dump({"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": {
    "ek_name": ek, "tpm_firmware_version": "%08x%08x" % tuple(fw), "pcrs": pcrs}}}, open(w + "/policy.json", "w"))
PY

hdr "1  enrollment: the AK is bound to the EK recorded at intake (PoC 5.1)"
enroll_args=(--node-id site-a --ek-public "$W/a/ek.pub" --ak-public "$W/a/ak.pub" --credential "$W/cred")
refused "a node that is not in the policy is refused" 'unknown node' \
  ver challenge --node-id site-z --ek-public "$W/a/ek.pub" --ak-public "$W/a/ak.pub" --credential "$W/cred"
refused "another TPM's EK is refused for site-a" 'not the one recorded for this node at intake' \
  ver challenge --node-id site-a --ek-public "$W/b/ek.pub" --ak-public "$W/b/ak.pub" --credential "$W/cred"
( TPM2TOOLS_TCTI="$(tcti A)"; export TPM2TOOLS_TCTI; tpm2_createprimary -C e -G ecc256:ecdsa-sha256 -c "$W/plain.ctx" \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' && tpm2_readpublic -c "$W/plain.ctx" -o "$W/plain.pub" ) \
  >/dev/null 2>&1 || F "could not make the unrestricted key"
TPM2TOOLS_TCTI="$(tcti A)" tpm2_flushcontext -t
refused "an unrestricted signing key is refused as an AK" 'must be a restricted, sign-only' \
  ver challenge --node-id site-a --ek-public "$W/a/ek.pub" --ak-public "$W/plain.pub" --credential "$W/cred"
# A's EK with B's AK: the verifier cannot tell from the public areas, so the credential decides
ver challenge --node-id site-a --ek-public "$W/a/ek.pub" --ak-public "$W/b/ak.pub" --credential "$W/cred.x" >/dev/null || F "challenge failed"
refused "TPM B cannot open a credential made for A's EK" 'does not hold the EK and AK' \
  node B node-activate --credential "$W/cred.x" --secret "$W/secret.xb"
refused "TPM A cannot open a credential made for B's AK" 'does not hold the EK and AK' \
  node A node-activate --credential "$W/cred.x" --secret "$W/secret.xa"
openssl rand -out "$W/guess" 32
refused "a guessed secret does not enroll the AK" 'not the secret that was wrapped' ver enroll --node-id site-a --secret "$W/guess"
ver challenge "${enroll_args[@]}" >/dev/null || F "challenge failed"
out="$(node A node-activate --credential "$W/cred" --secret "$W/secret")" && [ "$(stat -c %a "$W/secret")" = 600 ] \
  && P "TPM A opens its credential (the secret is written 0600)" || F "activation failed: $out"
grep -q "$(od -An -v -tx1 "$W/secret" | tr -d ' \n')" <<< "$out" && F "the secret appeared in the output" || P "the secret never appears in the output"
out="$(ver enroll --node-id site-a --secret "$W/secret")" && grep -q '^ENROLLED site-a AK 000b' <<< "$out" \
  && P "the AK is enrolled once the secret comes back" || F "enroll failed: $out"
refused "the same secret does not enroll twice" 'no enrollment challenge is outstanding' ver enroll --node-id site-a --secret "$W/secret"
refused "a second enrollment needs --replace" 'already has an enrolled AK' ver challenge "${enroll_args[@]}"

hdr "2  a fresh quote, bound to the boot session (PoC 5.4)"
S1="$(rnd)"; ephemeral "$W/k1.der"; EPOCH=7
N="$(ver nonce --node-id site-a)"
quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
out="$(verify "$EPOCH" "$S1" "$W/k1.der" "$N")" && grep -q '^ACCEPTED .*"reset_count": 1' <<< "$out" \
  && P "accepted: signature, nonce, transcript, PCRs, AK, firmware version, counters" || F "a good quote was refused: $out"
cp "$W/q.msg" "$W/old.msg"; cp "$W/q.sig" "$W/old.sig"; OLD="$N"

hdr "3  replay and substitution (PoC 5.5)"
refused "the same quote with its used nonce is refused" 'nonce is not outstanding' verify "$EPOCH" "$S1" "$W/k1.der" "$OLD"
refused "a nonce the verifier never issued is refused" 'nonce is not outstanding' verify "$EPOCH" "$S1" "$W/k1.der" "$(rnd)"
N="$(ver nonce --node-id site-a)"
refused "the old quote under a new nonce is refused" 'not bound to this transcript' verify "$EPOCH" "$S1" "$W/k1.der" "$N" "$W/old.msg" "$W/old.sig"
ephemeral "$W/other.der"; OTHER="$(rnd)"
# each transcript field changed on its own: the node quotes one thing, the verifier holds another
N="$(ver nonce --node-id site-a)"; quote A site-b "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "a quote made for another node ID is refused" 'not bound to this transcript' verify "$EPOCH" "$S1" "$W/k1.der" "$N"
N="$(ver nonce --node-id site-a)"; quote A site-a 6 "$S1" "$W/k1.der" "$N"
refused "a quote made at another manifest epoch is refused" 'not bound to this transcript' verify "$EPOCH" "$S1" "$W/k1.der" "$N"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "a substituted boot session ID is refused" 'not bound to this transcript' verify "$EPOCH" "$OTHER" "$W/k1.der" "$N"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "a substituted ephemeral key is refused" 'not bound to this transcript' verify "$EPOCH" "$S1" "$W/other.der" "$N"
N="$(ver nonce --node-id site-a)"; N2="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "a quote over one nonce is refused under another" 'not bound to this transcript' verify "$EPOCH" "$S1" "$W/k1.der" "$N2"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N" 0
refused "a quote over a different PCR selection is refused" 'covers PCRs' verify "$EPOCH" "$S1" "$W/k1.der" "$N"
N="$(ver nonce --node-id site-a)"; quote B site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "a quote signed by another TPM's AK is refused" 'signature does not verify' verify "$EPOCH" "$S1" "$W/k1.der" "$N"
flip(){ python3 -c 'import sys; b=bytearray(open(sys.argv[1],"rb").read()); b[int(sys.argv[3])]^=1; open(sys.argv[2],"wb").write(b)' "$@"; }
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"; flip "$W/q.sig" "$W/bad.sig" 10
refused "an altered signature is refused" 'signature does not verify' verify "$EPOCH" "$S1" "$W/k1.der" "$N" "$W/q.msg" "$W/bad.sig"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"; flip "$W/q.msg" "$W/bad.msg" -1
refused "an altered PCR digest in the quote is refused" 'signature does not verify' verify "$EPOCH" "$S1" "$W/k1.der" "$N" "$W/bad.msg"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
out="$(verify "$EPOCH" "$S1" "$W/k1.der" "$N")" && P "after every refusal, the same boot session still verifies with a fresh nonce" || F "refused: $out"
TPM2TOOLS_TCTI="$(tcti A)" tpm2_pcrextend "7:sha256=$(printf 'a changed boot chain' | sha256sum | cut -d' ' -f1)"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "changed PCR values are refused" 'not the expected PCR values' verify "$EPOCH" "$S1" "$W/k1.der" "$N"

hdr "4  reboots: the TPM's reset counter (TPMS_CLOCK_INFO)"
stop A; cp -a "$W/A" "$W/A.boot1"; boot A   # second boot; A.boot1 is the TPM's state as it was before it
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S1" "$W/k1.der" "$N"
refused "the previous boot's session and ephemeral key are refused after a reboot" 'from an earlier boot' verify "$EPOCH" "$S1" "$W/k1.der" "$N"
S2="$(rnd)"; ephemeral "$W/k2.der"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S2" "$W/k2.der" "$N"
out="$(verify "$EPOCH" "$S2" "$W/k2.der" "$N")" && grep -q '"reset_count": 2' <<< "$out" \
  && P "a new boot session is accepted after the reboot (resetCount 2)" || F "the new boot session was refused: $out"
S3="$(rnd)"; ephemeral "$W/k3.der"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S3" "$W/k3.der" "$N"
refused "a second boot session in the same boot is refused" 'second boot session in the same boot' verify "$EPOCH" "$S3" "$W/k3.der" "$N"
stop A; boot A   # third boot
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S3" "$W/k3.der" "$N"
out="$(verify "$EPOCH" "$S3" "$W/k3.der" "$N")" && grep -q '"reset_count": 3' <<< "$out" && P "third boot accepted (resetCount 3)" || F "third boot refused: $out"
stop A; rm -rf "$W/A"; mv "$W/A.boot1" "$W/A"; boot A   # the TPM's state rolled back to before boot 2
S4="$(rnd)"; ephemeral "$W/k4.der"
N="$(ver nonce --node-id site-a)"; quote A site-a "$EPOCH" "$S4" "$W/k4.der" "$N"
refused "rolled-back TPM state is refused (resetCount 2 after 3)" 'counters went backwards' verify "$EPOCH" "$S4" "$W/k4.der" "$N"

echo; echo "tpm-attest-swtpm: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
