#!/usr/bin/env bash
# kms-hardened-serve.sh — the REAL regalia-kms binary, started by systemd from the SHIPPED unit
# (deploy/systemd/regalia-kms.service) and the SHIPPED hardening drop-in
# (deploy/baremetal/regalia-kms-hardening.conf.example), serves a signature from a SoftHSM token that
# openssl then verifies; and the hardening is measured on THAT process (#61).
#
# e2e/kms-sandbox-negative.sh shows what the sandbox refuses a dummy service. This shows the other
# half: the daemon still works inside it.
#
#   REGALIA_SANDBOX_HOST_OK=1 e2e/kms-hardened-serve.sh       (CI sets nothing: GITHUB_ACTIONS is enough)
#
# It INSTALLS on this machine: the binary at /usr/local/sbin/regalia-kms, a regalia-kms system user,
# /etc/regalia-kms, /var/lib/regalia-kms, the unit and its drop-ins, and the AppArmor profile (in
# complain mode); and it starts the unit on the machine's own system manager. All of it is removed at
# the end. That is fine on a CI runner or a throwaway VM, and it is refused anywhere else unless
# REGALIA_SANDBOX_HOST_OK=1 says the host is one of those. Never a shared or production machine.
#
# What is the test's own, and not shipped (drop-in zz-e2e.conf, three lines):
#   Environment=SOFTHSM2_CONF=…   libsofthsm2 finds its token directory through it
#   LoadCredential=…              the PIN as a systemd credential, as production loads it, but from a
#                                 plain file: a runner has no TPM for LoadCredentialEncrypted
#   LimitMEMLOCK=1M               as deploy/systemd/regalia-kms-credentials.conf.example sets it
# The token is SoftHSM, through the daemon's ordinary PKCS#11 backend: no pcscd, no OpenSC, no card.
# The AppArmor profile is loaded in COMPLAIN mode, the first step its own header prescribes: it was
# written for OpenSC and pcscd and has never confined a running daemon. So kms_apparmor_enforced must
# FAIL here, and saying "complain" is what this test requires of it.
#
#   1  -check-config accepts the configuration, as the service user
#   2  systemd starts the shipped unit; the daemon is ready; it is the installed binary, as regalia-kms
#   3  it serves: POST /v1/operations/sign returns a signature openssl verifies against the token's
#      public key; an altered message does not verify; a replayed nonce and a caller with no
#      certificate are refused
#   4  the hardening on that process: os_probe's kms_service_unprivileged, kms_service_sandboxed and
#      kms_capabilities_minimal measure true; NoNewPrivs and a seccomp filter in /proc
#   5  AppArmor: the process carries the profile's label in complain mode, and the probe says so
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
die(){ printf 'kms-hardened-serve: %s\n' "$*" >&2; exit 2; }
if [ "${GITHUB_ACTIONS:-}" != true ] && [ "${REGALIA_SANDBOX_HOST_OK:-}" != 1 ]; then
  echo "kms-hardened-serve: refused: this installs a binary, a system user, a unit and an AppArmor profile on this"
  echo "  machine and starts the unit on its system manager. Run it in CI or on a throwaway VM (REGALIA_SANDBOX_HOST_OK=1)."
  exit 2
fi
export PATH="$PATH:/usr/sbin:/sbin"
for t in go softhsm2-util pkcs11-tool openssl python3 curl systemctl apparmor_parser; do
  command -v "$t" >/dev/null || die "$t is required"; done
sudo -n true 2>/dev/null || die "needs sudo"
MODULE=""; for c in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do [ -f "$c" ] && MODULE="$c" && break; done
[ -n "$MODULE" ] || die "libsofthsm2.so not found"
# Everything the cleanup removes must not exist yet: a host that has any of it is somebody's installation.
for existing in /etc/systemd/system/regalia-kms.service /etc/systemd/system/regalia-kms.service.d /etc/regalia-kms \
                /var/lib/regalia-kms /usr/local/sbin/regalia-kms; do
  [ ! -e "$existing" ] && [ ! -L "$existing" ] || die "this machine already has $existing: not a throwaway host, and the cleanup would delete it"
done
if sudo grep -q '^regalia-kms ' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
  die "an AppArmor profile named regalia-kms is already loaded: not a throwaway host, and the cleanup would unload it"
fi
echo "kms-hardened-serve: $(systemctl --version | head -1), kernel $(uname -r), AppArmor $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"

ETC=/etc/regalia-kms; STATE=/var/lib/regalia-kms; UNITDIR=/etc/systemd/system; SVC=regalia-kms.service
PORT=18443; SINK=18444; SITE=e2e-site; DEVICE=softhsm-e2e; OBJECT=e2e-signing-key; PRINCIPAL=spiffe://regalia/workload/e2e
PROFILE="$HERE/deploy/baremetal/apparmor/usr.local.sbin.regalia-kms"
W="$(mktemp -d)"; collector=""; made_user=0
cleanup(){
  sudo systemctl stop "$SVC" 2>/dev/null
  [ -n "$collector" ] && kill "$collector" 2>/dev/null
  sudo rm -rf "$UNITDIR/$SVC" "$UNITDIR/$SVC.d" "$ETC" "$STATE" /usr/local/sbin/regalia-kms "$W"
  sudo systemctl daemon-reload 2>/dev/null
  sudo apparmor_parser -R "$PROFILE" 2>/dev/null
  [ "$made_user" = 1 ] && sudo userdel regalia-kms 2>/dev/null
}
trap cleanup EXIT
as_kms(){ sudo -u regalia-kms env SOFTHSM2_CONF="$ETC/softhsm2.conf" "$@"; }

# ---- build and install -------------------------------------------------------------------------------
go -C "$HERE" build -o "$W/regalia-kms" ./cmd/regalia-kms || die "cannot build regalia-kms"
go -C "$HERE" build -o "$W/regalia-audit-collector" ./cmd/regalia-audit-collector || die "cannot build the audit collector"
sudo install -m 0755 "$W/regalia-kms" /usr/local/sbin/regalia-kms || die "cannot install the binary"
if ! id regalia-kms >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin regalia-kms || die "cannot create the regalia-kms user"; made_user=1
fi
sudo install -d -m 0750 -o root -g regalia-kms "$ETC" || die "cannot create $ETC"
sudo install -d -m 0700 -o regalia-kms -g regalia-kms "$STATE" "$STATE/softhsm" "$STATE/softhsm/tokens" || die "cannot create $STATE"

# ---- the token: SoftHSM, initialised as the service user, in its state directory ------------------------
PIN="$(openssl rand -hex 8)"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$STATE/softhsm/tokens" > "$W/softhsm2.conf"
sudo install -m 0640 -o root -g regalia-kms "$W/softhsm2.conf" "$ETC/softhsm2.conf"
as_kms softhsm2-util --init-token --free --label regalia-e2e --so-pin "$(openssl rand -hex 8)" --pin "$PIN" >/dev/null || die "cannot initialise the SoftHSM token"
as_kms env P="$PIN" pkcs11-tool --module "$MODULE" --token-label regalia-e2e --login --pin env:P \
  --keypairgen --key-type EC:prime256v1 --usage-sign --label regalia-e2e --id 01 >/dev/null 2>&1 || die "cannot generate the P-256 key on the token"
as_kms pkcs11-tool --module "$MODULE" --token-label regalia-e2e --read-object --type pubkey --id 01 --output-file "$STATE/pub.der" >/dev/null 2>&1 \
  || die "cannot read the public key"
# shellcheck disable=SC2024  # the copy is this user's, on purpose
sudo cat "$STATE/pub.der" > "$W/pub.der"; sudo rm -f "$STATE/pub.der"
openssl pkey -pubin -inform DER -in "$W/pub.der" -out "$W/pub.pem" || die "the token's public key is not a SubjectPublicKeyInfo"
SERIAL="$(as_kms pkcs11-tool --module "$MODULE" --token-label regalia-e2e --list-slots 2>/dev/null | awk -F: '/serial num/{gsub(/[[:space:]]/, "", $2); print $2; exit}')"
[ -n "$SERIAL" ] || die "SoftHSM serial unavailable"
KEYPIN="sha256:$(sha256sum "$W/pub.der" | cut -d' ' -f1)"

# ---- PKI: a CA, the daemon (also the audit client), the collector, one workload client ---------------------
ossl(){ openssl "$@" 2>/dev/null || die "openssl $1 failed"; }
ossl ecparam -genkey -name prime256v1 -noout -out "$W/ca.key"
ossl req -new -x509 -key "$W/ca.key" -subj "/CN=regalia e2e CA" -days 2 -out "$W/ca.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
cert(){ # name, extensions
  ossl ecparam -genkey -name prime256v1 -noout -out "$W/$1.key"
  ossl req -new -key "$W/$1.key" -subj "/CN=regalia e2e $1" -out "$W/$1.csr"
  printf '%b\n' "$2" > "$W/$1.ext"
  ossl x509 -req -in "$W/$1.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -set_serial "0x$(openssl rand -hex 8)" -days 2 -extfile "$W/$1.ext" -out "$W/$1.pem"; }
cert server "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature"
cert collector "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"
cert client "subjectAltName=URI:$PRINCIPAL\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature"

# ---- the daemon's configuration, under /etc/regalia-kms --------------------------------------------------
NOW="$(date -u +%FT%TZ)"; TOMORROW="$(date -u -d '+1 day' +%FT%TZ)"
cat > "$W/secure-channel.json" <<JSON
{"schema_version": 1, "devices": [{"device_serial": "$SERIAL", "verified_by": "e2e", "verified_at": "$NOW",
  "expires_at": "$TOMORROW", "firmware": "softhsm", "secure_messaging_established": true}]}
JSON
cat > "$W/manifest.json" <<JSON
{"schema_version": 1, "manifest_id": "hardened-serve-e2e", "generated_at": "$NOW", "objects": [{
  "id": "$OBJECT", "name": "E2E P-256 signing key", "kind": "asymmetric-key", "classification": "restricted",
  "environment": "staging", "owner": "security", "purpose": "e2e-signing", "custody": "direct-hardware",
  "algorithm": "p256", "operations": ["sign"], "policy_id": "e2e-sign",
  "bindings": [{"site": "$SITE", "backend": "nitrokey-pkcs11", "device_id": "$DEVICE", "device_serial": "$SERIAL",
                "object_id": "01", "public_key_sha256": "$KEYPIN", "public_fingerprint": "$KEYPIN", "state": "active"}],
  "recovery": {"mode": "shamir-4-of-6", "authority_id": "e2e", "minimum_replicas": 2, "status": "tested"},
  "rotation": {"maximum_age_days": 90, "last_rotated": null},
  "migration": {"status": "migrated", "source": "e2e"},
  "verification": {"status": "verified", "last_verified": "${NOW%%T*}", "evidence": "e2e"}}]}
JSON
cat > "$W/policy.json" <<JSON
{"schema_version": 1, "policies": [{"id": "e2e-sign", "object_id": "$OBJECT", "purpose": "e2e-signing",
  "environment": "staging", "operation": "sign", "algorithm": "p256",
  "content_types": ["application/vnd.regalia.digest"], "max_payload_bytes": 32,
  "max_future_seconds": 300, "required_approvals": 0, "approvers": ["spiffe://regalia/approver/e2e"]}]}
JSON
cat > "$W/rbac.json" <<JSON
{"schema_version": 1, "principals": [{"uri": "$PRINCIPAL", "grants": [
  {"objects": ["$OBJECT"], "operations": ["sign"], "environments": ["staging"]}]}]}
JSON
cat > "$W/config.json" <<JSON
{"listen_address": "127.0.0.1:$PORT", "site": "$SITE",
 "registry_path": "$ETC/manifest.json", "rbac_policy_path": "$ETC/rbac.json",
 "policy_path": "$ETC/policy.json", "policy_state_path": "$STATE/policy-state.jsonl",
 "tls_certificate_path": "$ETC/server.pem", "tls_private_key_path": "$ETC/server.key", "tls_client_ca_path": "$ETC/ca.pem",
 "pkcs11_module_path": "$MODULE", "secure_channel_evidence_path": "$ETC/secure-channel.json",
 "pin_paths": {"$DEVICE": "/run/credentials/$SVC/$DEVICE.pin"},
 "audit_journal_path": "$STATE/audit.jsonl", "audit_sink_url": "https://127.0.0.1:$SINK"}
JSON
for f in config.json manifest.json policy.json rbac.json secure-channel.json server.pem server.key ca.pem; do
  sudo install -m 0640 -o root -g regalia-kms "$W/$f" "$ETC/$f" || die "cannot install $f"; done
# The PIN: root's alone on disk; systemd hands it to the service as a credential.
printf '%s' "$PIN" > "$W/pin"; sudo install -m 0600 -o root -g root "$W/pin" "$ETC/softhsm.pin"; rm -f "$W/pin"

# ---- the unit: the shipped file, the shipped drop-in, and the test's three lines ---------------------------
sudo install -m 0644 "$HERE/deploy/systemd/regalia-kms.service" "$UNITDIR/$SVC"
sudo install -d -m 0755 "$UNITDIR/$SVC.d"
sudo install -m 0644 "$HERE/deploy/baremetal/regalia-kms-hardening.conf.example" "$UNITDIR/$SVC.d/hardening.conf"
printf '[Service]\nEnvironment=SOFTHSM2_CONF=%s\nLoadCredential=%s.pin:%s\nLimitMEMLOCK=1M\n' "$ETC/softhsm2.conf" "$DEVICE" "$ETC/softhsm.pin" > "$W/zz-e2e.conf"
sudo install -m 0644 "$W/zz-e2e.conf" "$UNITDIR/$SVC.d/zz-e2e.conf"
sudo apparmor_parser -r -C "$PROFILE" || die "cannot load the AppArmor profile in complain mode"
sudo systemctl daemon-reload

# ---- the off-host audit collector (another host in production; here, another process) ----------------------
mkdir -m 0700 "$W/collector-state"
"$W/regalia-audit-collector" -state "$W/collector-state" -listen "127.0.0.1:$SINK" -tls-cert "$W/collector.pem" \
  -tls-key "$W/collector.key" -client-ca "$W/ca.pem" > "$W/collector.log" 2>&1 &
collector=$!
sleep 2; kill -0 "$collector" 2>/dev/null || die "the audit collector did not start: $(tail -5 "$W/collector.log")"

hdr "1  the configuration"
out="$(as_kms /usr/local/sbin/regalia-kms -config "$ETC/config.json" -check-config 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "-check-config accepts it, as the service user" || F "-check-config (exit $rc): $(tail -c 600 <<< "$out")"

hdr "2  systemd starts the shipped unit"
journal(){ sudo journalctl -u "$SVC" --no-pager -n 40 2>/dev/null | cut -c1-300; }
sudo systemctl start "$SVC"; rc=$?
[ "$rc" = 0 ] && P "systemctl start $SVC" || { F "systemctl start failed (exit $rc)"; journal; }
ready=""
for _ in $(seq 1 60); do
  ready="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$W/ca.pem" "https://127.0.0.1:$PORT/v1/health/ready" 2>/dev/null)"
  [ "$ready" = 200 ] && break; systemctl is-active --quiet "$SVC" || break; sleep 1
done
[ "$ready" = 200 ] && P "the daemon is ready (GET /v1/health/ready: 200)" || { F "not ready (HTTP ${ready:-none}; unit $(systemctl is-active "$SVC"))"; journal; }
pid="$(systemctl show "$SVC" -p MainPID --value)"
exe="$(sudo readlink "/proc/$pid/exe" 2>/dev/null)"; uid="$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
[ "$exe" = /usr/local/sbin/regalia-kms ] && [ "$uid" = "$(id -u regalia-kms)" ] && [ "$uid" != 0 ] \
  && P "the main process (pid $pid) is the installed binary, running as regalia-kms (uid $uid)" || F "pid $pid runs '$exe' as uid '$uid'"
dropins="$(systemctl show "$SVC" -p DropInPaths --value)"
grep -q hardening.conf <<< "$dropins" && P "the shipped hardening drop-in is in effect ($dropins)" || F "drop-ins in effect: '$dropins'"

hdr "3  it serves: a signature from the token, verified by openssl"
printf 'regalia-kms hardened-serve e2e %s\n' "$NOW" > "$W/message"
# sign <nonce> [curl args]: POST the SHA-256 digest of the message; the HTTP status goes to stdout, the body to $W/response.
sign(){ local nonce="$1"; shift
  python3 - "$W/message" "$nonce" "$OBJECT" > "$W/request.json" <<'PY'
import base64, datetime, hashlib, json, sys
digest = hashlib.sha256(open(sys.argv[1], "rb").read()).digest()
expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump({"object_id": sys.argv[3], "context": {"environment": "staging", "purpose": "e2e-signing", "expires_at": expires, "nonce": sys.argv[2]},
           "content_type": "application/vnd.regalia.digest", "payload_base64": base64.b64encode(digest).decode()}, sys.stdout)
PY
  curl -s -o "$W/response" -w '%{http_code}' --cacert "$W/ca.pem" "$@" -H 'Content-Type: application/json' \
    -H "X-Request-ID: $(cat /proc/sys/kernel/random/uuid)" -H "Idempotency-Key: $nonce" \
    --data-binary "@$W/request.json" "https://127.0.0.1:$PORT/v1/operations/sign"; }
mtls=(--cert "$W/client.pem" --key "$W/client.key")
nonce="e2e-nonce-$(openssl rand -hex 12)"
status="$(sign "$nonce" "${mtls[@]}")"
if [ "$status" = 200 ]; then P "POST /v1/operations/sign: 200"; else
  F "sign: HTTP $status: $(head -c 400 "$W/response")"
  # The daemon says only BACKEND_UNAVAILABLE to a caller; what it could and could not use is here.
  # Looked at from INSIDE the service's mount namespace: the credential directory is not on the host's /run.
  echo "  the PIN credential, as the service sees it:"
  sudo nsenter -t "$pid" -m -- sh -c "stat -c '%n %U:%G mode %a (%F)' /run/credentials/$SVC/* 2>&1; command -v getfacl >/dev/null && getfacl -p /run/credentials/$SVC/* 2>&1; grep -E 'Max locked memory' /proc/$pid/limits" 2>&1 | sed 's/^/    /'
  echo "  ready after the failure: HTTP $(curl -s -o /dev/null -w '%{http_code}' --cacert "$W/ca.pem" "https://127.0.0.1:$PORT/v1/health/ready")"
  echo "  the last audit records:"; sudo tail -n 3 "$STATE/audit.jsonl" 2>&1 | cut -c1-1500 | sed 's/^/    /'
  journal
fi
# The KMS returns raw r||s; openssl wants DER SEQUENCE{INTEGER r, INTEGER s}.
python3 - "$W/response" "$W/sig.der" <<'PY' && P "the result is a 64-byte P-256 signature (r||s)" || F "the response carries no 64-byte signature: $(head -c 300 "$W/response")"
import base64, json, sys
raw = base64.b64decode(json.load(open(sys.argv[1]))["result_base64"], validate=True)
assert len(raw) == 64, len(raw)
def integer(b):
    b = b.lstrip(b"\x00") or b"\x00"
    b = (b"\x00" + b) if b[0] & 0x80 else b
    return b"\x02" + bytes([len(b)]) + b
body = integer(raw[:32]) + integer(raw[32:])
open(sys.argv[2], "wb").write(b"\x30" + bytes([len(body)]) + body)
PY
openssl dgst -sha256 -verify "$W/pub.pem" -signature "$W/sig.der" "$W/message" >/dev/null 2>&1 \
  && P "openssl verifies it over the message, against the token's public key" || F "openssl does not verify the signature"
printf 'another message\n' > "$W/other"
openssl dgst -sha256 -verify "$W/pub.pem" -signature "$W/sig.der" "$W/other" >/dev/null 2>&1 \
  && F "the signature verifies over ANOTHER message: the check proves nothing" || P "control: it does not verify over another message"
status="$(sign "$nonce" "${mtls[@]}")"
[ "$status" = 409 ] && P "the same nonce again is refused (409)" || F "a replayed nonce: HTTP $status"
status="$(sign "e2e-nonce-$(openssl rand -hex 12)")"
case "$status" in 401|403) P "a caller with no client certificate is refused ($status)";; *) F "no client certificate: HTTP $status";; esac
status="$(sign "e2e-nonce-$(openssl rand -hex 12)" "${mtls[@]}")"
[ "$status" = 200 ] && P "and the daemon still signs after the refusals (200)" || F "a second sign: HTTP $status: $(head -c 300 "$W/response")"

hdr "4  the hardening, measured on that process"
# shellcheck disable=SC2024  # the report is this user's, on purpose: only the probe is root
sudo env PYTHONPATH="$HERE" python3 - > "$W/probes" <<'PY'
from deploy.baremetal import os_probe
host = os_probe.Host()
for name in ("kms_service_unprivileged", "kms_service_sandboxed", "kms_capabilities_minimal", "kms_apparmor_enforced"):
    ok, why = os_probe.PROBES[name](host)
    print("%s\t%s\t%s" % (name, "true" if ok else "false", why))
PY
probe(){ awk -F'\t' -v n="$1" '$1==n{print $2 "\t" $3}' "$W/probes"; }
for name in kms_service_unprivileged kms_service_sandboxed kms_capabilities_minimal; do
  IFS=$'\t' read -r value why < <(probe "$name")
  [ "${value:-}" = true ] && P "$name: $why" || F "$name is ${value:-not measured}: ${why:-}"
done
nnp="$(awk '/^NoNewPrivs:/{print $2}' "/proc/$pid/status")"; seccomp="$(awk '/^Seccomp:/{print $2}' "/proc/$pid/status")"
[ "$nnp" = 1 ] && [ "$seccomp" = 2 ] && P "the kernel reports NoNewPrivs 1 and a seccomp filter (2) for pid $pid" || F "NoNewPrivs $nnp, Seccomp $seccomp"
[ "$(systemctl show "$SVC" -p MainPID --value)" = "$pid" ] && P "it is still the process that signed (pid $pid, no restart)" || F "the main pid changed during the test"

hdr "5  AppArmor: the profile's label, in complain mode"
label="$(sudo cat "/proc/$pid/attr/apparmor/current" 2>/dev/null || sudo cat "/proc/$pid/attr/current" 2>/dev/null)"
[ "$label" = "regalia-kms (complain)" ] && P "the process is labelled '$label'" || F "the process is labelled '${label:-nothing}'"
IFS=$'\t' read -r value why < <(probe kms_apparmor_enforced)
[ "${value:-}" = false ] && grep -q "in complain mode, not enforce" <<< "$why" \
  && P "kms_apparmor_enforced is false, for the right reason: $why" || F "kms_apparmor_enforced is ${value:-not measured}: ${why:-}"
# Information for the profile's author, not a verdict: what enforce mode would have refused in this run
# (SoftHSM's own files are expected here; the profile was written for OpenSC and pcscd).
echo "  what the profile would have refused (kernel log, apparmor=\"ALLOWED\"), by operation and name:"
sudo journalctl -k --no-pager 2>/dev/null | grep 'apparmor="ALLOWED"' | grep 'profile="regalia-kms"' \
  | sed -E 's/.*operation="([^"]*)".*name="([^"]*)".*/    \1 \2/; t; s/.*operation="([^"]*)".*/    \1/' | sort | uniq -c | head -40

echo; echo "kms-hardened-serve: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
