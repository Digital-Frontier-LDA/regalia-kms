#!/usr/bin/env bash
# kms-two-token-systemd.sh — the REAL regalia-kms binary (built with -tags piv), started by systemd from
# the SHIPPED unit and the SHIPPED hardening drop-in, serving a REAL SmartCard-HSM through OpenSC and a
# REAL YubiKey through PIV in one process (regalia#541, configuration 3).
#
# e2e/kms-hardened-serve.sh shows the unit with a SoftHSM token. This is the deployment shape itself:
# pcscd, opensc-pkcs11.so and the PIV backend's exclusive card access, under the unit's sandbox, as the
# unprivileged service user, with OPENSC_CONF=/etc/regalia-kms/opensc.conf as the unit sets it.
#
#   REGALIA_BENCH_HOST_OK=1 \
#   REGALIA_TWO_TOKEN_HSM_SERIAL=DENK0404144 REGALIA_TWO_TOKEN_HSM_PIN=… \
#   REGALIA_TWO_TOKEN_YK_SERIAL=35718625 REGALIA_TWO_TOKEN_YK_PIN=… \
#     e2e/kms-two-token-systemd.sh
#
# The PINs come from the environment only; they are never put on a command line.
#
# It INSTALLS on this machine, and removes at the end: the binary at /usr/local/sbin/regalia-kms, a
# regalia-kms system user, /etc/regalia-kms, /var/lib/regalia-kms, the unit and its drop-ins, and the
# polkit rule that lets that user reach pcscd. It is refused unless REGALIA_BENCH_HOST_OK=1 says the
# machine is a bench host that may carry that for a few minutes.
#
# ON THE TOKENS: one throwaway P-256 key pair is generated on the HSM (id e2, label below) and DELETED
# at the end, with a listing to show it is gone. The YubiKey is only read and signed with (slot 9c,
# which must hold a P-256 key with PIN policy once and touch policy never).
#
#   1  the service user cannot reach pcscd without the polkit rule: the daemon is not ready
#   2  with the shipped rule's grant: systemd starts the shipped unit; the daemon is ready, as regalia-kms
#   3  it signs through the HSM (PKCS#11, OpenSC) and through the YubiKey (PIV); openssl verifies both
#   4  the hardening and the OpenSC setting, measured on that process (os_probe)
#   5  without /etc/regalia-kms/opensc.conf the unit does not stay up, and the journal names the setting
#   6  the shipped polkit rule as it is (the KMS user and root only): the daemon still signs, another
#      user is refused by pcscd, and the host probe reads the rule (kms_pcscd_access_rule)
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
die(){ printf 'kms-two-token-systemd: %s\n' "$*" >&2; exit 2; }
if [ "${REGALIA_BENCH_HOST_OK:-}" != 1 ]; then
  echo "kms-two-token-systemd: refused: this installs a binary, a system user, a unit and a polkit rule on this machine,"
  echo "  starts the unit on its system manager, and generates (then deletes) a key on the HSM. REGALIA_BENCH_HOST_OK=1 on a bench host."
  exit 2
fi
export PATH="$PATH:/usr/sbin:/sbin"
HSM_SERIAL="${REGALIA_TWO_TOKEN_HSM_SERIAL:-}"; YK_SERIAL="${REGALIA_TWO_TOKEN_YK_SERIAL:-}"
[ -n "$HSM_SERIAL" ] && [ -n "$YK_SERIAL" ] || die "set REGALIA_TWO_TOKEN_HSM_SERIAL and REGALIA_TWO_TOKEN_YK_SERIAL"
[ -n "${REGALIA_TWO_TOKEN_HSM_PIN:-}" ] && [ -n "${REGALIA_TWO_TOKEN_YK_PIN:-}" ] || die "set REGALIA_TWO_TOKEN_HSM_PIN and REGALIA_TWO_TOKEN_YK_PIN (environment only)"
# The PINs stay in this shell: not exported, so no child (go, curl, the audit collector) inherits them.
# Each token tool that needs one is handed it as P_ for that one command.
HSM_PIN="$REGALIA_TWO_TOKEN_HSM_PIN"; YK_PIN="$REGALIA_TWO_TOKEN_YK_PIN"
export -n REGALIA_TWO_TOKEN_HSM_PIN REGALIA_TWO_TOKEN_YK_PIN; unset REGALIA_TWO_TOKEN_HSM_PIN REGALIA_TWO_TOKEN_YK_PIN
for t in go pkcs11-tool ykman openssl python3 curl systemctl pkcheck; do command -v "$t" >/dev/null || die "$t is required"; done
sudo -n true 2>/dev/null || die "needs sudo"
MODULE=""; for c in /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so; do [ -f "$c" ] && MODULE="$c" && break; done
[ -n "$MODULE" ] || die "opensc-pkcs11.so not found"
ETC=/etc/regalia-kms; STATE=/var/lib/regalia-kms; UNITDIR=/etc/systemd/system; SVC=regalia-kms.service
RULE=/etc/polkit-1/rules.d/50-regalia-kms-pcscd.rules
for existing in "$UNITDIR/$SVC" "$UNITDIR/$SVC.d" "$ETC" "$STATE" /usr/local/sbin/regalia-kms "$RULE"; do
  # asked as root: /etc/polkit-1/rules.d is not readable by an ordinary user
  { ! sudo test -e "$existing" && ! sudo test -L "$existing"; } || die "this machine already has $existing: somebody's installation, and the cleanup would delete it"
done
echo "kms-two-token-systemd: $(systemctl --version | head -1), kernel $(uname -r), pcscd $(dpkg-query -W -f='${Version}' pcscd 2>/dev/null || echo '?'), OpenSC $(dpkg-query -W -f='${Version}' opensc-pkcs11 2>/dev/null || echo '?'), AppArmor $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"

PORT=18443; SINK=18444; SITE=bench-site; HSM_DEVICE=hsm-bench; YK_DEVICE=yubikey-bench
HSM_OBJECT=two-token-hsm-key; YK_OBJECT=two-token-piv-key; PRINCIPAL=spiffe://regalia/workload/e2e
KEY_ID=e2; KEY_LABEL=regalia-two-token-e2e
IGNORE="$HERE/deploy/opensc/ignore-yubikey.conf"; SHIPPED_RULE="$HERE/deploy/polkit/50-regalia-kms-pcscd.rules"
W="$(mktemp -d)"; collector=""; made_user=0; made_key=0
# This user's own token tools run with OpenSC told to leave the YubiKey alone, as the daemon's does.
# By slot, found by serial: SmartCard-HSMs often share a label, and --token-label takes the first match.
hsm(){ OPENSC_CONF="$IGNORE" pkcs11-tool --module "$MODULE" --slot "$HSM_SLOT" "$@"; }
delete_key(){
  [ "$made_key" = 1 ] || return 0
  P_="$HSM_PIN" hsm --login --pin env:P_ --delete-object --type privkey --id "$KEY_ID" >/dev/null 2>&1
  P_="$HSM_PIN" hsm --login --pin env:P_ --delete-object --type pubkey --id "$KEY_ID" >/dev/null 2>&1
  # "None left" counts only from a listing that worked: the login succeeded (pkcs11-tool exits non-zero
  # otherwise) and nothing in it is an error.
  if listing="$(P_="$HSM_PIN" hsm --login --pin env:P_ --list-objects 2>&1)" && ! grep -qi "error\|CKR_" <<< "$listing"; then
    if ! grep -q "ID:[[:space:]]*$KEY_ID\$" <<< "$listing" && ! grep -q "$KEY_LABEL" <<< "$listing"; then
      echo "kms-two-token-systemd: the throwaway HSM key $KEY_LABEL (id $KEY_ID) is deleted; a listing that read the token shows none left"; made_key=0; return 0
    fi
  fi
  echo "kms-two-token-systemd: WARNING: cannot show that the throwaway key $KEY_LABEL (id $KEY_ID) is gone from $HSM_SERIAL: check and delete it by hand" >&2
}
cleanup(){
  sudo systemctl stop "$SVC" 2>/dev/null
  [ -n "$collector" ] && kill "$collector" 2>/dev/null
  sudo rm -f "$RULE"; sleep 2      # polkit rereads its rules; this user's own token calls below need pcscd again
  sudo sh -c 'for f in "$1"/*.pin; do [ -f "$f" ] && shred -u "$f"; done' sh "$ETC" 2>/dev/null
  sudo rm -rf "$UNITDIR/$SVC" "$UNITDIR/$SVC.d" "$ETC" "$STATE" /usr/local/sbin/regalia-kms
  sudo systemctl daemon-reload 2>/dev/null
  sudo systemctl reset-failed "$SVC" 2>/dev/null
  [ "$made_user" = 1 ] && sudo userdel regalia-kms 2>/dev/null
  delete_key
  rm -rf "$W"
}
trap cleanup EXIT

# ---- the tokens, as this user sees them ----------------------------------------------------------------
HSM_SLOT="$(OPENSC_CONF="$IGNORE" pkcs11-tool --module "$MODULE" --list-token-slots 2>/dev/null | awk -v s="$HSM_SERIAL" '
  /^Slot [0-9]+ \(0x[0-9a-f]+\)/{slot=$3; gsub(/[():]/, "", slot)} /serial num/{v=$0; sub(/.*: */, "", v); gsub(/[ \t]/, "", v); if (v==s) {print slot; exit}}')"
[ -n "$HSM_SLOT" ] || die "no PKCS#11 token with serial $HSM_SERIAL is attached"
HSM_LABEL="$(hsm --list-token-slots 2>/dev/null | awk -v s="$HSM_SLOT" '/^Slot /{on=(index($0, "(" s ")")>0)} on && /token label/{v=$0; sub(/.*: */, "", v); print v; exit}')"
# A PIN is presented only to a token that can afford a wrong one.
flags="$(hsm --list-token-slots 2>/dev/null | awk -v s="$HSM_SLOT" '/^Slot /{on=(index($0, "(" s ")")>0)} on && /token flags/{print; exit}')"
# Fails closed: a flags line must be found, say the PIN is initialised, and say nothing of a low count.
grep -q "PIN initialized" <<< "$flags" || die "the HSM's token flags could not be read ('$flags'): not presenting a PIN to it"
grep -qi "count low\|final try\|locked" <<< "$flags" && die "the HSM's user PIN counter is not full ($flags): not presenting a PIN to it"
case "$(ykman --device "$YK_SERIAL" piv info 2>/dev/null | awk -F: '/PIN tries/{gsub(/ /, "", $2); print $2}')" in
  3/3) ;; *) die "the YubiKey's PIV PIN counter is not 3/3: not presenting a PIN to it";; esac
ykman --device "$YK_SERIAL" piv info >/dev/null 2>&1 || die "no YubiKey with serial $YK_SERIAL is attached"
echo "kms-two-token-systemd: HSM $HSM_SERIAL (slot $HSM_SLOT, label ${HSM_LABEL:-?}), YubiKey $YK_SERIAL; PIV PIN $(ykman --device "$YK_SERIAL" piv info 2>/dev/null | awk -F: '/PIN tries/{gsub(/ /, "", $2); print $2}')"
# ONE login before anything is created: it proves the PIN (a wrong one costs one try, and the script
# stops before the cleanup could spend more on deleting a key that was never made), and it lists the
# private objects too, so a key already holding the id is seen and never deleted by mistake.
existing="$(P_="$HSM_PIN" hsm --login --pin env:P_ --list-objects 2>&1)" \
  || die "the logged-in listing failed (a refused PIN spends one try; pcscd or the token may also have refused): nothing was created"
grep -q "$KEY_LABEL" <<< "$existing" || grep -q "ID:[[:space:]]*$KEY_ID\$" <<< "$existing" \
  && die "an object with label $KEY_LABEL or id $KEY_ID is already on the HSM (an earlier run?): delete it by hand first"
made_key=1   # the PIN is good and the id is free: from here on the cleanup looks for the key, whatever happens
P_="$HSM_PIN" hsm --login --pin env:P_ --keypairgen --key-type EC:prime256v1 --usage-sign --label "$KEY_LABEL" --id "$KEY_ID" >/dev/null 2>&1 \
  || die "cannot generate the throwaway P-256 key on the HSM (is the PIN the token's?)"
hsm --read-object --type pubkey --id "$KEY_ID" --output-file "$W/hsm.der" >/dev/null 2>&1 || die "cannot read the HSM key's public half"
openssl pkey -pubin -inform DER -in "$W/hsm.der" -out "$W/hsm.pem" 2>/dev/null || die "the HSM's public key is not a SubjectPublicKeyInfo"
ykman --device "$YK_SERIAL" piv keys export 9c "$W/yk.pem" >/dev/null 2>&1 || die "cannot read the public key of PIV slot 9c"
openssl pkey -pubin -in "$W/yk.pem" -outform DER -out "$W/yk.der" 2>/dev/null || die "PIV slot 9c does not hold a readable public key"
HSM_KEYPIN="sha256:$(sha256sum "$W/hsm.der" | cut -d' ' -f1)"; YK_KEYPIN="sha256:$(sha256sum "$W/yk.der" | cut -d' ' -f1)"

# ---- build and install ----------------------------------------------------------------------------------
go -C "$HERE" build -tags piv -o "$W/regalia-kms" ./cmd/regalia-kms || die "cannot build regalia-kms with -tags piv"
go -C "$HERE" build -o "$W/regalia-audit-collector" ./cmd/regalia-audit-collector || die "cannot build the audit collector"
sudo install -m 0755 "$W/regalia-kms" /usr/local/sbin/regalia-kms || die "cannot install the binary"
if ! id regalia-kms >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin regalia-kms || die "cannot create the regalia-kms user"; made_user=1
fi
sudo install -d -m 0750 -o root -g regalia-kms "$ETC" || die "cannot create $ETC"
sudo install -d -m 0700 -o regalia-kms -g regalia-kms "$STATE" || die "cannot create $STATE"
# The OpenSC configuration the shipped unit names, from the shipped file.
sudo install -m 0644 -o root -g root "$IGNORE" "$ETC/opensc.conf" || die "cannot install opensc.conf"

# ---- PKI ---------------------------------------------------------------------------------------------------
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

# ---- the daemon's configuration: BOTH backends -----------------------------------------------------------
NOW="$(date -u +%FT%TZ)"; TOMORROW="$(date -u -d '+1 day' +%FT%TZ)"
cat > "$W/secure-channel.json" <<JSON
{"schema_version": 1, "devices": [{"device_serial": "$HSM_SERIAL", "verified_by": "bench", "verified_at": "$NOW",
  "expires_at": "$TOMORROW", "firmware": "bench", "secure_messaging_established": true}]}
JSON
object(){ # id, name, binding json
  cat <<JSON
{"id": "$1", "name": "$2", "kind": "asymmetric-key", "classification": "restricted",
  "environment": "staging", "owner": "security", "purpose": "e2e-signing", "custody": "direct-hardware",
  "algorithm": "p256", "operations": ["sign"], "policy_id": "$1-policy",
  "bindings": [$3],
  "recovery": {"mode": "shamir-4-of-6", "authority_id": "e2e", "minimum_replicas": 2, "status": "tested"},
  "rotation": {"maximum_age_days": 90, "last_rotated": null},
  "migration": {"status": "migrated", "source": "e2e"},
  "verification": {"status": "verified", "last_verified": "${NOW%%T*}", "evidence": "e2e"}}
JSON
}
hsm_binding="{\"site\": \"$SITE\", \"backend\": \"nitrokey-pkcs11\", \"device_id\": \"$HSM_DEVICE\", \"device_serial\": \"$HSM_SERIAL\", \"object_id\": \"$KEY_ID\", \"public_key_sha256\": \"$HSM_KEYPIN\", \"public_fingerprint\": \"$HSM_KEYPIN\", \"state\": \"active\"}"
yk_binding="{\"site\": \"$SITE\", \"backend\": \"yubikey-piv\", \"device_id\": \"$YK_DEVICE\", \"device_serial\": \"$YK_SERIAL\", \"object_id\": \"9c\", \"public_fingerprint\": \"$YK_KEYPIN\", \"state\": \"active\", \"pin_policy\": \"once\", \"touch_policy\": \"never\"}"
{ printf '{"schema_version": 1, "manifest_id": "two-token-e2e", "generated_at": "%s", "objects": [' "$NOW"
  object "$HSM_OBJECT" "Bench P-256 key on the HSM" "$hsm_binding"; printf ','
  object "$YK_OBJECT" "Bench P-256 key on the YubiKey" "$yk_binding"; printf ']}\n'; } > "$W/manifest.json"
policy(){ printf '{"id": "%s-policy", "object_id": "%s", "purpose": "e2e-signing", "environment": "staging", "operation": "sign", "algorithm": "p256", "content_types": ["application/vnd.regalia.digest"], "max_payload_bytes": 32, "max_future_seconds": 300, "required_approvals": 0, "approvers": ["spiffe://regalia/approver/e2e"]}' "$1" "$1"; }
printf '{"schema_version": 1, "policies": [%s, %s]}\n' "$(policy "$HSM_OBJECT")" "$(policy "$YK_OBJECT")" > "$W/policy.json"
cat > "$W/rbac.json" <<JSON
{"schema_version": 1, "principals": [{"uri": "$PRINCIPAL", "grants": [
  {"objects": ["$HSM_OBJECT", "$YK_OBJECT"], "operations": ["sign"], "environments": ["staging"]}]}]}
JSON
cat > "$W/config.json" <<JSON
{"listen_address": "127.0.0.1:$PORT", "site": "$SITE",
 "registry_path": "$ETC/manifest.json", "rbac_policy_path": "$ETC/rbac.json",
 "policy_path": "$ETC/policy.json", "policy_state_path": "$STATE/policy-state.jsonl",
 "tls_certificate_path": "$ETC/server.pem", "tls_private_key_path": "$ETC/server.key", "tls_client_ca_path": "$ETC/ca.pem",
 "pkcs11_module_path": "$MODULE", "secure_channel_evidence_path": "$ETC/secure-channel.json",
 "yubikey_devices": {"$YK_DEVICE": "$YK_SERIAL"},
 "pin_paths": {"$HSM_DEVICE": "/run/credentials/$SVC/$HSM_DEVICE.pin", "$YK_DEVICE": "/run/credentials/$SVC/$YK_DEVICE.pin"},
 "audit_journal_path": "$STATE/audit.jsonl", "audit_sink_url": "https://127.0.0.1:$SINK",
 "runtime_admission": "disabled-for-lab"}
JSON
for f in config.json manifest.json policy.json rbac.json secure-channel.json server.pem server.key ca.pem; do
  sudo install -m 0640 -o root -g regalia-kms "$W/$f" "$ETC/$f" || die "cannot install $f"; done
# The PINs: root's alone on disk, exactly the PIN and no newline; systemd hands them over as credentials.
( umask 077; printf '%s' "$HSM_PIN" > "$W/hsm.pin"; printf '%s' "$YK_PIN" > "$W/yk.pin" )
sudo install -m 0600 -o root -g root "$W/hsm.pin" "$ETC/$HSM_DEVICE.pin"; sudo install -m 0600 -o root -g root "$W/yk.pin" "$ETC/$YK_DEVICE.pin"; rm -f "$W/hsm.pin" "$W/yk.pin"

# ---- the unit: the shipped file, the shipped drop-in, and the test's three lines --------------------------
sudo install -m 0644 "$HERE/deploy/systemd/regalia-kms.service" "$UNITDIR/$SVC"
sudo install -d -m 0755 "$UNITDIR/$SVC.d"
sudo install -m 0644 "$HERE/deploy/baremetal/regalia-kms-hardening.conf.example" "$UNITDIR/$SVC.d/hardening.conf"
printf '[Service]\nLoadCredential=%s.pin:%s\nLoadCredential=%s.pin:%s\nLimitMEMLOCK=1M\n' \
  "$HSM_DEVICE" "$ETC/$HSM_DEVICE.pin" "$YK_DEVICE" "$ETC/$YK_DEVICE.pin" > "$W/zz-e2e.conf"
sudo install -m 0644 "$W/zz-e2e.conf" "$UNITDIR/$SVC.d/zz-e2e.conf"
sudo systemctl daemon-reload

mkdir -m 0700 "$W/collector-state"
"$W/regalia-audit-collector" -state "$W/collector-state" -listen "127.0.0.1:$SINK" -tls-cert "$W/collector.pem" \
  -tls-key "$W/collector.key" -client-ca "$W/ca.pem" > "$W/collector.log" 2>&1 &
collector=$!
sleep 2; kill -0 "$collector" 2>/dev/null || die "the audit collector did not start: $(tail -5 "$W/collector.log")"

journal(){ sudo journalctl -u "$SVC" --no-pager -n "${1:-25}" --since "$STARTED" 2>/dev/null | cut -c1-420; }
ready(){ curl -s -o /dev/null -w '%{http_code}' --cacert "$W/ca.pem" "https://127.0.0.1:$PORT/v1/health/ready" 2>/dev/null; }
wait_ready(){ local code=""; for _ in $(seq 1 "${1:-60}"); do code="$(ready)"; [ "$code" = 200 ] && break; systemctl is-active --quiet "$SVC" || break; sleep 1; done; echo "$code"; }
printf 'regalia-kms two-token e2e %s\n' "$NOW" > "$W/message"; printf 'another message\n' > "$W/other"
# sign <object> <nonce>: POST the SHA-256 digest of the message; the HTTP status to stdout, the body to $W/response.
sign(){
  python3 -I - "$W/message" "$2" "$1" > "$W/request.json" <<'PY'
import base64, datetime, hashlib, json, sys
digest = hashlib.sha256(open(sys.argv[1], "rb").read()).digest()
expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump({"object_id": sys.argv[3], "context": {"environment": "staging", "purpose": "e2e-signing", "expires_at": expires, "nonce": sys.argv[2]},
           "content_type": "application/vnd.regalia.digest", "payload_base64": base64.b64encode(digest).decode()}, sys.stdout)
PY
  curl -s -o "$W/response" -w '%{http_code}' --cacert "$W/ca.pem" --cert "$W/client.pem" --key "$W/client.key" -H 'Content-Type: application/json' \
    -H "X-Request-ID: $(cat /proc/sys/kernel/random/uuid)" -H "Idempotency-Key: $2" \
    --data-binary "@$W/request.json" "https://127.0.0.1:$PORT/v1/operations/sign"; }
# verified <public key pem>: the response is a 64-byte r||s that openssl verifies over the message and not over another.
verified(){
  python3 -I - "$W/response" "$W/sig.der" <<'PY' || return 1
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
  openssl dgst -sha256 -verify "$1" -signature "$W/sig.der" "$W/message" >/dev/null 2>&1 || return 1
  ! openssl dgst -sha256 -verify "$1" -signature "$W/sig.der" "$W/other" >/dev/null 2>&1; }
sign_both(){ # label
  local status
  status="$(sign "$HSM_OBJECT" "e2e-nonce-$(openssl rand -hex 12)")"
  [ "$status" = 200 ] && verified "$W/hsm.pem" && P "$1: a signature through the HSM (PKCS#11, OpenSC), verified by openssl against the HSM key" \
    || { F "$1: sign through the HSM: HTTP $status: $(head -c 300 "$W/response")"; journal 12; }
  status="$(sign "$YK_OBJECT" "e2e-nonce-$(openssl rand -hex 12)")"
  [ "$status" = 200 ] && verified "$W/yk.pem" && P "$1: a signature through the YubiKey (PIV slot 9c), verified by openssl against the slot's key" \
    || { F "$1: sign through the YubiKey: HTTP $status: $(head -c 300 "$W/response")"; journal 12; }
}

hdr "1  without a polkit rule, the service user cannot reach pcscd"
STARTED="$(date '+%F %T')"
sudo systemctl start "$SVC"; code="$(wait_ready 25)"
status="$(sign "$HSM_OBJECT" "e2e-nonce-$(openssl rand -hex 12)")"; status_yk="$(sign "$YK_OBJECT" "e2e-nonce-$(openssl rand -hex 12)")"
refused="$(sudo journalctl -u pcscd --no-pager --since "$STARTED" 2>/dev/null | grep -c "user: $(id -u regalia-kms)) is NOT authorized")"
if [ "$status" != 200 ] && [ "$status_yk" != 200 ] && [ "$refused" -ge 1 ]; then
  P "no key is served (ready: HTTP ${code:-none}; sign HSM $status, YubiKey $status_yk), and pcscd logged that polkit did not authorize regalia-kms ($refused time(s))"
else
  F "with no polkit rule: HSM $status, YubiKey $status_yk, pcscd refusals of regalia-kms logged: $refused (both must be refused, and pcscd must say why)"
fi
echo "  what the daemon said:"; journal 8 | sed 's/^/    /'
sudo systemctl stop "$SVC"

hdr "2  with the shipped rule's grant, systemd starts the shipped unit"
[ -f "$SHIPPED_RULE" ] || die "the shipped polkit rule $SHIPPED_RULE is missing"
# The shipped rule also REFUSES every other user. On a bench that would cut this user's own tools off
# pcscd, so the grant alone is installed here; the rule as shipped is step 6.
sed 's/^    var ONLY_THE_KMS = true;$/    var ONLY_THE_KMS = false;/' "$SHIPPED_RULE" > "$W/grant.rules"
cmp -s "$SHIPPED_RULE" "$W/grant.rules" && die "the shipped rule has no '    var ONLY_THE_KMS = true;' line to switch"
sudo install -m 0644 -o root -g root "$W/grant.rules" "$RULE"; sleep 2
STARTED="$(date '+%F %T')"
sudo systemctl start "$SVC"; rc=$?
[ "$rc" = 0 ] && P "systemctl start $SVC" || { F "systemctl start failed (exit $rc)"; journal; }
code="$(wait_ready 60)"
[ "$code" = 200 ] && P "the daemon is ready (GET /v1/health/ready: 200)" || { F "not ready (HTTP ${code:-none}; unit $(systemctl is-active "$SVC"))"; journal; }
pid="$(systemctl show "$SVC" -p MainPID --value)"
exe="$(sudo readlink "/proc/$pid/exe" 2>/dev/null)"; uid="$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
[ "$exe" = /usr/local/sbin/regalia-kms ] && [ "$uid" = "$(id -u regalia-kms)" ] && [ "$uid" != 0 ] \
  && P "the main process (pid $pid) is the installed binary, running as regalia-kms (uid $uid)" || F "pid $pid runs '$exe' as uid '$uid'"
grep -q hardening.conf <<< "$(systemctl show "$SVC" -p DropInPaths --value)" && P "the shipped hardening drop-in is in effect" || F "the hardening drop-in is not in effect"
conf="$(sudo cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | sed -n 's/^OPENSC_CONF=//p')"
[ "$conf" = "$ETC/opensc.conf" ] && P "the process runs with OPENSC_CONF=$conf, from the shipped unit" || F "OPENSC_CONF in the process is '${conf:-unset}'"

hdr "3  it signs through both tokens"
sign_both "first"
sign_both "again"
# A signature through the YubiKey that failed may have been a refused PIN. Every later step starts the
# daemon again, which presents the PIN again: stop here rather than spend the card's counter.
if [ "$fail" -gt 0 ]; then
  echo "kms-two-token-systemd: stopping after step 3: a signature failed, and the later steps would present the PINs again" >&2
  echo; echo "kms-two-token-systemd: $pass passed, $fail failed"; exit 1
fi
[ "$(systemctl show "$SVC" -p MainPID --value)" = "$pid" ] && P "it is still the process that started (pid $pid, no restart)" || F "the main pid changed"

hdr "4  the hardening and the OpenSC setting, measured on that process"
# shellcheck disable=SC2024  # the report is this user's, on purpose: only the probe is root
sudo env PYTHONPATH="$HERE" python3 -Ps - > "$W/probes" <<'PY'
from deploy.baremetal import os_probe
host = os_probe.Host()
for name in ("kms_service_unprivileged", "kms_service_sandboxed", "kms_capabilities_minimal", "kms_opensc_leaves_piv_cards", "kms_apparmor_enforced"):
    ok, why = os_probe.PROBES[name](host)
    print("%s\t%s\t%s" % (name, "true" if ok else "false", why))
ok, why = os_probe.pcscd_clients(host)
print("pcscd_clients\t%s\t%s" % ("true" if ok else "false", why))
PY
probe(){ awk -F'\t' -v n="$1" '$1==n{print $2 "\t" $3}' "$W/probes"; }
for name in kms_service_unprivileged kms_service_sandboxed kms_capabilities_minimal kms_opensc_leaves_piv_cards; do
  IFS=$'\t' read -r value why < <(probe "$name")
  [ "${value:-}" = true ] && P "$name: $why" || F "$name is ${value:-not measured}: ${why:-}"
done
nnp="$(awk '/^NoNewPrivs:/{print $2}' "/proc/$pid/status")"; seccomp="$(awk '/^Seccomp:/{print $2}' "/proc/$pid/status")"
[ "$nnp" = 1 ] && [ "$seccomp" = 2 ] && P "the kernel reports NoNewPrivs 1 and a seccomp filter (2) for pid $pid" || F "NoNewPrivs $nnp, Seccomp $seccomp"
IFS=$'\t' read -r value why < <(probe pcscd_clients)
[ "${value:-}" = true ] && P "pcscd's clients: $why" || F "pcscd's clients: ${value:-not measured}: ${why:-}"
IFS=$'\t' read -r value why < <(probe kms_apparmor_enforced)
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then
  [ "${value:-}" = true ] && P "kms_apparmor_enforced: $why" || F "kms_apparmor_enforced is ${value:-not measured}: ${why:-}"
else
  [ "${value:-}" = false ] && P "kms_apparmor_enforced is false, as it must be here: AppArmor is not enabled in this kernel ($why). THE PROFILE IS NOT TESTED BY THIS RUN" \
    || F "kms_apparmor_enforced is ${value:-not measured} on a kernel without AppArmor: ${why:-}"
fi

hdr "5  without the OpenSC configuration the unit does not stay up, and says why"
sudo systemctl stop "$SVC"
sudo mv "$ETC/opensc.conf" "$ETC/opensc.conf.aside"
STARTED="$(date '+%F %T')"
sudo systemctl start "$SVC" 2>/dev/null
# The refusal comes once the module has looked at the readers and the PIV cards were tried: seconds, not at once.
said=0
for _ in $(seq 1 45); do
  said="$(sudo journalctl -u "$SVC" --no-pager --since "$STARTED" 2>/dev/null | grep 'KMS stopped' | grep 'ignored_readers' | grep -c 'deploy/opensc/ignore-yubikey.conf')"
  [ "$said" -ge 1 ] && break; sleep 1
done
code="$(ready)"; result="$(systemctl show "$SVC" -p Result --value)"
[ "$code" != 200 ] && [ "$said" -ge 1 ] && [ "$result" = exit-code ] && P "the daemon stopped itself (unit result: $result; ready: HTTP ${code:-none}), and the journal names ignored_readers and the shipped file" \
  || { F "with no opensc.conf: ready HTTP ${code:-none}, $said journal line(s) naming the setting"; journal 10; }
sudo systemctl stop "$SVC" 2>/dev/null; sudo systemctl reset-failed "$SVC" 2>/dev/null
sudo mv "$ETC/opensc.conf.aside" "$ETC/opensc.conf"

hdr "6  the polkit rule as shipped: the KMS user and root only"
sudo install -m 0644 -o root -g root "$SHIPPED_RULE" "$RULE"; sleep 2
STARTED="$(date '+%F %T')"
sudo systemctl start "$SVC"; code="$(wait_ready 60)"
[ "$code" = 200 ] && P "the daemon is ready under the shipped rule" || { F "not ready under the shipped rule (HTTP ${code:-none})"; journal; }
sign_both "under the shipped rule"
# Another user, in a transient unit, against the KMS user in the same kind of unit as the positive
# control: same tool, same pcscd, only the user differs. What this does NOT show is the rule's own NO:
# a user with no session is refused by Debian's default policy as well. The refusal of a user WITH an
# active console session is not measured on this bench (see below).
seen_as(){ sudo systemd-run --quiet --wait --pipe --collect -p User="$1" -E OPENSC_CONF="$IGNORE" \
  pkcs11-tool --module "$MODULE" --list-token-slots 2>/dev/null | grep -c "$HSM_SERIAL"; }
kms_sees="$(seen_as regalia-kms)"; nobody_sees="$(seen_as nobody)"
[ "$kms_sees" -ge 1 ] && [ "$nobody_sees" = 0 ] \
  && P "regalia-kms in a unit of its own sees the HSM, and nobody in the same kind of unit does not" \
  || F "positive control and refusal: regalia-kms sees the HSM $kms_sees time(s), nobody $nobody_sees"
mine="$(OPENSC_CONF="$IGNORE" pkcs11-tool --module "$MODULE" --list-token-slots 2>/dev/null | grep -c "$HSM_SERIAL")"
if id -nG | tr ' ' '\n' | grep -qx qubes; then
  echo "  (this user, $(id -un), is in the qubes group, which a Qubes polkit rule allows everything: it sees $mine line(s) for the HSM, and that says nothing about the shipped rule)"
else
  [ "$mine" = 0 ] && P "this user ($(id -un)), with an active session, is refused too" || F "this user ($(id -un)) still sees the HSM under the shipped rule ($mine)"
fi
# The host probe's reading of the rule, on this machine as it is.
IFS=$'\t' read -r value why < <(sudo env PYTHONPATH="$HERE" python3 -Ps -c '
from deploy.baremetal import os_probe
ok, why = os_probe.PROBES["kms_pcscd_access_rule"](os_probe.Host())
print("%s\t%s" % ("true" if ok else "false", why))')
if sudo sh -c 'ls /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/ 2>/dev/null' | grep -q qubes; then
  [ "${value:-}" = false ] && grep -q "00-qubes-allow-all.rules is a polkit rules file this host is not known to need" <<< "$why" \
    && P "kms_pcscd_access_rule is false here, for the right reason: $why" || F "kms_pcscd_access_rule is ${value:-not measured} beside Qubes' allow-everything rule: ${why:-}"
else
  [ "${value:-}" = true ] && P "kms_pcscd_access_rule: $why" || F "kms_pcscd_access_rule is ${value:-not measured}: ${why:-}"
fi
sudo systemctl stop "$SVC"
# no rule at all again, so that the cleanup's own token calls (deleting the key) are not refused
sudo rm -f "$RULE"; sleep 2

echo; echo "kms-two-token-systemd: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
