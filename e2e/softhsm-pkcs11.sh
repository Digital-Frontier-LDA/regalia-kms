#!/usr/bin/env bash
# Provision an ephemeral software token and exercise the concrete PKCS#11
# driver/provider. All state is confined to a newly-created temporary directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The ceremony qualification script lives in regalia-ceremony; point REGALIA_CEREMONY_DIR at a
# checkout to cross-check it against this SoftHSM token.
CEREMONY="${REGALIA_CEREMONY_DIR:-}"
STATE="$(mktemp -d)"
cleanup(){ rm -rf -- "$STATE"; }
trap cleanup EXIT HUP INT TERM
mkdir "$STATE/tokens"
chmod 0700 "$STATE" "$STATE/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$STATE/tokens" > "$STATE/softhsm2.conf"
export SOFTHSM2_CONF="$STATE/softhsm2.conf"

MODULE="${REGALIA_PKCS11_E2E_MODULE:-}"
if [ -z "$MODULE" ]; then
  for candidate in \
    /opt/homebrew/lib/softhsm/libsofthsm2.so \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
    [ -f "$candidate" ] && { MODULE="$candidate"; break; }
  done
fi
[ -f "$MODULE" ] || { echo "SoftHSM2 module not found" >&2; exit 2; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util not found" >&2; exit 2; }
command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool not found" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 2; }

# Credentials are deliberately generated per run. They are never printed or exported outside
# this process, so a test log cannot be mistaken for a reusable token credential.
SO_PIN="$(openssl rand -hex 16)"
E2E_PIN="$(openssl rand -hex 16)"
softhsm2-util --init-token --free --label regalia-kms-e2e --so-pin "$SO_PIN" --pin "$E2E_PIN" >/dev/null
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --keypairgen --key-type EC:secp256k1 \
  --usage-sign --label regalia-kms-e2e --id 01 >/dev/null
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --keypairgen --key-type rsa:2048 \
  --usage-sign --usage-decrypt --label regalia-kms-wrap-e2e --id 02 >/dev/null
# A DELIBERATELY NON-HARDWARE-ROOTED KEK, so the guard that refuses one has something to refuse.
# Generated with openssl on this host and imported, which is exactly the shape #6 forbids: the
# private half existed in a file. Both halves are written, because a wrap needs the public object
# and importing only the private one makes the wrap fail for the wrong reason -- an absent public
# key, not an untrustworthy private one.
openssl genrsa -out "$STATE/imported.pem" 2048 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$STATE/imported.pem" -outform DER -out "$STATE/imported.der"
openssl rsa -in "$STATE/imported.pem" -pubout -outform DER -out "$STATE/imported.pub.der" 2>/dev/null
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --write-object "$STATE/imported.der" --type privkey \
  --usage-decrypt --extractable --label regalia-kms-imported-e2e --id 07 >/dev/null
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --write-object "$STATE/imported.pub.der" --type pubkey \
  --label regalia-kms-imported-e2e --id 07 >/dev/null

# A p256 key, because key-agreement is advertised for p256/p384 and the secp256k1 key above is
# sign-only. Without it the concrete driver's ECDH path is exercised by nothing: the existing
# key-agreement tests all run against fakes, and Derive sat at 0% on a real module.
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --keypairgen --key-type EC:prime256v1 \
  --usage-derive --label regalia-kms-ecdh-e2e --id 03 >/dev/null

# An AES-256 KEK. A symmetric KEK is a single CKO_SECRET_KEY object with no public or private half,
# which is the shape the provenance guards were blind to until they learned to dispatch on class.
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --keygen --key-type AES:32 --sensitive \
  --label regalia-kms-aes-e2e --id 09 >/dev/null
# And one WITHOUT --sensitive. SoftHSM reports it as "never extractable", and C_GetAttributeValue
# still returns its plaintext value -- "cannot be wrapped out" is not "cannot be read". It is the
# negative fixture for the CKA_SENSITIVE half of the guard.
REGALIA_E2E_PIN="$E2E_PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e \
  --login --pin env:REGALIA_E2E_PIN --keygen --key-type AES:32 \
  --label regalia-kms-aes-readable-e2e --id 0a >/dev/null

slots="$(pkcs11-tool --module "$MODULE" --token-label regalia-kms-e2e --list-slots 2>/dev/null)"
serial="$(printf '%s\n' "$slots" | awk -F: '/serial num/{gsub(/[[:space:]]/, "", $2); print $2; exit}')"
[ -n "$serial" ] || { echo "SoftHSM2 serial unavailable" >&2; exit 1; }

REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" \
  go -C "$ROOT" test -count=1 -run '^TestConcretePKCS11DriverAgainstSoftHSM$|^TestAES256UnwrapRoundTripsAgainstSoftHSM$' ./internal/backend/nitrokey

# The Nitrokey HSM 2 qualification instrument, run here in CONTROL mode against this SoftHSM token so
# it is exercised in CI, not only when a real token is attached: a generated key (id 01) must read
# LOCAL, an imported key (id 07) must be refused, and there is no device certificate. Pointed at a
# Nitrokey (REGALIA_QUAL_*), the same test records the #447/#448 answers instead of asserting them.
REGALIA_QUAL_MODULE="$MODULE" REGALIA_QUAL_SERIAL="$serial" \
  REGALIA_QUAL_GENERATED_ID=01 REGALIA_QUAL_IMPORTED_ID=07 REGALIA_QUAL_CONTROL=1 \
  go -C "$ROOT" test -count=1 -run '^TestNitrokeyHSM2Qualification$' ./internal/backend/nitrokey

# The no-Go Qubes qualification (qubes/scripts/nitrokey-qualify.sh in regalia-ceremony, run in the
# vault-tools AppVM with only OpenSC) is cross-checked here against the same SoftHSM token: read-only,
# it must see no device certificate and report the generated key (id 01) as CKA_LOCAL=true, the
# imported key (id 07) not. That script lives in the other repository, so this arm runs only when
# REGALIA_CEREMONY_DIR points at a checkout, and says so loudly when it does not rather than leaving
# a reader to assume the cross-check ran.
if [ -n "$CEREMONY" ] && [ -x "$CEREMONY/qubes/scripts/nitrokey-qualify.sh" ]; then
  qual_out="$("$CEREMONY/qubes/scripts/nitrokey-qualify.sh" --module "$MODULE" --serial "$serial" 2>&1)"
  printf '%s\n' "$qual_out"
  # Assert CKA_LOCAL DISCRIMINATES on this token: at least one generated key reads local and at least
  # one (the imported id 07) does not. Exact counts vary with the token's key set, so parse rather than
  # pin a number.
  qual_line="$(grep -oE '#447 public keys: [0-9]+ total, [0-9]+ report' <<< "$qual_out")"
  qual_total="$(sed -E 's/.*keys: ([0-9]+) total.*/\1/' <<< "$qual_line")"
  qual_local="$(sed -E 's/.*total, ([0-9]+) report.*/\1/' <<< "$qual_line")"
  { [ "${qual_local:-0}" -ge 1 ] && [ "${qual_local:-0}" -lt "${qual_total:-0}" ]; } \
    || { echo "nitrokey-qualify.sh CKA_LOCAL did not discriminate (local=$qual_local total=$qual_total); a generated key must read local and the imported one must not" >&2; exit 1; }
  grep -q '#448 device certificate: none exposed' <<< "$qual_out" \
    || { echo "nitrokey-qualify.sh did not report the absent device certificate" >&2; exit 1; }
else
  echo ">> SKIPPING the nitrokey-qualify.sh cross-check: set REGALIA_CEREMONY_DIR to a regalia-ceremony checkout to run it" >&2
fi

REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" \
  go -C "$ROOT" test -count=1 -run '^TestHTTPToCoordinatorToConcretePKCS11$' ./internal/integration
REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" REGALIA_PKCS11_E2E_TOKEN_LABEL=regalia-kms-e2e \
  go -C "$ROOT" test -count=1 -run '^TestCosmosPolicyToConcretePKCS11$' ./internal/integration
REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" \
  go -C "$ROOT" test -count=1 -run '^TestSOPSCLIThroughMTLSPolicyAuditAndConcretePKCS11$' ./internal/integration
REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" \
  go -C "$ROOT" test -count=1 -run '^TestDeployedSOPSSidecarExecutableThroughMTLS$' ./internal/integration
REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" \
  go -C "$ROOT" test -count=1 -run '^TestSealOnConcretePKCS11ThenReleaseFromIt$' ./internal/integration
# ADR-0002 D1 through the PRODUCTION driver constructor and the real probes: SoftHSM exposes no
# device certificate, exactly like a genuine SmartCard-HSM, so it is identified by serial plus the
# commissioned public key. "public-key" only — it never logs in.
# regalia#48 criterion 2: a missing, wrong or mismatched token never makes the daemon READY.
REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" \
  go -C "$ROOT" test -count=1 -run '^TestAGuestIsNotReadyWithAMissingWrongOrMismatchedToken$' ./internal/integration
REGALIA_D1_MODULE="$MODULE" REGALIA_D1_SERIAL="$serial" REGALIA_D1_OBJECT_ID=01 \
  go -C "$ROOT" test -count=1 -run '^TestTheProductionDriverIdentifiesATokenByItsCommissionedPublicKey$' ./internal/integration
REGALIA_COSMOS_PKCS11_MODULE="$MODULE" REGALIA_COSMOS_PKCS11_TOKEN_LABEL=regalia-kms-e2e REGALIA_COSMOS_PKCS11_SLOT='' \
  REGALIA_COSMOS_PKCS11_PIN="$E2E_PIN" REGALIA_COSMOS_PKCS11_OBJECT_ID=01 \
  "$ROOT/e2e/cosmos-hardware-sign-verify.sh"
# THE PIN IS LOAD-BEARING. Four of these five read it through e2ePKCS11PIN, which SKIPS without it —
# and a skip is a pass. This line once omitted it, so the hardware-rooted KEK guards, the release
# refusal and the concrete ECDH path "passed" here on every run while never executing.
REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$serial" REGALIA_PKCS11_E2E_PIN="$E2E_PIN" \
  go -C "$ROOT" test -count=1 -run '^TestOnlyAHardwareRootedKEKIsUsable$|^TestReleaseRefusesAKEKTheTokenWillHandBack$|^TestKEKAttributesRequireALoggedInSession$|^TestKeyAgreementOnAConcretePKCS11Module$|^TestTheKEKGuardsSeeASymmetricKey$' ./internal/integration
