#!/usr/bin/env bash
# Sign the generated Cosmos SignDoc digest with a staging PKCS#11 secp256k1 key and verify it
# against the public key returned by the same token. This is intentionally opt-in: it touches a
# real token and therefore requires an explicit module, token selector, PIN, and object id.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="${REGALIA_COSMOS_PKCS11_MODULE:-}"
TOKEN_LABEL="${REGALIA_COSMOS_PKCS11_TOKEN_LABEL:-}"
SLOT="${REGALIA_COSMOS_PKCS11_SLOT:-}"
PIN="${REGALIA_COSMOS_PKCS11_PIN:-}"
OBJECT_ID="${REGALIA_COSMOS_PKCS11_OBJECT_ID:-}"

[ -n "$MODULE" ] || { echo "REGALIA_COSMOS_PKCS11_MODULE is required" >&2; exit 2; }
[ -f "$MODULE" ] || { echo "PKCS#11 module does not exist: $MODULE" >&2; exit 2; }
[ -n "$TOKEN_LABEL" ] || [ -n "$SLOT" ] || { echo "REGALIA_COSMOS_PKCS11_TOKEN_LABEL or REGALIA_COSMOS_PKCS11_SLOT is required" >&2; exit 2; }
[ -z "$SLOT" ] || [[ "$SLOT" =~ ^[0-9]+$ ]] || { echo "PKCS#11 slot must be a decimal number: $SLOT" >&2; exit 2; }
[ -n "$OBJECT_ID" ] || { echo "REGALIA_COSMOS_PKCS11_OBJECT_ID is required" >&2; exit 2; }
case "$OBJECT_ID" in *[!0-9A-Fa-f]*) echo "REGALIA_COSMOS_PKCS11_OBJECT_ID must be hexadecimal" >&2; exit 2;; esac
[ -n "$PIN" ] || { echo "REGALIA_COSMOS_PKCS11_PIN is required" >&2; exit 2; }
[ "${#PIN}" -ge 6 ] || { echo "refusing a PIN shorter than six characters" >&2; exit 2; }
command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
python3 -c 'import cryptography' 2>/dev/null || {
  echo "python cryptography package is required for signature verification" >&2
  exit 2
}

STATE="$(mktemp -d)"
cleanup() { unset PIN; rm -rf -- "$STATE"; }
trap cleanup EXIT HUP INT TERM
chmod 700 "$STATE"

python3 - "$ROOT/internal/policy/testdata/signdoc-akashnet2-msgsend.hex" "$STATE/digest.bin" <<'PY'
import hashlib
import pathlib
import sys

raw = bytes.fromhex(pathlib.Path(sys.argv[1]).read_text())
pathlib.Path(sys.argv[2]).write_bytes(hashlib.sha256(raw).digest())
PY

SELECTOR=()
if [ -n "$SLOT" ]; then SELECTOR=(--slot "$SLOT"); else SELECTOR=(--token-label "$TOKEN_LABEL"); fi
PKCS11_PIN="$PIN" pkcs11-tool --module "$MODULE" "${SELECTOR[@]}" \
  --login --pin env:PKCS11_PIN --read-object --type pubkey --id "$OBJECT_ID" \
  --output-file "$STATE/public.der" >/dev/null
PKCS11_PIN="$PIN" pkcs11-tool --module "$MODULE" "${SELECTOR[@]}" \
  --login --pin env:PKCS11_PIN --sign --mechanism ECDSA --id "$OBJECT_ID" \
  --input-file "$STATE/digest.bin" --output-file "$STATE/signature.raw" >/dev/null

python3 - "$STATE/public.der" "$STATE/digest.bin" "$STATE/signature.raw" <<'PY'
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
import pathlib
import sys

public = serialization.load_der_public_key(pathlib.Path(sys.argv[1]).read_bytes())
if not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != "secp256k1":
    raise SystemExit(f"token public key is not secp256k1: {getattr(public, 'curve', None)}")
digest = pathlib.Path(sys.argv[2]).read_bytes()
signature = pathlib.Path(sys.argv[3]).read_bytes()
if len(signature) != 64:
    raise SystemExit(f"PKCS#11 ECDSA result is {len(signature)} bytes, expected raw r||s")
r = int.from_bytes(signature[:32], "big")
s = int.from_bytes(signature[32:], "big")
public.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
PY

echo "Cosmos SignDoc hardware signature verified (token=${TOKEN_LABEL:-slot-$SLOT} object=$OBJECT_ID)"
