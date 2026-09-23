#!/usr/bin/env bash
# cosmos-simapp-kms-tx.sh — a live Cosmos node accepts a transaction the KMS signed (regalia#439,
# acceptance criterion 1), and rejects the ones it must.
#
#   REGALIA_COSMOS_SIMD_BIN=/path/to/simd REGALIA_COSMOS_PYTHON=/path/to/venv-with-cosmpy/bin/python \
#     e2e/cosmos-simapp-kms-tx.sh
#
# cosmos-simapp-tx.sh proves the node accepts a MsgSend signed by simd's own test keyring. That is
# not evidence about the KMS. Here the signer is the KMS path — production SignDoc parser, production
# policy engine, concrete PKCS#11 provider with low-S — over a key on a disposable SoftHSM token, and
# the transaction bytes come from cosmpy's GENERATED bindings (e2e/cosmos_kms_tx.py), never from an
# encoder in this repository. The node's verdict is the evidence.
#
# ARMS, in order, each against the same live chain:
#   1. KMS-signed MsgSend       -> committed with code 0, and the balances move by exactly the amount
#   2. the same TxRaw replayed  -> rejected, and no balance moves
#   3. a KMS signature over a SignDoc for ANOTHER chain id -> rejected by the node's signature check
#   4. a destination the policy does not allow -> refused by the KMS BEFORE the token; nothing to send
#
# EVIDENCE CLASS: emulated. The token is SoftHSM; the chain, the encoding and the KMS path are real.
# Pointing REGALIA_PKCS11_E2E_* at a physical token is what would make it physical.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIMD="${REGALIA_COSMOS_SIMD_BIN:-}"
PY="${REGALIA_COSMOS_PYTHON:-python3}"
[ -n "$SIMD" ] && [ -x "$SIMD" ] || { echo "REGALIA_COSMOS_SIMD_BIN must name an executable simd" >&2; exit 2; }
"$PY" -c 'import cosmpy, cryptography' 2>/dev/null || { echo "$PY lacks cosmpy/cryptography (set REGALIA_COSMOS_PYTHON)" >&2; exit 2; }
for tool in curl jq softhsm2-util pkcs11-tool openssl go; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
MODULE=""
for candidate in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                 /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so /opt/homebrew/lib/softhsm/libsofthsm2.so; do
  [ -f "$candidate" ] && { MODULE="$candidate"; break; }
done
[ -n "$MODULE" ] || { echo "SoftHSM2 module not found" >&2; exit 2; }

STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-kms-tx.XXXXXX")"
chmod 700 "$STATE"
pid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  exec 3>&- 2>/dev/null || true
  rm -rf -- "$STATE"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

# ---- the token ---------------------------------------------------------------------------------
mkdir "$STATE/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$STATE/tokens" > "$STATE/softhsm2.conf"
export SOFTHSM2_CONF="$STATE/softhsm2.conf"
PIN="$(openssl rand -hex 16)"
softhsm2-util --init-token --free --label regalia-kms-tx --so-pin "$(openssl rand -hex 16)" --pin "$PIN" >/dev/null
P11() { REGALIA_E2E_PIN="$PIN" pkcs11-tool --module "$MODULE" --token-label regalia-kms-tx --login --pin env:REGALIA_E2E_PIN "$@"; }
P11 --keypairgen --key-type EC:secp256k1 --usage-sign --label regalia-kms-tx --id 01 >/dev/null
P11 --read-object --type pubkey --id 01 --output-file "$STATE/pub.der" >/dev/null
SERIAL="$(pkcs11-tool --module "$MODULE" --token-label regalia-kms-tx --list-slots 2>/dev/null \
          | awk -F: '/serial num/{gsub(/[[:space:]]/, "", $2); print $2; exit}')"
[ -n "$SERIAL" ] || fail "SoftHSM serial unavailable"
read -r KMS_ADDR _ < <("$PY" "$ROOT/e2e/cosmos_kms_tx.py" address --pubkey-der "$STATE/pub.der")
say "KMS key address: $KMS_ADDR"

# ---- the chain ---------------------------------------------------------------------------------
CHAIN_ID="regalia-kms-tx-$(date +%s)-$$"
RPC="http://127.0.0.1:26657" REST="http://127.0.0.1:1317"
mkfifo "$STATE/control"
exec 3<>"$STATE/control"
"$SIMD" testnet start --v 1 --chain-id "$CHAIN_ID" --output-dir "$STATE/net" \
  --key-type secp256k1 --minimum-gas-prices 0stake \
  --rpc.address tcp://127.0.0.1:26657 --api.address tcp://127.0.0.1:1317 \
  --grpc.address 127.0.0.1:9090 --print-mnemonic=false <"$STATE/control" >"$STATE/simd.log" 2>&1 &
pid=$!
HOME_DIR="$STATE/net/$CHAIN_ID/node0/simcli"
deadline=$((SECONDS + 60))
until [ -f "$HOME_DIR/keyring-test/node0.info" ] \
      && [ "$(curl -fs "$RPC/status" 2>/dev/null | jq -r '.result.sync_info.latest_block_height // "0"')" != "0" ] \
      && curl -fs "$REST/cosmos/base/tendermint/v1beta1/node_info" >/dev/null 2>&1; do
  { kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; } || { cat "$STATE/simd.log" >&2; fail "node did not come up"; }
  sleep 1
done
NODE0="$("$SIMD" keys show node0 -a --home "$HOME_DIR" --keyring-backend test)"
say "chain $CHAIN_ID up; node0 = $NODE0"

# Fund the KMS address from node0. This transfer is simd-signed and is NOT the evidence.
"$SIMD" tx bank send node0 "$KMS_ADDR" 1000000stake --from node0 --home "$HOME_DIR" --keyring-backend test \
  --chain-id "$CHAIN_ID" --node "$RPC" --fees 1stake --gas 200000 --broadcast-mode sync --yes --output json >"$STATE/fund.json" 2>&1 \
  || { cat "$STATE/fund.json" >&2; fail "funding transfer refused"; }
deadline=$((SECONDS + 30))
until [ "$("$PY" "$ROOT/e2e/cosmos_kms_tx.py" balance --rest "$REST" --address "$KMS_ADDR" --denom stake)" -gt 0 ]; do
  [ "$SECONDS" -lt "$deadline" ] || fail "funding never landed"; sleep 1
done
say "funded: $("$PY" "$ROOT/e2e/cosmos_kms_tx.py" balance --rest "$REST" --address "$KMS_ADDR" --denom stake) stake"

# kms_sign <dir> <chain-id-the-policy-allows> <allowed-destination> [expect-deny]
kms_sign() {
  local out
  out="$(REGALIA_COSMOS_NODE_SIGNDOC="$1/signdoc.bin" REGALIA_COSMOS_NODE_SIGNATURE_OUT="$1/sig.bin" \
     REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$SERIAL" REGALIA_PKCS11_E2E_PIN="$PIN" \
     REGALIA_COSMOS_NODE_OBJECT_ID=01 REGALIA_COSMOS_NODE_CHAIN_ID="$2" REGALIA_COSMOS_NODE_ALLOWED_DESTINATION="$3" \
     REGALIA_COSMOS_NODE_EXPECT_DENY="${4:-0}" \
     go -C "$ROOT" test -count=1 -v -run '^TestCosmosKMSSignsASignDocForALiveNode$' ./internal/integration 2>&1)" \
     || { printf '%s\n' "$out" >&2; return 1; }
  # A SKIP IS NOT A SIGNATURE. The test skips when its environment is incomplete; that must fail here.
  grep -q -- '--- PASS: TestCosmosKMSSignsASignDocForALiveNode' <<< "$out" || { printf '%s\n' "$out" >&2; return 1; }
}
build() { "$PY" "$ROOT/e2e/cosmos_kms_tx.py" build --rest "$REST" --from "$KMS_ADDR" --denom stake --fee 1 --gas 200000 \
            --pubkey-der "$STATE/pub.der" "$@"; }
balance() { "$PY" "$ROOT/e2e/cosmos_kms_tx.py" balance --rest "$REST" --address "$1" --denom stake; }
AMOUNT=12345

# ---- arm 1: the KMS signs, the node commits -----------------------------------------------------
kms0="$(balance "$KMS_ADDR")"; n0="$(balance "$NODE0")"
read -r ACCT SEQ < <(build --chain-id "$CHAIN_ID" --to "$NODE0" --amount "$AMOUNT" --out "$STATE/tx1")
kms_sign "$STATE/tx1" "$CHAIN_ID" "$NODE0" || fail "the KMS did not sign the cosmpy SignDoc"
r1="$("$PY" "$ROOT/e2e/cosmos_kms_tx.py" broadcast --rest "$REST" --dir "$STATE/tx1" --signature "$STATE/tx1/sig.bin")"
[ "$(jq -r .committed <<< "$r1")" = true ] || fail "node did not commit the KMS-signed tx: $r1"
kms1="$(balance "$KMS_ADDR")"; n1="$(balance "$NODE0")"
[ $(( kms0 - kms1 )) -eq $(( AMOUNT + 1 )) ] || fail "KMS balance moved by $(( kms0 - kms1 )), expected $(( AMOUNT + 1 ))"
# node0 is also the validator and collects fees, so it gains the amount plus, at most, the fee.
{ [ $(( n1 - n0 )) -ge "$AMOUNT" ] && [ $(( n1 - n0 )) -le $(( AMOUNT + 1 )) ]; } || fail "node0 balance moved by $(( n1 - n0 ))"
say "ARM 1 PASS: KMS-signed MsgSend committed (account $ACCT, sequence $SEQ, tx $(jq -r .txhash <<< "$r1"), height $(jq -r .height <<< "$r1"))"

# ---- arm 2: replaying the committed transaction is rejected -------------------------------------
r2="$("$PY" "$ROOT/e2e/cosmos_kms_tx.py" broadcast --rest "$REST" --dir "$STATE/tx1" --signature "$STATE/tx1/sig.bin")"
[ "$(jq -r .code <<< "$r2")" != 0 ] || fail "the node ACCEPTED a replayed transaction: $r2"
[ "$(balance "$KMS_ADDR")" -eq "$kms1" ] || fail "a replay moved the balance"
say "ARM 2 PASS: replay rejected (code $(jq -r .code <<< "$r2"): $(jq -r .log <<< "$r2" | cut -c1-80))"

# ---- arm 3: a valid KMS signature over the wrong chain id is rejected by the node ---------------
read -r _ SEQ3 < <(build --chain-id "not-$CHAIN_ID" --to "$NODE0" --amount "$AMOUNT" --out "$STATE/tx3")
kms_sign "$STATE/tx3" "not-$CHAIN_ID" "$NODE0" || fail "the KMS did not sign the wrong-chain SignDoc (the policy allowed that chain)"
r3="$("$PY" "$ROOT/e2e/cosmos_kms_tx.py" broadcast --rest "$REST" --dir "$STATE/tx3" --signature "$STATE/tx3/sig.bin")"
[ "$(jq -r .committed <<< "$r3")" != true ] && [ "$(jq -r .code <<< "$r3")" != 0 ] || fail "the node accepted a signature over another chain id: $r3"
[ "$(balance "$KMS_ADDR")" -eq "$kms1" ] || fail "a wrong-chain tx moved the balance"
say "ARM 3 PASS: signature over chain 'not-$CHAIN_ID' rejected (code $(jq -r .code <<< "$r3"))"

# ---- arm 4: the policy refuses a destination it does not allow, before the token ---------------
read -r _ _ < <(build --chain-id "$CHAIN_ID" --to "$KMS_ADDR" --amount "$AMOUNT" --out "$STATE/tx4")
kms_sign "$STATE/tx4" "$CHAIN_ID" "$NODE0" 1 || fail "the policy did not refuse a disallowed destination"
[ ! -e "$STATE/tx4/sig.bin" ] || fail "a refused request still produced a signature"
say "ARM 4 PASS: MsgSend to a disallowed destination refused by policy; no signature exists"

echo "Cosmos KMS-signed transaction accepted by a live node, and 3 negative arms held (chain=$CHAIN_ID evidence=emulated token)"
