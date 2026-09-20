#!/usr/bin/env bash
set -euo pipefail
SIMD="${REGALIA_COSMOS_SIMD_BIN:-}"
[ -n "$SIMD" ] || { echo "REGALIA_COSMOS_SIMD_BIN is required" >&2; exit 2; }
[ -x "$SIMD" ] || { echo "simd binary is not executable: $SIMD" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-simapp-tx.XXXXXX")"
CHAIN_ID="regalia-cosmos-tx-$(date +%s)-$$"
RPC_PORT=26657
mkfifo "$STATE/control"
exec 3<>"$STATE/control"
pid=""
cleanup() {
	if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
	exec 3>&- 2>/dev/null || true
	rm -rf -- "$STATE"
}
trap cleanup EXIT HUP INT TERM
"$SIMD" testnet start --v 1 --chain-id "$CHAIN_ID" --output-dir "$STATE" \
	--key-type secp256k1 --minimum-gas-prices 0stake \
	--rpc.address "tcp://127.0.0.1:$RPC_PORT" --api.address tcp://127.0.0.1:1317 \
	--grpc.address 127.0.0.1:9090 --print-mnemonic=false <"$STATE/control" >"$STATE/simd.log" 2>&1 &
pid=$!
HOME_DIR="$STATE/$CHAIN_ID/node0/simcli"
deadline=$((SECONDS + 45))
while :; do
	status="$(curl --fail --silent "http://127.0.0.1:$RPC_PORT/status" 2>/dev/null || true)"
	latest="$(printf '%s' "$status" | jq -r '.result.sync_info.latest_block_height // "0"' 2>/dev/null || true)"
	if [ -f "$HOME_DIR/keyring-test/node0.info" ] && [ -n "$status" ] && [ "$latest" != "0" ]; then break; fi
	if ! kill -0 "$pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then cat "$STATE/simd.log" >&2; exit 1; fi
	sleep 1
done
address="$($SIMD keys show node0 -a --home "$HOME_DIR" --keyring-backend test)"
tx_output="$STATE/tx.json"
if ! "$SIMD" tx bank send node0 "$address" 1stake --from node0 --home "$HOME_DIR" \
	--keyring-backend test --chain-id "$CHAIN_ID" --node "tcp://127.0.0.1:$RPC_PORT" \
	--fees 1stake --gas 200000 --broadcast-mode sync --yes --output json >"$tx_output" 2>&1; then
	cat "$tx_output" >&2; exit 1
fi
tx_hash="$(jq -r '.txhash // empty' "$tx_output")"
code="$(jq -r '.code // 1' "$tx_output")"
[ "$code" = 0 ] && [ -n "$tx_hash" ] || { cat "$tx_output" >&2; exit 1; }
deadline=$((SECONDS + 20))
while :; do
	tx="$(curl --fail --silent "http://127.0.0.1:$RPC_PORT/tx?hash=0x$tx_hash" 2>/dev/null || true)"
	if [ "$(printf '%s' "$tx" | jq -r '.result.tx_result.code // 1' 2>/dev/null || true)" = 0 ]; then
		printf 'Cosmos simapp transaction committed (chain=%s tx=%s)\n' "$CHAIN_ID" "$tx_hash"; exit 0
	fi
	if [ "$SECONDS" -ge "$deadline" ]; then cat "$tx_output" >&2; exit 1; fi
	sleep 1
done
