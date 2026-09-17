#!/usr/bin/env bash
# Start a disposable Cosmos SDK simapp and prove its RPC endpoint becomes healthy.
# The binary is injected explicitly so CI cannot silently drift to a broken "latest" image.
set -euo pipefail

SIMD="${REGALIA_COSMOS_SIMD_BIN:-}"
[ -n "$SIMD" ] || { echo "REGALIA_COSMOS_SIMD_BIN is required (use a reviewed simd build)" >&2; exit 2; }
[ -x "$SIMD" ] || { echo "simd binary is not executable: $SIMD" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-simapp.XXXXXX")"
CHAIN_ID="regalia-cosmos-e2e-$(date +%s)-$$"
mkfifo "$STATE/control"
exec 3<>"$STATE/control"
pid=""
cleanup() {
	if [ -n "$pid" ]; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	exec 3>&- 2>/dev/null || true
	rm -rf -- "$STATE"
}
trap cleanup EXIT HUP INT TERM

"$SIMD" testnet start --v 1 --chain-id "$CHAIN_ID" --output-dir "$STATE" \
	--key-type secp256k1 --minimum-gas-prices 0stake \
	--rpc.address tcp://127.0.0.1:26657 --api.address tcp://127.0.0.1:1317 \
	--grpc.address 127.0.0.1:9090 --print-mnemonic=false <"$STATE/control" >"$STATE/simd.log" 2>&1 &
pid=$!

deadline=$((SECONDS + 45))
while :; do
	if curl --fail --silent --show-error http://127.0.0.1:26657/status >"$STATE/status.json" 2>/dev/null; then
		printf 'Cosmos simapp RPC healthy (chain=%s binary=%s)\n' "$CHAIN_ID" "$SIMD"
		exit 0
	fi
	if ! kill -0 "$pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
		cat "$STATE/simd.log" >&2
		exit 1
	fi
	sleep 1
done
