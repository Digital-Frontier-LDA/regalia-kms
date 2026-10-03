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
# ARMS, in order, each against the same live chain. "The KMS" keeps ONE durable policy journal for
# the whole run, as the daemon does; "another KMS" is the same code with an empty journal and, where
# said, a policy that allows what this one refuses. It exists to show what the NODE does when only the
# node is left to refuse.
#    1. KMS-signed MsgSend            -> committed with code 0; the balances move by exactly amount + fee
#    2. the same TxRaw replayed       -> rejected by the node (code 19); no balance moves
#    3. another chain id              -> refused by the KMS (cosmos-chain); signed by another KMS, the
#                                        node rejects the signature (code 4)
#    4. a destination outside policy  -> refused by the KMS (cosmos-destination) before the token
#    5. account sequence              -> a skipped and a reused sequence are refused by the KMS (rule
#                                        sequence); signed by another KMS, the node rejects it (code 32)
#    6. account number                -> another account's number is refused by the KMS (cosmos-account);
#                                        signed by another KMS, the node rejects the signature (code 4)
#    7. fee and gas                   -> a fee or gas limit over the cap is refused by the KMS
#                                        (cosmos-fee, cosmos-gas); a gas limit the KMS allows but the
#                                        chain cannot run in is rejected by the node (code 11)
#    8. several messages              -> two allowed MsgSends commit and move the sum; one disallowed
#                                        destination (cosmos-destination), or a sum over the
#                                        per-transaction cap (cosmos-amount), is refused
#    9. malformed sign bytes          -> a memo and a truncated SignDoc are refused by the parser
#   10. daily quota                   -> the send that would cross the cap is refused (rule quota); a
#                                        smaller one at the SAME sequence then commits
#   11. promotion                     -> the promoted epoch signs the next sequence and it commits; the
#                                        superseded epoch is then refused (rule epoch)
# The run ends by checking the chain's own sequence and the KMS balance against the sum of what was
# committed, so a refused arm that moved anything fails there even if its own check missed it.
#
# EVIDENCE CLASS: emulated by default (SoftHSM); PHYSICAL with REGALIA_COSMOS_TOKEN_SERIAL (see below).
# The chain, the encoding and the KMS path are real either way; the final line names the class.
# Physical example: REGALIA_COSMOS_TOKEN_SERIAL=DENK0404144 REGALIA_COSMOS_TOKEN_OBJECT_ID=30 REGALIA_COSMOS_TOKEN_PIN=…
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIMD="${REGALIA_COSMOS_SIMD_BIN:-}"
PY="${REGALIA_COSMOS_PYTHON:-python3}"
[ -n "$SIMD" ] && [ -x "$SIMD" ] || { echo "REGALIA_COSMOS_SIMD_BIN must name an executable simd" >&2; exit 2; }
"$PY" -I -c 'import cosmpy, cryptography' 2>/dev/null || { echo "$PY lacks cosmpy/cryptography (set REGALIA_COSMOS_PYTHON)" >&2; exit 2; }
for tool in curl jq pkcs11-tool openssl go; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
# SoftHSM is needed only for the EMULATED run; a host with just OpenSC and a real token must be able
# to run the physical one (review of #32).
MODULE=""
if [ -z "${REGALIA_COSMOS_TOKEN_SERIAL:-}" ]; then
  command -v softhsm2-util >/dev/null || { echo "softhsm2-util is required for the emulated run" >&2; exit 2; }
  for candidate in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                   /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so /opt/homebrew/lib/softhsm/libsofthsm2.so; do
    [ -f "$candidate" ] && { MODULE="$candidate"; break; }
  done
  [ -n "$MODULE" ] || { echo "SoftHSM2 module not found" >&2; exit 2; }
fi

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
# EMULATED by default: a disposable SoftHSM token and a fresh secp256k1 key. PHYSICAL when
# REGALIA_COSMOS_TOKEN_SERIAL names a real token: the key at REGALIA_COSMOS_TOKEN_OBJECT_ID must
# already exist on it (secp256k1, generated on the card), the slot is resolved BY SERIAL — never by
# index — and the PIN comes from REGALIA_COSMOS_TOKEN_PIN. The KMS path is identical in both; only
# the class of evidence the final line claims changes.
OBJECT_ID=01
if [ -n "${REGALIA_COSMOS_TOKEN_SERIAL:-}" ]; then
  EVIDENCE="physical token ${REGALIA_COSMOS_TOKEN_SERIAL}"
  MODULE="${REGALIA_COSMOS_TOKEN_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
  SERIAL="$REGALIA_COSMOS_TOKEN_SERIAL"
  PIN="${REGALIA_COSMOS_TOKEN_PIN:?REGALIA_COSMOS_TOKEN_PIN is required with a physical token}"
  OBJECT_ID="${REGALIA_COSMOS_TOKEN_OBJECT_ID:?REGALIA_COSMOS_TOKEN_OBJECT_ID is required with a physical token}"
  SLOT_ID="$(pkcs11-tool --module "$MODULE" --list-slots 2>/dev/null | awk -v want="$SERIAL" '
      /^Slot [0-9]+ \(0x[0-9a-fA-F]+\)/ { match($0, /\(0x[0-9a-fA-F]+\)/); id = substr($0, RSTART + 1, RLENGTH - 2) }
      /serial num *:/ { v = $NF; if (v == want) { n++; found = id } }
      END { if (n > 1) print "AMBIGUOUS"; else if (n == 1) print found }')"
  [ "$SLOT_ID" != AMBIGUOUS ] || fail "more than one slot reports serial $SERIAL — refusing to guess which token signs"
  [ -n "$SLOT_ID" ] || fail "no slot reports serial $SERIAL"
  P11() { REGALIA_E2E_PIN="$PIN" pkcs11-tool --module "$MODULE" --slot "$SLOT_ID" --login --pin env:REGALIA_E2E_PIN "$@"; }
  P11 --read-object --type pubkey --id "$OBJECT_ID" --output-file "$STATE/pub.der" >/dev/null 2>&1 \
    || fail "no public key at object $OBJECT_ID on $SERIAL"
else
  EVIDENCE="emulated token"
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
fi
read -r KMS_ADDR _ < <("$PY" -Es "$ROOT/e2e/cosmos_kms_tx.py" address --pubkey-der "$STATE/pub.der")
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
until [ "$("$PY" -Es "$ROOT/e2e/cosmos_kms_tx.py" balance --rest "$REST" --address "$KMS_ADDR" --denom stake)" -gt 0 ]; do
  [ "$SECONDS" -lt "$deadline" ] || fail "funding never landed"; sleep 1
done
say "funded: $("$PY" -Es "$ROOT/e2e/cosmos_kms_tx.py" balance --rest "$REST" --address "$KMS_ADDR" --denom stake) stake"

# ---- the policy the KMS enforces, fixed by the operator, never read from a SignDoc ----------------
MAX_GAS=300000 MAX_FEE=1000 MAX_PER_TX=20000 MAX_PER_DAY=30000
EPOCH_HELD=7 EPOCH_PROMOTED=8
NOW="$(date +%s)"
ACCT=""   # the KMS account's number on this chain; read from the chain before arm 1

# kms_sign <dir> [NAME=value ...] — one request to the KMS. NAME overrides REGALIA_COSMOS_NODE_NAME
# for that request only (the policy another KMS would hold, or the refusal an arm expects).
kms_sign() {
  local dir="$1" out kv; shift
  local -a over=()
  for kv in "$@"; do over+=("REGALIA_COSMOS_NODE_$kv"); done
  rm -f -- "$dir/sig.bin"
  out="$(env REGALIA_COSMOS_NODE_SIGNDOC="$dir/signdoc.bin" REGALIA_COSMOS_NODE_SIGNATURE_OUT="$dir/sig.bin" \
     REGALIA_PKCS11_E2E_MODULE="$MODULE" REGALIA_PKCS11_E2E_SERIAL="$SERIAL" REGALIA_PKCS11_E2E_PIN="$PIN" \
     REGALIA_COSMOS_NODE_OBJECT_ID="$OBJECT_ID" REGALIA_COSMOS_NODE_CHAIN_ID="$CHAIN_ID" \
     REGALIA_COSMOS_NODE_ACCOUNT_NUMBER="$ACCT" REGALIA_COSMOS_NODE_SOURCE="$KMS_ADDR" \
     REGALIA_COSMOS_NODE_ALLOWED_DESTINATION="$NODE0" REGALIA_COSMOS_NODE_POLICY_STATE="$STATE/policy-state.jsonl" \
     REGALIA_COSMOS_NODE_MAX_GAS="$MAX_GAS" REGALIA_COSMOS_NODE_MAX_FEE="$MAX_FEE" \
     REGALIA_COSMOS_NODE_MAX_PER_TX="$MAX_PER_TX" REGALIA_COSMOS_NODE_MAX_PER_DAY="$MAX_PER_DAY" \
     REGALIA_COSMOS_NODE_EPOCH="$EPOCH_HELD" REGALIA_COSMOS_NODE_NOW="$NOW" "${over[@]}" \
     go -C "$ROOT" test -count=1 -v -run '^TestCosmosKMSSignsASignDocForALiveNode$' ./internal/integration 2>&1)" \
     || { printf '%s\n' "$out" >&2; return 1; }
  # A SKIP IS NOT A SIGNATURE. The test skips when its environment is incomplete; that must fail here.
  grep -q -- '--- PASS: TestCosmosKMSSignsASignDocForALiveNode' <<< "$out" || { printf '%s\n' "$out" >&2; return 1; }
}
# build [cosmpy build flags] — FEE and GAS may be set for one call.
build() { "$PY" -Es "$ROOT/e2e/cosmos_kms_tx.py" build --rest "$REST" --from "$KMS_ADDR" --denom stake --fee "${FEE:-1}" --gas "${GAS:-200000}" \
            --chain-id "$CHAIN_ID" --pubkey-der "$STATE/pub.der" "$@"; }
# balance <address> — prints the stake balance. A balance that could not be READ is a harness
# failure and says so; it must never be compared as if it were a number, because "the query failed"
# would then read as "a refused transaction moved the balance".
balance() {
  local value
  value="$("$PY" -Es "$ROOT/e2e/cosmos_kms_tx.py" balance --rest "$REST" --address "$1" --denom stake)" \
    && [[ "$value" =~ ^[0-9]+$ ]] || { echo "HARNESS: could not read the balance of $1 from the node" >&2; return 1; }
  printf '%s\n' "$value"
}
broadcast() { "$PY" -Es "$ROOT/e2e/cosmos_kms_tx.py" broadcast --rest "$REST" --dir "$1" --signature "$1/sig.bin"; }

negatives=0
kms_balance=""   # what the KMS account must hold; only a committed transaction changes it
# kms_refuses <what> <dir> <refusal> [NAME=value ...] — the KMS must refuse for exactly that reason,
# and leave no signature behind.
kms_refuses() {
  local what="$1" dir="$2" refusal="$3"; shift 3
  kms_sign "$dir" EXPECT_REFUSAL="$refusal" "$@" || fail "$what: the KMS did not refuse with '$refusal'"
  [ ! -e "$dir/sig.bin" ] || fail "$what: a refused request still produced a signature"
  negatives=$((negatives + 1))
  say "  refused by the KMS ($refusal): $what"
}
# node_rejects <what> <dir> <code> — the node must reject the signed transaction with exactly that ABCI
# code, and no balance may move.
node_rejects() {
  local what="$1" dir="$2" want="${3:?node_rejects needs the expected ABCI code}" r code
  r="$(broadcast "$dir")"
  code="$(jq -r .code <<< "$r")"
  [ "$(jq -r .committed <<< "$r")" != true ] && [ "$code" != 0 ] || fail "$what: the node ACCEPTED it: $r"
  [ "$code" = "$want" ] || fail "$what: the node rejected it with code $code, expected $want: $r"
  local now; now="$(balance "$KMS_ADDR")" || fail "$what: the balance could not be read, so nothing is concluded"
  [ "$now" -eq "$kms_balance" ] || fail "$what: a rejected transaction moved the balance"
  negatives=$((negatives + 1))
  say "  rejected by the node (code $code: $(jq -r .log <<< "$r" | cut -c1-70)): $what"
}
# node_commits <what> <dir> <total-amount> — the node must commit it and the KMS account must pay
# exactly the amount and the fee.
commits=0
node_commits() {
  local what="$1" dir="$2" amount="$3" r
  r="$(broadcast "$dir")"
  [ "$(jq -r .committed <<< "$r")" = true ] || fail "$what: the node did not commit the KMS-signed tx: $r"
  kms_balance=$(( kms_balance - amount - 1 ))
  local now; now="$(balance "$KMS_ADDR")" || fail "$what: the balance could not be read, so nothing is concluded"
  [ "$now" -eq "$kms_balance" ] || fail "$what: the KMS balance is $now, expected $kms_balance"
  commits=$((commits + 1))
  say "  committed (tx $(jq -r .txhash <<< "$r" | cut -c1-16)…, height $(jq -r .height <<< "$r")): $what"
}
# Another KMS: an empty journal of its own, so nothing this run reserved constrains it.
other_kms() { local dir="$1"; shift; kms_sign "$dir" POLICY_STATE="$dir/other-kms-state.jsonl" "$@"; }
AMOUNT=12345

# ---- arm 1: the KMS signs, the node commits -----------------------------------------------------
kms_balance="$(balance "$KMS_ADDR")"; n0="$(balance "$NODE0")"
read -r ACCT SEQ < <(build --to "$NODE0" --amount "$AMOUNT" --out "$STATE/tx1")
kms_sign "$STATE/tx1" || fail "the KMS did not sign the cosmpy SignDoc"
node_commits "MsgSend of $AMOUNT (account $ACCT, sequence $SEQ)" "$STATE/tx1" "$AMOUNT"
n1="$(balance "$NODE0")"
# node0 is also the validator and collects fees, so it gains the amount plus, at most, the fee.
{ [ $(( n1 - n0 )) -ge "$AMOUNT" ] && [ $(( n1 - n0 )) -le $(( AMOUNT + 1 )) ]; } || fail "node0 balance moved by $(( n1 - n0 ))"
say "ARM 1 PASS: a KMS-signed MsgSend is committed and moves exactly the amount and the fee"

# ---- arm 2: replaying the committed transaction is rejected -------------------------------------
node_rejects "the committed TxRaw, broadcast again" "$STATE/tx1" 19
say "ARM 2 PASS: replay rejected"

# ---- arm 3: a valid KMS signature over the wrong chain id is rejected by the node ---------------
CHAIN_ID="not-$CHAIN_ID" build --to "$NODE0" --amount "$AMOUNT" --out "$STATE/tx3" >/dev/null
kms_refuses "a SignDoc for chain 'not-$CHAIN_ID'" "$STATE/tx3" cosmos-chain
other_kms "$STATE/tx3" CHAIN_ID="not-$CHAIN_ID" || fail "another KMS, whose policy allows that chain, did not sign"
node_rejects "a signature over chain 'not-$CHAIN_ID'" "$STATE/tx3" 4
say "ARM 3 PASS: another chain id is refused by the KMS, and rejected by the node when signed anyway"

# ---- arm 4: the policy refuses a destination it does not allow, before the token ---------------
build --to "$KMS_ADDR" --amount "$AMOUNT" --out "$STATE/tx4" >/dev/null
kms_refuses "MsgSend to a destination outside the policy" "$STATE/tx4" cosmos-destination
say "ARM 4 PASS: a disallowed destination never reaches the token"

# ---- arm 5: the account sequence ---------------------------------------------------------------
NEXT=$((SEQ + 1))   # the sequence the chain expects now
build --to "$NODE0" --amount 100 --sequence $((NEXT + 1)) --out "$STATE/tx5a" >/dev/null
kms_refuses "sequence $((NEXT + 1)), skipping $NEXT" "$STATE/tx5a" sequence
build --to "$NODE0" --amount 100 --sequence "$SEQ" --out "$STATE/tx5b" >/dev/null
kms_refuses "sequence $SEQ, already signed" "$STATE/tx5b" sequence
other_kms "$STATE/tx5a" || fail "another KMS, with no journal, did not sign the skipped sequence"
node_rejects "sequence $((NEXT + 1)) while the chain expects $NEXT" "$STATE/tx5a" 32
say "ARM 5 PASS: an out-of-order sequence is refused by the KMS, and rejected by the node when signed anyway"

# ---- arm 6: the account number -----------------------------------------------------------------
build --to "$NODE0" --amount 100 --account-number $((ACCT + 1)) --out "$STATE/tx6" >/dev/null
kms_refuses "account number $((ACCT + 1)), not the policy's $ACCT" "$STATE/tx6" cosmos-account
other_kms "$STATE/tx6" ACCOUNT_NUMBER=$((ACCT + 1)) || fail "another KMS, whose policy names that account, did not sign"
node_rejects "a signature over account number $((ACCT + 1))" "$STATE/tx6" 4
say "ARM 6 PASS: another account number is refused by the KMS, and rejected by the node when signed anyway"

# ---- arm 7: fee and gas ------------------------------------------------------------------------
FEE=$((MAX_FEE + 1)) build --to "$NODE0" --amount 100 --out "$STATE/tx7a" >/dev/null
kms_refuses "a fee of $((MAX_FEE + 1)), over the cap of $MAX_FEE" "$STATE/tx7a" cosmos-fee
GAS=$((MAX_GAS + 1)) build --to "$NODE0" --amount 100 --out "$STATE/tx7b" >/dev/null
kms_refuses "a gas limit of $((MAX_GAS + 1)), over the cap of $MAX_GAS" "$STATE/tx7b" cosmos-gas
GAS=1 build --to "$NODE0" --amount 100 --out "$STATE/tx7c" >/dev/null
other_kms "$STATE/tx7c" || fail "another KMS did not sign a gas limit of 1, which the policy allows"
node_rejects "a gas limit of 1" "$STATE/tx7c" 11
say "ARM 7 PASS: a fee or gas limit over the cap is refused by the KMS; the node rejects a gas limit it cannot run in"

# ---- arm 8: several messages in one transaction ------------------------------------------------
build --to "$NODE0" --amount 1000 --to "$NODE0" --amount 2000 --out "$STATE/tx8a" >/dev/null
kms_sign "$STATE/tx8a" || fail "the KMS did not sign two allowed MsgSends"
node_commits "two MsgSends, 1000 + 2000 (sequence $NEXT)" "$STATE/tx8a" 3000
NEXT=$((NEXT + 1))
build --to "$NODE0" --amount 1000 --to "$KMS_ADDR" --amount 1000 --out "$STATE/tx8b" >/dev/null
kms_refuses "two MsgSends, the second to a destination outside the policy" "$STATE/tx8b" cosmos-destination
half=$(( MAX_PER_TX / 2 + 1 ))
build --to "$NODE0" --amount "$half" --to "$NODE0" --amount "$half" --out "$STATE/tx8c" >/dev/null
kms_refuses "two MsgSends of $half each, together over the per-transaction cap of $MAX_PER_TX" "$STATE/tx8c" cosmos-amount
say "ARM 8 PASS: every message is checked, and their sum is what the per-transaction cap bounds"

# ---- arm 9: sign bytes the parser must refuse --------------------------------------------------
build --to "$NODE0" --amount 100 --memo "exchange deposit 42" --out "$STATE/tx9a" >/dev/null
kms_refuses "a SignDoc carrying a memo" "$STATE/tx9a" signdoc
build --to "$NODE0" --amount 100 --out "$STATE/tx9b" >/dev/null
head -c "$(( $(wc -c < "$STATE/tx9b/signdoc.bin") - 1 ))" "$STATE/tx9b/signdoc.bin" > "$STATE/tx9b/truncated.bin"
mv "$STATE/tx9b/truncated.bin" "$STATE/tx9b/signdoc.bin"
kms_refuses "a SignDoc truncated by one byte" "$STATE/tx9b" signdoc
say "ARM 9 PASS: a memo and a truncated SignDoc are refused by the parser, before policy"

# ---- arm 10: the daily quota -------------------------------------------------------------------
spent=$(( AMOUNT + 3000 ))                 # what the KMS has signed for today: arms 1 and 8
excess=$(( MAX_PER_DAY - spent + 1 ))      # one more than what is left
[ "$excess" -le "$MAX_PER_TX" ] || fail "harness: the over-quota send would trip the per-transaction cap instead"
build --to "$NODE0" --amount "$excess" --out "$STATE/tx10a" >/dev/null
kms_refuses "a send of $excess with $((MAX_PER_DAY - spent)) left of the daily $MAX_PER_DAY" "$STATE/tx10a" quota
fits=$(( excess - 1000 ))
build --to "$NODE0" --amount "$fits" --out "$STATE/tx10b" >/dev/null
kms_sign "$STATE/tx10b" || fail "the KMS did not sign a send that fits the daily quota (the refusal burned the sequence?)"
node_commits "a send of $fits at the same sequence $NEXT" "$STATE/tx10b" "$fits"
NEXT=$((NEXT + 1)); spent=$(( spent + fits ))
say "ARM 10 PASS: the daily quota refuses the send that would cross it, and the refusal costs no sequence"

# ---- arm 11: active/passive promotion ----------------------------------------------------------
build --to "$NODE0" --amount 100 --out "$STATE/tx11a" >/dev/null
kms_sign "$STATE/tx11a" EPOCH="$EPOCH_PROMOTED" || fail "the promoted site (epoch $EPOCH_PROMOTED) did not sign"
node_commits "the promoted site's send at sequence $NEXT" "$STATE/tx11a" 100
NEXT=$((NEXT + 1))
build --to "$NODE0" --amount 100 --out "$STATE/tx11b" >/dev/null
kms_refuses "sequence $NEXT at the superseded epoch $EPOCH_HELD" "$STATE/tx11b" epoch
say "ARM 11 PASS: after a promotion the new epoch signs the next sequence, and the superseded site is refused"

# ---- the chain's own account of the run --------------------------------------------------------
read -r _ chain_seq < <(build --to "$NODE0" --amount 1 --out "$STATE/final")
[ "$chain_seq" -eq "$NEXT" ] || fail "the chain's sequence is $chain_seq, expected $NEXT: something a refusal should have stopped was committed"
final="$(balance "$KMS_ADDR")" || fail "the final balance could not be read, so nothing is concluded"
[ "$final" -eq "$kms_balance" ] || fail "the KMS balance is $final, expected $kms_balance"

echo "Cosmos: $commits KMS-signed transactions committed by a live node, and $negatives negative checks held (chain=$CHAIN_ID evidence=$EVIDENCE)"
