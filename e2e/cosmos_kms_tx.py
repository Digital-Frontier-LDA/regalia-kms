#!/usr/bin/env python3
"""cosmos_kms_tx.py — the cosmpy half of e2e/cosmos-simapp-kms-tx.sh (regalia#439, criterion 1).

Every byte of the transaction is produced by cosmpy's GENERATED protobuf bindings. This repository
already has one hand-written Cosmos decoder, and a hand-written encoder beside it agreed with it
about a wire format neither matched (internal/policy/testdata/README.md). So nothing here encodes
protobuf by hand: the SignDoc the KMS signs and the TxRaw the node receives come from the same
upstream-generated classes the chain itself was built from.

    address   --pubkey-der F --prefix P            -> "<address> <compressed-pubkey-hex>"
    build     --rest URL --chain-id C --from A --to B --amount N --denom D --fee N --gas N
              --pubkey-der F --out DIR [--account-number N --sequence N]
              -> DIR/signdoc.bin, DIR/body.bin, DIR/authinfo.bin; prints "<account> <sequence>"
    broadcast --rest URL --dir DIR --signature F   -> prints JSON {txhash, code, committed, log}
    balance   --rest URL --address A --denom D     -> prints the amount
"""
import argparse
import base64
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import serialization
from cosmpy.crypto.address import Address
from cosmpy.crypto.keypairs import PublicKey
from cosmpy.protos.cosmos.bank.v1beta1.tx_pb2 import MsgSend
from cosmpy.protos.cosmos.base.v1beta1.coin_pb2 import Coin
from cosmpy.protos.cosmos.crypto.secp256k1.keys_pb2 import PubKey
from cosmpy.protos.cosmos.tx.signing.v1beta1.signing_pb2 import SignMode
from cosmpy.protos.cosmos.tx.v1beta1.tx_pb2 import AuthInfo, Fee, ModeInfo, SignDoc, SignerInfo, TxBody, TxRaw
from google.protobuf.any_pb2 import Any


def compressed_pubkey(der_path):
    key = serialization.load_der_public_key(pathlib.Path(der_path).read_bytes())
    if getattr(key, "curve", None) is None or key.curve.name != "secp256k1":
        sys.exit("the token key is not secp256k1")
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def http_json(url, body=None):
    # urllib also opens file:// and ftp:// URLs. Every URL here is built from --rest, so refuse any
    # scheme but http(s) rather than let a mistyped or hostile value read a local file.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise SystemExit(f"refusing non-HTTP URL: {url!r}")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return json.loads(payload)
        except ValueError:
            raise SystemExit(f"{url}: HTTP {e.code}: {payload[:300]!r}")


def cmd_address(a):
    pub = compressed_pubkey(a.pubkey_der)
    print(str(Address(PublicKey(pub), prefix=a.prefix)), pub.hex())


def cmd_build(a):
    pub = compressed_pubkey(a.pubkey_der)
    if a.account_number is None or a.sequence is None:
        acct = http_json(f"{a.rest}/cosmos/auth/v1beta1/accounts/{getattr(a, 'from')}")["account"]
        account_number, sequence = int(acct["account_number"]), int(acct.get("sequence") or 0)
    else:
        account_number, sequence = a.account_number, a.sequence

    msg = MsgSend(from_address=getattr(a, "from"), to_address=a.to, amount=[Coin(denom=a.denom, amount=str(a.amount))])
    packed = Any()
    packed.Pack(msg, type_url_prefix="/")
    # No memo: the KMS parser admits only TxBody.messages (fail-closed allowlist). Whether it should
    # ever sign a memo is a policy decision, not this harness's.
    body = TxBody(messages=[packed])
    pk = Any()
    pk.Pack(PubKey(key=pub), type_url_prefix="/")
    auth = AuthInfo(
        signer_infos=[SignerInfo(public_key=pk, mode_info=ModeInfo(single=ModeInfo.Single(mode=SignMode.SIGN_MODE_DIRECT)), sequence=sequence)],
        fee=Fee(amount=[Coin(denom=a.denom, amount=str(a.fee))], gas_limit=a.gas),
    )
    body_bytes, auth_bytes = body.SerializeToString(), auth.SerializeToString()
    sign_doc = SignDoc(body_bytes=body_bytes, auth_info_bytes=auth_bytes, chain_id=a.chain_id, account_number=account_number)
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "signdoc.bin").write_bytes(sign_doc.SerializeToString())
    (out / "body.bin").write_bytes(body_bytes)
    (out / "authinfo.bin").write_bytes(auth_bytes)
    print(account_number, sequence)


def cmd_broadcast(a):
    d = pathlib.Path(a.dir)
    sig = pathlib.Path(a.signature).read_bytes()
    if len(sig) != 64:
        sys.exit(f"signature must be 64 bytes r||s, got {len(sig)}")
    raw = TxRaw(body_bytes=(d / "body.bin").read_bytes(), auth_info_bytes=(d / "authinfo.bin").read_bytes(), signatures=[sig])
    resp = http_json(f"{a.rest}/cosmos/tx/v1beta1/txs",
                     {"tx_bytes": base64.b64encode(raw.SerializeToString()).decode(), "mode": "BROADCAST_MODE_SYNC"})
    tr = resp.get("tx_response") or {}
    result = {"txhash": tr.get("txhash", ""), "code": int(tr.get("code", -1)), "committed": False, "log": tr.get("raw_log", "") or resp.get("message", "")}
    # A SYNC ack is CheckTx only. Committed means the tx is in a block with code 0 — poll for it.
    if result["code"] == 0 and result["txhash"]:
        deadline = time.time() + 30
        while time.time() < deadline:
            q = http_json(f"{a.rest}/cosmos/tx/v1beta1/txs/{result['txhash']}")
            qr = q.get("tx_response")
            if qr and qr.get("height") not in (None, "0"):
                result["code"], result["committed"], result["log"] = int(qr.get("code", -1)), int(qr.get("code", -1)) == 0, qr.get("raw_log", "")
                result["height"] = qr["height"]
                break
            time.sleep(1)
    print(json.dumps(result))


def cmd_balance(a):
    resp = http_json(f"{a.rest}/cosmos/bank/v1beta1/balances/{a.address}/by_denom?denom={a.denom}")
    print(int(resp.get("balance", {}).get("amount", "0")))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("address"); p.add_argument("--pubkey-der", required=True); p.add_argument("--prefix", default="cosmos")
    p = sub.add_parser("build")
    for flag in ("--rest", "--chain-id", "--from", "--to", "--denom", "--pubkey-der", "--out"):
        p.add_argument(flag, required=True)
    for flag in ("--amount", "--fee", "--gas"):
        p.add_argument(flag, required=True, type=int)
    p.add_argument("--account-number", type=int); p.add_argument("--sequence", type=int)
    p = sub.add_parser("broadcast"); p.add_argument("--rest", required=True); p.add_argument("--dir", required=True); p.add_argument("--signature", required=True)
    p = sub.add_parser("balance"); p.add_argument("--rest", required=True); p.add_argument("--address", required=True); p.add_argument("--denom", required=True)
    a = ap.parse_args()
    {"address": cmd_address, "build": cmd_build, "broadcast": cmd_broadcast, "balance": cmd_balance}[a.cmd](a)


if __name__ == "__main__":
    main()
