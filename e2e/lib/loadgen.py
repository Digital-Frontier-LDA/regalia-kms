#!/usr/bin/env python3
"""The KMS load generator for fault drills (#495) and the three-node scenarios: steady requests against CANARY keys
only, across the three servers, with a client-side failover, and one JSON line per request for the shared predicates
(e2e/lib/drills.py, from_loadgen). Standard library only, mutual TLS.

    loadgen.py run      --config C --drill RUN --seconds N --out log.jsonl
    loadgen.py baseline --config C --drill RUN --seconds 1800 --out baseline.json

EACH LINE (exactly these ten fields; drills.from_loadgen refuses a line missing one):
    start_ms, end_ms   UTC milliseconds around the request, retries included
    op, key            the operation and the canary key's object id
    node               the server that answered, from its certificate's SAN ("" when none answered)
    outcome            "ok", or the API's error code, or "CONNECTION" when no server answered
    attempt            1, or 2 after a failover
    drill              the run id
    stateful           the canary key's own declaration (approval-gated or sequenced), never inferred
    request_id         the X-Request-ID, which every audit line carries: how the collector ties its lines to the run

FAILOVER: a connection error, or a retryable 503 (BACKEND_UNAVAILABLE, DEPENDENCY_UNAVAILABLE), is tried once more on
the next server, WITH THE SAME NONCE (the API requires Idempotency-Key == context.nonce). A retry after the first
server reserved the nonce answers CONFLICT and counts as failed: the honest outcome. A 4xx is never retried, so a
replay or a refusal is never hidden.

CANARY ONLY, ENFORCED: at start, every configured key must be named in the custody manifest with a purpose that
starts with "canary-"; otherwise the generator refuses to start. (The KMS refuses too: the canary policies are granted
only to the generator's identity.)
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import secrets
import ssl
import sys
import time
import uuid

FIELDS = ("start_ms", "end_ms", "op", "key", "node", "outcome", "attempt", "drill", "stateful", "request_id")
RETRYABLE = ("BACKEND_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE")
TIMEOUT_S = 10
BUCKETS_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)


class Refused(Exception):
    pass


def now_ms():
    return int(time.time() * 1000)


def load_config(path, manifest_path):
    """{"servers": [{"name", "url"}...], "tls": {"cert", "key", "ca"}, "keys": [{"object_id", "op", "purpose",
    "environment", "content_type", "stateful"}...]} with every key a canary of the custody manifest."""
    with open(path) as f:
        config = json.load(f)
    servers, keys = config.get("servers"), config.get("keys")
    if not isinstance(servers, list) or len(servers) < 1 or not isinstance(keys, list) or not keys:
        raise Refused("the configuration needs servers and keys")
    with open(manifest_path) as f:
        objects = {o.get("id"): o for o in json.load(f).get("objects", [])}
    for key in keys:
        found = objects.get(key.get("object_id"))
        if found is None or not str(found.get("purpose", "")).startswith("canary-"):
            raise Refused("%r is not a canary key of the custody manifest (purpose canary-*): the load generator touches canaries only"
                          % key.get("object_id"))
        if key.get("purpose") != found["purpose"] or not isinstance(key.get("stateful"), bool):
            raise Refused("%r: its purpose must be the manifest's, and stateful must be declared true or false" % key["object_id"])
    return config


def tls_context(tls):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=tls["ca"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tls["cert"], tls["key"])
    return context


def node_of(sock):
    """The answering server's name: its certificate's first DNS SAN."""
    cert = sock.getpeercert() or {}
    for kind, value in cert.get("subjectAltName", ()):
        if kind == "DNS":
            return value
    return ""


def body_for(key, nonce, expires):
    payload = hashlib.sha256(nonce.encode()).digest()
    return {"object_id": key["object_id"],
            "context": {"environment": key["environment"], "purpose": key["purpose"], "expires_at": expires, "nonce": nonce},
            "content_type": key.get("content_type", "application/vnd.regalia.digest"),
            "payload_base64": base64.b64encode(payload).decode()}


def ask(server, context, key, body, request_id, nonce):
    """One request to one server: (node, outcome, retryable)."""
    parsed = server["url"].split("://", 1)[1].rstrip("/")
    host, _, port = parsed.partition(":")
    connection = http.client.HTTPSConnection(host, int(port or 443), context=context, timeout=TIMEOUT_S)
    try:
        connection.request("POST", "/v1/operations/" + key["op"], body=json.dumps(body),
                           headers={"Content-Type": "application/json", "X-Request-ID": request_id, "Idempotency-Key": nonce})
        node = node_of(connection.sock)
        response = connection.getresponse()
        raw = response.read(1 << 20)
    except (OSError, http.client.HTTPException):
        return "", "CONNECTION", True
    finally:
        connection.close()
    if response.status == 200:
        return node, "ok", False
    try:
        code = json.loads(raw).get("code") or "HTTP_%d" % response.status
    except ValueError:
        code = "HTTP_%d" % response.status
    return node, code, code in RETRYABLE


def one(config, context, key, drill, first):
    """A request to key, starting on servers[first], failing over once. Returns its line."""
    servers = config["servers"]
    nonce, request_id = secrets.token_hex(16), str(uuid.uuid4())
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 30))
    body = body_for(key, nonce, expires)
    start = now_ms()
    node, outcome, retryable = ask(servers[first % len(servers)], context, key, body, request_id, nonce)
    attempt = 1
    if retryable and len(servers) > 1:
        attempt = 2
        node, outcome, _ = ask(servers[(first + 1) % len(servers)], context, key, body, request_id, nonce)
    return {"start_ms": start, "end_ms": now_ms(), "op": key["op"], "key": key["object_id"], "node": node, "outcome": outcome,
            "attempt": attempt, "drill": drill, "stateful": key["stateful"], "request_id": request_id}


def run(config, drill, seconds, out, rate=5.0, ask_one=None):
    """Steady requests for `seconds`, round-robin over keys and servers, `rate` per second; one line each to `out`."""
    context = tls_context(config["tls"]) if ask_one is None else None
    ask_one = ask_one or (lambda key, first: one(config, context, key, drill, first))
    end, i, written = time.time() + seconds, 0, 0
    while time.time() < end:
        key = config["keys"][i % len(config["keys"])]
        line = ask_one(key, i)
        assert tuple(line) == FIELDS, "a line has exactly the documented fields"
        out.write(json.dumps(line, sort_keys=True) + "\n")
        out.flush()
        written, i = written + 1, i + 1
        time.sleep(max(0.0, 1.0 / rate - (line["end_ms"] - line["start_ms"]) / 1000))
    return written


def baseline(lines):
    """The latency and error histogram drill.py's `baseline accept` takes: per op, counts per latency bucket and per
    outcome."""
    ops = {}
    for line in lines:
        entry = ops.setdefault(line["op"], {"requests": 0, "latency_ms": {str(b): 0 for b in BUCKETS_MS + ("inf",)}, "outcomes": {}})
        entry["requests"] += 1
        latency = line["end_ms"] - line["start_ms"]
        bucket = next((str(b) for b in BUCKETS_MS if latency <= b), "inf")
        entry["latency_ms"][bucket] += 1
        entry["outcomes"][line["outcome"]] = entry["outcomes"].get(line["outcome"], 0) + 1
    return {"schema": "regalia.loadgen-baseline/v1", "buckets_ms": list(BUCKETS_MS), "ops": ops}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=("run", "baseline"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--manifest", required=True, help="the custody manifest: canary keys are checked against it")
    parser.add_argument("--drill", required=True)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--rate", type=float, default=5.0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config, args.manifest)
    except Refused as refused:
        print("loadgen: REFUSED: %s" % refused, file=sys.stderr)
        return 2
    if args.mode == "run":
        with open(args.out, "a") as out:
            run(config, args.drill, args.seconds, out, args.rate)
        return 0
    log = args.out + ".requests.jsonl"
    with open(log, "a") as out:
        run(config, args.drill, args.seconds, out, args.rate)
    with open(log) as f:
        lines = [json.loads(line) for line in f if line.strip()]
    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(baseline(lines), f, sort_keys=True, indent=1)
    os.replace(tmp, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
