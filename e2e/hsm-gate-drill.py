#!/usr/bin/env python3
"""hsm-gate-drill.py — the HSM gate of regalia-kms#72 (G3) on a REAL token, with an operator at the bench.

    sudo -v && python3 -Es e2e/hsm-gate-drill.py --serial DENK0404144 [--evidence FILE]

The real daemon (built with -tags piv, the production build) serves a key on the real token through
OpenSC, under runtime_admission: required. This drill plays the lease service: it writes the admission
file the daemon reads, as deploy/baremetal/admission.py does on a host (the leases themselves, and peers
issuing them, are e2e/runtime-admission.py's and the three-node tests'). What it shows is the daemon's
side of the gate on hardware:

  12.1  booted, with a lease asked for after the daemon started: ready, and a signature that verifies
  12.3  the lease refused: NOT ready and every request refused, while the daemon and the OS stay up
  12.4  the token PULLED (the operator), then put back: refused until a lease asked for after its return
  G2    the token pulled and put back BETWEEN two requests, with nothing asking meanwhile: the next request
        is still refused until a fresh lease (the PC/SC reader watcher saw it go)

What it changes, and puts back: ONE temporary P-256 key is generated on the token for the drill and
deleted at the end; the objects on the token are listed before and after, and must be the same. The PIN is
read from the terminal (never an argument, never logged), checked once before anything else (a wrong PIN
costs one try of the token's counter, and the drill stops there), and held only in a 0600 file in a 0700
directory under /tmp for the daemon, removed at the end. The evidence log records every step, the daemon's
log and its audit journal, and no PIN.
"""
import argparse
import base64
import datetime
import getpass
import hashlib
import http.client
import json
import os
import pwd
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deploy.baremetal import admission  # noqa: E402

MODULE = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
SITE, DEVICE, OBJECT, PRINCIPAL = "g3-drill", "hsm-drill", "g3-drill-key", "spiffe://regalia/workload/g3-drill"
LABEL, NODE, SESSION = "regalia-g3-drill", "a", "5e" * 32
log, results = None, []


def say(text):
    line = "%s %s" % (datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"), text)
    print(line, flush=True)
    log.write(line + "\n")
    log.flush()


def check(condition, text, detail=""):
    results.append(bool(condition))
    say("%s %s%s" % ("PASS" if condition else "FAIL", text, "" if condition or not detail else ": " + str(detail)[:400]))


def run(argv, env=None, input=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env, input=input)
    if done.returncode != 0:
        raise SystemExit("hsm-gate-drill: %s failed (%d): %s" % (" ".join(str(a) for a in argv[:3]), done.returncode, done.stderr.strip()[-400:]))
    return done.stdout


def operator(text):
    say("OPERATOR: " + text)
    input("           press Enter when done ")
    say("operator: done")


def objects(serial):
    """The token's objects, as pkcs11-tool lists them without a login (public objects): what must be the same after."""
    return run(["pkcs11-tool", "--module", MODULE, "--token-label", token_label(serial), "--list-objects"])


def token_label(serial):
    slots = [block for block in run(["pkcs11-tool", "--module", MODULE, "-L"]).split("Slot ")[1:] if "serial num         : %s\n" % serial in block]
    if len(slots) != 1:
        raise SystemExit("hsm-gate-drill: the token %s is not attached exactly once (found %d): refused" % (serial, len(slots)))
    label = next(line.split(":", 1)[1].strip() for line in slots[0].splitlines() if line.strip().startswith("token label"))
    # pkcs11-tool picks the token by label (its slot number changes when it is replugged): no other may carry it
    labels = [line.split(":", 1)[1].strip() for line in run(["pkcs11-tool", "--module", MODULE, "-L"]).splitlines()
              if line.strip().startswith("token label")]
    if labels.count(label) != 1:
        raise SystemExit("hsm-gate-drill: the label %r of token %s is not unique among the attached tokens: refused" % (label, serial))
    return label


def main():
    global log
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--serial", required=True, help="the token serial the drill runs on (refused on any other)")
    parser.add_argument("--evidence", default=None, help="the evidence log (default: ./g3-drill-<serial>-<time>.log)")
    args = parser.parse_args()
    if os.geteuid() == 0 or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        raise SystemExit("hsm-gate-drill: run as your user with sudo authorised (sudo -v): the daemon runs as you, two files are root's")
    for tool in ("go", "pkcs11-tool", "openssl"):
        if not shutil.which(tool):
            raise SystemExit("hsm-gate-drill: %s is required" % tool)
    path = args.evidence or "g3-drill-%s-%s.log" % (args.serial, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    log = open(path, "x")
    say("regalia-kms#72 G3 drill on token %s (evidence: %s)" % (args.serial, path))
    label = token_label(args.serial)
    say("the token: serial %s, label %r, through %s" % (args.serial, label, MODULE))
    before = objects(args.serial)
    pin = getpass.getpass("User PIN of %s (read from the terminal, never logged): " % args.serial)
    token = ["pkcs11-tool", "--module", MODULE, "--token-label", label]
    if subprocess.run(token + ["--login", "--pin", "env:P", "--list-objects"], capture_output=True, env=dict(os.environ, P=pin)).returncode != 0:
        raise SystemExit("hsm-gate-drill: the PIN was refused (one try of the counter is spent): stopping here")
    w = Path(tempfile.mkdtemp(dir="/tmp"))
    runtime = Path("/tmp") / ("regalia-run-" + w.name)
    key_id = os.urandom(4).hex()
    processes = []
    try:
        drill(args.serial, label, pin, w, runtime, key_id, processes)
    finally:
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
        for kind in ("privkey", "pubkey"):
            subprocess.run(token + ["--login", "--pin", "env:P", "--delete-object", "--type", kind, "--id", key_id],
                           capture_output=True, env=dict(os.environ, P=pin))
        for name in ("daemon.log", "state/audit.jsonl"):
            if (w / name).exists():
                log.write("\n----- %s -----\n%s\n" % (name, (w / name).read_text(errors="replace")[-20000:]))
        subprocess.run(["sudo", "rm", "-rf", str(runtime)], capture_output=True)
        shutil.rmtree(w, ignore_errors=True)
        after = objects(args.serial)
        check(after == before, "the token's objects are as they were (the drill's key deleted)", after)
        say("%d passed, %d failed" % (results.count(True), results.count(False)))
        log.close()
    return 0 if results and all(results) else 1


def drill(serial, label, pin, w, runtime, key_id, processes):
    etc, state = w / "etc", w / "state"
    for d in (etc, state, w / "collector"):
        d.mkdir(mode=0o700)
    token = ["pkcs11-tool", "--module", MODULE, "--token-label", label]
    run(token + ["--login", "--pin", "env:P", "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", LABEL, "--id", key_id],
        env=dict(os.environ, P=pin))
    say("a temporary P-256 key generated on the token (id %s, label %s): deleted at the end" % (key_id, LABEL))
    run(token + ["--read-object", "--type", "pubkey", "--id", key_id, "--output-file", w / "pub.der"])
    run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", w / "pub.der", "-out", w / "pub.pem"])
    keypin = "sha256:" + hashlib.sha256((w / "pub.der").read_bytes()).hexdigest()
    (etc / "card.pin").touch(mode=0o600)
    (etc / "card.pin").write_text(pin)
    for name in ("regalia-kms", "regalia-audit-collector"):
        run(["go", "-C", ROOT, "build", *(["-tags", "piv"] if name == "regalia-kms" else []), "-o", w / name, "./cmd/" + name])
    for name, ext in (("ca", None), ("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature"),
                      ("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"),
                      ("client", "subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature" % PRINCIPAL)):
        run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", etc / (name + ".key")])
        if ext is None:
            run(["openssl", "req", "-new", "-x509", "-key", etc / "ca.key", "-subj", "/CN=g3 drill CA", "-days", "1", "-out", etc / "ca.pem",
                 "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"])
            continue
        run(["openssl", "req", "-new", "-key", etc / (name + ".key"), "-subj", "/CN=g3 drill " + name, "-out", etc / (name + ".csr")])
        (etc / (name + ".ext")).write_text(ext + "\n")
        run(["openssl", "x509", "-req", "-in", etc / (name + ".csr"), "-CA", etc / "ca.pem", "-CAkey", etc / "ca.key", "-set_serial",
             str(int.from_bytes(os.urandom(8), "big")), "-days", "1", "-extfile", etc / (name + ".ext"), "-out", etc / (name + ".pem")])
    stamp = datetime.datetime.now(datetime.timezone.utc)
    day = lambda d: (stamp + datetime.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
    port, sink = 18463, 18464
    documents = {
        "secure-channel.json": {"schema_version": 1, "devices": [{"device_serial": serial, "verified_by": "g3-drill", "verified_at": day(0),
                                                                   "expires_at": day(1), "firmware": "bench", "secure_messaging_established": True}]},
        "manifest.json": {"schema_version": 1, "manifest_id": "g3-drill", "generated_at": day(0), "objects": [{
            "id": OBJECT, "name": "G3 drill P-256 key", "kind": "asymmetric-key", "classification": "restricted", "environment": "staging",
            "owner": "security", "purpose": "g3-drill", "custody": "direct-hardware", "algorithm": "p256", "operations": ["sign"], "policy_id": "g3",
            "bindings": [{"site": SITE, "backend": "nitrokey-pkcs11", "device_id": DEVICE, "device_serial": serial, "object_id": key_id,
                          "public_key_sha256": keypin, "public_fingerprint": keypin, "state": "active"}],
            "recovery": {"mode": "shamir-4-of-6", "authority_id": "g3", "minimum_replicas": 2, "status": "tested"},
            "rotation": {"maximum_age_days": 90, "last_rotated": None}, "migration": {"status": "migrated", "source": "g3"},
            "verification": {"status": "verified", "last_verified": day(0)[:10], "evidence": "g3"}}]},
        "policy.json": {"schema_version": 1, "policies": [{"id": "g3", "object_id": OBJECT, "purpose": "g3-drill", "environment": "staging",
                                                           "operation": "sign", "algorithm": "p256", "content_types": ["application/vnd.regalia.digest"],
                                                           "max_payload_bytes": 32, "max_future_seconds": 300, "required_approvals": 0,
                                                           "approvers": ["spiffe://regalia/approver/g3"]}]},
        "rbac.json": {"schema_version": 1, "principals": [{"uri": PRINCIPAL, "grants": [{"objects": [OBJECT], "operations": ["sign"], "environments": ["staging"]}]}]},
        "config.json": {"listen_address": "127.0.0.1:%d" % port, "site": SITE, "registry_path": str(etc / "manifest.json"),
                        "rbac_policy_path": str(etc / "rbac.json"), "policy_path": str(etc / "policy.json"),
                        "policy_state_path": str(state / "policy-state.jsonl"), "tls_certificate_path": str(etc / "server.pem"),
                        "tls_private_key_path": str(etc / "server.key"), "tls_client_ca_path": str(etc / "ca.pem"), "pkcs11_module_path": MODULE,
                        "secure_channel_evidence_path": str(etc / "secure-channel.json"), "pin_paths": {DEVICE: str(etc / "card.pin")},
                        "audit_journal_path": str(state / "audit.jsonl"), "audit_sink_url": "https://127.0.0.1:%d" % sink,
                        "runtime_admission": "required", "runtime_admission_path": str(runtime / "admission" / "admission.json"),
                        "runtime_admission_owner": pwd.getpwuid(os.getuid()).pw_name, "node_id": NODE,
                        "boot_session_path": str(runtime / "boot-session")}}
    for name, document in documents.items():
        (etc / name).write_text(json.dumps(document, indent=1) + "\n")
        (etc / name).chmod(0o600)
    run(["sudo", "install", "-d", "-m", "0755", "-o", "root", "-g", "root", runtime])
    run(["sudo", "install", "-d", "-m", "0755", "-o", str(os.getuid()), "-g", str(os.getgid()), runtime / "admission"])
    (w / "boot-session").write_text(SESSION + "\n")
    run(["sudo", "install", "-m", "0644", "-o", "root", "-g", "root", w / "boot-session", runtime / "boot-session"])

    def lease(serve=True):
        """The lease service's file: a lease asked for NOW, listing this token (G1), or a refusal."""
        now = admission.boottime_ms()
        document = {"schema": admission.SCHEMA, "node_id": NODE, "session_id": SESSION, "boot_id": admission.boot_id(), "epoch": 1,
                    "manifest_digest": "d1" * 32, "hsm_serials": serial, "lease_issued_at": day(0),
                    "requested_boottime_ms": now if serve else 0, "serve_until_boottime_ms": now + 250_000 if serve else 0,
                    "reason": "" if serve else "the drill refuses the lease"}
        tmp = runtime / "admission" / ".admission.new"
        tmp.write_text(json.dumps(document) + "\n")
        tmp.chmod(0o644)
        os.replace(tmp, runtime / "admission" / "admission.json")
        say("lease service: %s" % ("a lease asked for now (boot clock %d ms)" % now if serve else "the lease refused (serve_until 0)"))
        time.sleep(1)

    processes.append(subprocess.Popen([str(w / "regalia-audit-collector"), "-state", str(w / "collector"), "-listen", "127.0.0.1:%d" % sink,
                                       "-tls-cert", str(etc / "collector.pem"), "-tls-key", str(etc / "collector.key"), "-client-ca", str(etc / "ca.pem")],
                                      stdout=open(w / "collector.log", "w"), stderr=subprocess.STDOUT))
    time.sleep(2)
    daemon = subprocess.Popen([str(w / "regalia-kms"), "-config", str(etc / "config.json")], stdout=open(w / "daemon.log", "w"), stderr=subprocess.STDOUT)
    processes.append(daemon)
    context = ssl.create_default_context(cafile=str(etc / "ca.pem"))
    context.load_cert_chain(str(etc / "client.pem"), str(etc / "client.key"))

    def call(method, url, body=None):
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=60)
        nonce = "g3-" + os.urandom(12).hex()
        headers = {"X-Request-ID": str(uuid.uuid4()), **({"Content-Type": "application/json", "Idempotency-Key": nonce} if body else {})}
        connection.request(method, url, body=json.dumps(body) if body else None, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, (json.loads(payload) if payload.startswith(b"{") else {})

    def ready():
        try:
            return call("GET", "/v1/health/ready")[0]
        except OSError:
            return None

    def sign():
        message = os.urandom(32)
        expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        status, answer = call("POST", "/v1/operations/sign", {
            "object_id": OBJECT, "context": {"environment": "staging", "purpose": "g3-drill", "expires_at": expires, "nonce": "g3-" + os.urandom(8).hex()},
            "content_type": "application/vnd.regalia.digest", "payload_base64": base64.b64encode(hashlib.sha256(message).digest()).decode()})
        if status != 200:
            return status, False
        raw = base64.b64decode(answer["result_base64"])
        integer = lambda v: b"\x02" + bytes([len(v)]) + v
        part = lambda v: (b"\x00" + v.lstrip(b"\x00")) if (v.lstrip(b"\x00") or b"\x00")[0] & 0x80 else (v.lstrip(b"\x00") or b"\x00")
        body = integer(part(raw[:32])) + integer(part(raw[32:]))
        (w / "sig.der").write_bytes(b"\x30" + bytes([len(body)]) + body)
        (w / "message").write_bytes(message)
        verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", w / "pub.pem", "-signature", w / "sig.der", w / "message"],
                                  capture_output=True).returncode == 0
        return status, verified

    def wait(want, seconds=60):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and daemon.poll() is None:
            if ready() == want:
                return want
            time.sleep(1)
        return ready()

    check(wait(503) == 503, "the daemon is up and NOT ready before any lease")
    say("### 12.1  a lease asked for after the daemon started")
    lease()
    check(wait(200) == 200, "ready under the lease")
    status, verified = sign()
    check(status == 200 and verified, "it signs on the token, and openssl verifies the signature", status)
    say("### 12.3  the lease refused: the daemon and the OS stay up, the KMS does not serve")
    lease(serve=False)
    check(wait(503) == 503 and sign()[0] == 503 and daemon.poll() is None, "not ready, a sign is refused (503), and the daemon still runs")
    lease()
    check(wait(200) == 200 and sign() == (200, True), "a lease again: it serves again")
    say("### 12.4  the token pulled, then put back")
    operator("PULL token %s out of its USB port (leave it out)" % serial)
    check(sign()[0] == 503 and wait(503) == 503, "with the token out: a sign is refused, not ready")
    operator("PUT token %s back into a USB port" % serial)
    time.sleep(3)
    check(sign()[0] == 503 and wait(503, 15) == 503, "back, under the lease from before it left: still refused, not ready")
    lease()
    check(wait(200) == 200 and sign() == (200, True), "under a lease asked for after its return: it serves")
    say("### G2  pulled and put back BETWEEN two requests, nothing asking meanwhile")
    check(sign() == (200, True), "serving before")
    operator("PULL token %s and PUT IT BACK within ten seconds" % serial)
    time.sleep(3)
    check(sign()[0] == 503, "the next request is refused: the reader watcher saw it go, though no request did")
    lease()
    check(wait(200) == 200 and sign() == (200, True), "under a fresh lease it serves")


if __name__ == "__main__":
    sys.exit(main())
