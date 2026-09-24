#!/usr/bin/env python3
"""control-plane-restore-drill.py — regalia#26 criterion 3 and #49's physical drill, on the bench:
the REAL daemon, serving from a REAL Nitrokey, loses its host state and gets it back from a
control-plane export.

    REGALIA_CEREMONY_DIR=… HSM_STAGING_REGISTRY_FILE=… CARD_PIN=… \
      python3 e2e/control-plane-restore-drill.py --serial DENK0404380 --object-id 10 --workdir /build/cpdrill

Sequence:
  1 seal     an envelope to the card's KEK (TestEnvelopeSurvivesTokenWipeAndDKEKRestore, phase seal)
  2 serve    the daemon starts from a full config (mTLS, RBAC, policy, audit journal, policy state,
             the card pinned by serial and public key) and releases the secret; a replayed nonce is
             refused (CONFLICT): the policy state remembers it
  3 export   the stopped daemon's control plane is exported and sealed to a custody authority key
  4 wipe     the state directory is deleted: the host has lost its history
  5 restore  -inspect-export (bound to the site), -restore-export under /, -scan-tree,
             -verify-audit and -verify-policy-state on what was placed
  6 serve    the daemon starts on the restored state: the OLD nonce is still refused, so the history
             came back, and a new release works; the audit chain verifies across the restore
The card's PIN counter is read from outside before and after; the drill secret, the envelope record
and the authority key are deleted at the end.
"""
import argparse
import atexit
import base64
import datetime
import hashlib
import http.client
import json
import os
import shutil
import signal
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = os.environ.get("HSM_PKCS11_MODULE", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
SITE, DEVICE, PRINCIPAL = "drill", "nk-drill", "spiffe://regalia/workload/drill"
OBJECT, PURPOSE, ENV = "drill-deployment-token", "deployment-api", "staging"
LOG = []


def say(msg):
    line = f"{datetime.datetime.now(datetime.timezone.utc):%H:%M:%S} {msg}"
    print(line, flush=True)
    LOG.append(line)


def die(msg):
    say(f"FAIL: {msg}")
    sys.exit(1)


def run(argv, env=None, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        die(f"{' '.join(map(str, argv[:3]))} … failed ({result.returncode}): {result.stderr.strip()[-600:]}")
    return result


def pin_tries(serial):
    listing = run(["opensc-tool", "-l"]).stdout
    for line in listing.splitlines():
        if f"({serial}0000" in line:
            reader = line.split()[0]
            out = run(["opensc-tool", "--reader", reader, "-s", "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00",
                       "-s", "00 20 00 81"], check=False).stdout
            sw = [l for l in out.splitlines() if "SW1=0x63" in l]
            return sw[-1].split("0xC")[-1].rstrip(")").strip() if sw else "?"
    return "absent"


def pki(d):
    """A drill CA, a server certificate for 127.0.0.1 and a client certificate carrying the principal."""
    def ossl(*args):
        run(["openssl", *map(str, args)])
    ossl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", d / "ca.key")
    ossl("req", "-new", "-x509", "-key", d / "ca.key", "-subj", "/CN=regalia drill CA", "-days", "2", "-out", d / "ca.pem",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    # The daemon's certificate is ALSO its client identity towards the audit collector.
    for name, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature"),
                      ("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"),
                      ("client", f"subjectAltName=URI:{PRINCIPAL}\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature")):
        ossl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", d / f"{name}.key")
        ossl("req", "-new", "-key", d / f"{name}.key", "-subj", f"/CN=regalia drill {name}", "-out", d / f"{name}.csr")
        (d / f"{name}.ext").write_text(ext + "\n")
        ossl("x509", "-req", "-in", d / f"{name}.csr", "-CA", d / "ca.pem", "-CAkey", d / "ca.key", "-set_serial",
             str(int.from_bytes(os.urandom(8), "big")), "-days", "2", "-extfile", d / f"{name}.ext", "-out", d / f"{name}.pem")
    for f in d.iterdir():
        f.chmod(0o600)


def write_json(path, doc):
    path.write_text(json.dumps(doc, indent=2) + "\n")
    path.chmod(0o600)


class Daemon:
    def __init__(self, binary, config, env, logfile):
        self.proc = subprocess.Popen([str(binary), "-config", str(config)], env=env,
                                     stdout=open(logfile, "a"), stderr=subprocess.STDOUT)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def client(d):
    ctx = ssl.create_default_context(cafile=str(d / "ca.pem"))
    ctx.load_cert_chain(str(d / "client.pem"), str(d / "client.key"))
    return ctx


def call(ctx, port, method, path, body=None, nonce=None):
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=60)
    headers = {"X-Request-ID": str(uuid.uuid4())}
    data = None
    if body is not None:
        headers.update({"Content-Type": "application/json", "Idempotency-Key": nonce})
        data = json.dumps(body)
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    try:
        return response.status, json.loads(payload) if payload else {}
    except json.JSONDecodeError:
        return response.status, {"raw": payload.decode(errors="replace")}


def wait_ready(ctx, port, daemon, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if daemon.proc.poll() is not None:
            return False
        try:
            status, _ = call(ctx, port, "GET", "/v1/health/ready")
            if status == 200:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def release(ctx, port, blob, nonce):
    expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"object_id": OBJECT, "context": {"environment": ENV, "purpose": PURPOSE, "expires_at": expires, "nonce": nonce},
            "format": "regalia-envelope-v2", "payload_base64": base64.b64encode(blob).decode()}
    return call(ctx, port, "POST", "/v1/operations/release-secret", body, nonce)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--serial", required=True)
    ap.add_argument("--object-id", default="10")
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--port", type=int, default=18443)
    args = ap.parse_args()
    pin = os.environ.get("CARD_PIN") or die("CARD_PIN is required")
    work = Path(args.workdir)
    if work.exists():
        shutil.rmtree(work)
    etc, state, custody = work / "etc", work / "state", work / "custody"
    for d in (etc, state, custody):
        d.mkdir(parents=True, mode=0o700)
    env = dict(os.environ)
    (etc / "opensc.conf").write_text("app default {\n}\napp opensc-pkcs11 {\n\tpkcs11 {\n\t\tmax_virtual_slots = 32;\n\t}\n}\n")
    env["OPENSC_CONF"] = str(etc / "opensc.conf")
    before = pin_tries(args.serial)
    say(f"card {args.serial} object {args.object_id}; PIN tries before: {before}; workdir {work}")

    say("BUILD — the daemon binary")
    binary = work / "regalia-kms"
    run(["go", "-C", str(ROOT), "build", "-o", str(binary), "./cmd/regalia-kms"], env=env)
    collector_bin = work / "regalia-audit-collector"
    run(["go", "-C", str(ROOT), "build", "-o", str(collector_bin), "./cmd/regalia-audit-collector"], env=env)
    fence_bin = work / "regalia-fence"
    run(["go", "-C", str(ROOT), "build", "-o", str(fence_bin), "./cmd/regalia-fence"], env=env)

    say("STEP 1 — seal an envelope to the card's KEK")
    seal_env = dict(env, REGALIA_ENVDRILL_PHASE="seal", REGALIA_ENVDRILL_MODULE=MODULE, REGALIA_ENVDRILL_SERIAL=args.serial,
                    REGALIA_ENVDRILL_OBJECT_ID=args.object_id, REGALIA_ENVDRILL_PIN=pin, REGALIA_ENVDRILL_STATE=str(custody))
    out = run(["go", "-C", str(ROOT), "test", "-count=1", "-run", "^TestEnvelopeSurvivesTokenWipeAndDKEKRestore$",
               "./internal/integration"], env=seal_env, check=False)
    if "ok" not in out.stdout:
        die(f"seal phase failed: {out.stdout[-800:]}")
    record = json.loads((custody / "envelope-drill.json").read_text())
    blob, secret, pinned = base64.b64decode(record["envelope"]), base64.b64decode(record["secret"]), record["public_key_sha256"]
    say(f"  sealed; KEK pinned {pinned}")

    say("CONFIG — full daemon config: mTLS, RBAC, policy, audit journal, policy state, the card by serial and key")
    pki(etc)
    (etc / "card.pin").write_text(pin)
    (etc / "card.pin").chmod(0o600)
    now = datetime.datetime.now(datetime.timezone.utc)
    write_json(etc / "secure-channel.json", {"schema_version": 1, "devices": [{
        "device_serial": args.serial, "verified_by": "bench-drill", "verified_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "firmware": "4.1",
        "secure_messaging_established": True}]})
    write_json(etc / "manifest.json", {"schema_version": 1, "manifest_id": "control-plane-drill",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "objects": [{
            "id": OBJECT, "name": "Control-plane drill token", "kind": "api-token", "classification": "restricted",
            "environment": ENV, "owner": "security", "purpose": PURPOSE, "custody": "hardware-envelope",
            "algorithm": "opaque", "operations": ["release-secret"], "policy_id": "drill-release",
            "bindings": [{"site": SITE, "backend": "nitrokey-pkcs11", "device_id": DEVICE, "device_serial": args.serial,
                          "object_id": args.object_id, "kek_algorithm": "rsa2048", "kek_version": "1",
                          "public_key_sha256": pinned, "public_fingerprint": pinned, "state": "active"}],
            "recovery": {"mode": "shamir-4-of-6", "authority_id": "drill", "minimum_replicas": 1, "status": "tested"},
            "rotation": {"maximum_age_days": 90, "last_rotated": None},
            "migration": {"status": "migrated", "source": "drill"},
            "verification": {"status": "verified", "last_verified": now.strftime("%Y-%m-%d"), "evidence": "drill"}}]})
    write_json(etc / "policy.json", {"schema_version": 1, "policies": [{
        "id": "drill-release", "object_id": OBJECT, "purpose": PURPOSE, "environment": ENV, "operation": "release-secret",
        "algorithm": "opaque", "content_types": ["application/vnd.regalia.data-key"], "max_payload_bytes": 65536,
        "max_future_seconds": 300, "required_approvals": 0, "approvers": ["spiffe://regalia/approver/drill"]}]})
    write_json(etc / "rbac.json", {"schema_version": 1, "principals": [{"uri": PRINCIPAL, "grants": [
        {"objects": [OBJECT], "operations": ["release-secret"], "environments": [ENV]}]}]})
    # FENCING, as a two-site deployment runs: the authority (regalia-fence, its key in custody) grants
    # this site epoch 1 for exactly this registry. The epoch journal is part of the control plane.
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    fence_key = Ed25519PrivateKey.generate()
    seed = fence_key.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    pub = fence_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    (custody / "fence.key").write_text(base64.b64encode(seed + pub).decode() + "\n")
    (custody / "fence.key").chmod(0o600)
    (etc / "fence.pub").write_text(base64.b64encode(pub).decode() + "\n")
    (etc / "fence.pub").chmod(0o600)
    registry_digest = "sha256:" + hashlib.sha256((etc / "manifest.json").read_bytes()).hexdigest()
    run([str(fence_bin), "-key", str(custody / "fence.key"), "-state", str(custody / "fence-state.json"),
         "-journal", str(custody / "fence-journal.jsonl"), "-operator", "bench-drill", "-out", str(etc / "lease.json"),
         "-site", SITE, "-registry-digest", registry_digest, "-epoch", "1"])
    (etc / "lease.json").chmod(0o600)
    say(f"  fencing lease: site {SITE}, epoch 1, bound to registry {registry_digest[:23]}…")
    config = etc / "config.json"
    write_json(config, {
        "listen_address": f"127.0.0.1:{args.port}", "site": SITE,
        "registry_path": str(etc / "manifest.json"), "rbac_policy_path": str(etc / "rbac.json"),
        "policy_path": str(etc / "policy.json"), "policy_state_path": str(state / "policy-state.jsonl"),
        "tls_certificate_path": str(etc / "server.pem"), "tls_private_key_path": str(etc / "server.key"),
        "tls_client_ca_path": str(etc / "ca.pem"), "pkcs11_module_path": MODULE,
        "secure_channel_evidence_path": str(etc / "secure-channel.json"),
        "pin_paths": {DEVICE: str(etc / "card.pin")}, "audit_journal_path": str(state / "audit.jsonl"),
        # A journal-only host is deliberately never ready (high-risk operations fail closed without an
        # off-host copy), so the drill runs the real collector: the OFF-HOST memory of what was shipped.
        "audit_sink_url": f"https://127.0.0.1:{args.port + 1}",
        "fencing_lease_path": str(etc / "lease.json"), "fencing_state_path": str(state / "epochs.jsonl"),
        "fencing_public_key_path": str(etc / "fence.pub")})
    check = run([str(binary), "-config", str(config), "-check-config"], env=env, check=False)
    if check.returncode != 0:
        die(f"-check-config refused the bench config: {(check.stderr or check.stdout).strip()[-900:]}")
    say("  -check-config passed")

    ctx = client(etc)
    daemon_log = work / "daemon.log"
    # The collector is another host in production; here, another process with its own state directory
    # that the wipe below does NOT touch.
    collector_state = work / "collector-state"
    collector_state.mkdir(mode=0o700)
    collector = subprocess.Popen([str(collector_bin), "-state", str(collector_state), "-listen", f"127.0.0.1:{args.port + 1}",
                                  "-tls-cert", str(etc / "collector.pem"), "-tls-key", str(etc / "collector.key"),
                                  "-client-ca", str(etc / "ca.pem")], stdout=open(work / "collector.log", "a"), stderr=subprocess.STDOUT)
    atexit.register(lambda: collector.poll() is None and collector.kill())
    time.sleep(2)
    if collector.poll() is not None:
        die(f"the audit collector did not start: {(work / 'collector.log').read_text()[-800:]}")
    say("  audit collector running (off-host memory, untouched by the wipe)")

    say("STEP 2 — serve: release the secret; a replayed nonce must be refused")
    daemon = Daemon(binary, config, env, daemon_log)
    try:
        if not wait_ready(ctx, args.port, daemon):
            die(f"the daemon did not become ready: {daemon_log.read_text()[-1200:]}")
        nonces = [f"drill-nonce-{uuid.uuid4().hex}" for _ in range(3)]
        for nonce in nonces:
            status, body = release(ctx, args.port, blob, nonce)
            if status != 200 or base64.b64decode(body.get("result_base64", "")) != secret:
                die(f"release failed: HTTP {status} {body}")
        say(f"  3 releases served, each byte-identical to the sealed secret")
        status, body = release(ctx, args.port, blob, nonces[0])
        if status != 409:
            die(f"a replayed nonce was not refused before the wipe: HTTP {status} {body}")
        say(f"  replayed nonce refused: HTTP 409 {body.get('code')}")
    finally:
        daemon.stop()
    for flag, path in (("-verify-audit", state / "audit.jsonl"), ("-verify-policy-state", state / "policy-state.jsonl")):
        say(f"  {flag}: {run([str(binary), flag, str(path)]).stdout.strip().splitlines()[-1]}")

    say("STEP 3 — export the control plane, sealed to the custody authority")
    run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(custody / "authority.key")])
    run(["openssl", "pkey", "-in", str(custody / "authority.key"), "-pubout", "-out", str(custody / "authority.pub")])
    export = custody / "site-export.bin"
    (etc / "deployment-version").write_text("regalia-kms control-plane drill\n")
    run([str(binary), "-config", str(config), "-export-control-plane", str(export),
         "-export-recipient-pem", str(custody / "authority.pub"), "-export-version-file", str(etc / "deployment-version")], env=env)
    say(f"  exported {export.stat().st_size} bytes")
    before_digest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in state.iterdir()}

    say("STEP 4 — WIPE: the host loses its state directory")
    shutil.rmtree(state)
    state.mkdir(mode=0o700)

    say("STEP 4b — the wiped host must NOT come back as if it were new: the collector remembers its history")
    daemon = Daemon(binary, config, env, daemon_log)
    try:
        came_up = wait_ready(ctx, args.port, daemon, seconds=60)
    finally:
        daemon.stop()
    if came_up:
        die("DEFECT: the daemon became ready on a WIPED host whose shipped history the collector remembers")
    tail = daemon_log.read_text()[-1500:]
    say("  refused to serve on the wiped state; last daemon line: " + [l for l in tail.splitlines() if l.strip()][-1][-220:])
    # Anything that refusing start-up created goes, so the restore meets absent targets (it never overwrites).
    shutil.rmtree(state)
    state.mkdir(mode=0o700)

    say("STEP 5 — inspect, restore, scan, verify")
    inspect = run([str(binary), "-inspect-export", str(export), "-authority-key-pem", str(custody / "authority.key"), "-expect-site", SITE])
    say("  " + inspect.stdout.strip().splitlines()[-2])
    restored = run([str(binary), "-restore-export", str(export), "-authority-key-pem", str(custody / "authority.key"),
                    "-expect-site", SITE, "-restore-root", "/"])
    for line in restored.stdout.strip().splitlines():
        say("  " + line)
    after_digest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in state.iterdir()}
    if after_digest != before_digest:
        die(f"the restored state differs from the exported one: {sorted(set(before_digest) ^ set(after_digest))}")
    say(f"  restored state is byte-identical to the state before the wipe ({len(after_digest)} files)")
    scan = run([str(binary), "-scan-tree", str(state)])
    say("  -scan-tree: " + scan.stdout.strip().splitlines()[-1])
    for flag, path in (("-verify-audit", state / "audit.jsonl"), ("-verify-policy-state", state / "policy-state.jsonl")):
        say(f"  {flag}: {run([str(binary), flag, str(path)]).stdout.strip().splitlines()[-1]}")

    say("STEP 6 — serve on the restored state: the OLD nonce is still refused; a new release works")
    daemon = Daemon(binary, config, env, daemon_log)
    try:
        if not wait_ready(ctx, args.port, daemon):
            die(f"the daemon did not become ready on the restored state: {daemon_log.read_text()[-1200:]}")
        status, body = release(ctx, args.port, blob, nonces[1])
        if status != 409:
            die(f"DEFECT: a nonce consumed BEFORE the wipe was accepted after the restore: HTTP {status} — history was not restored")
        say(f"  nonce consumed before the wipe is still refused: HTTP 409 {body.get('code')} — the history came back")
        status, body = release(ctx, args.port, blob, f"drill-nonce-{uuid.uuid4().hex}")
        if status != 200 or base64.b64decode(body.get("result_base64", "")) != secret:
            die(f"a new release failed on the restored state: HTTP {status} {body}")
        say("  a new release is served, byte-identical")
    finally:
        daemon.stop()
    say(f"  -verify-audit across the restore: {run([str(binary), '-verify-audit', str(state / 'audit.jsonl')]).stdout.strip().splitlines()[-1]}")
    collector.terminate()
    collector.wait(timeout=30)

    after = pin_tries(args.serial)
    say(f"PIN tries after: {after}")
    if after != before:
        die(f"the card's PIN counter moved: {before} -> {after}")
    for secret_file in (custody / "envelope-drill.json", custody / "authority.key", custody / "fence.key", etc / "card.pin"):
        secret_file.unlink(missing_ok=True)
    say("DRILL PASSED: served → exported → wiped → inspected and restored → the old nonce still refused, a new release served, the audit chain intact")
    (work / "transcript.log").write_text("\n".join(LOG) + "\n")


if __name__ == "__main__":
    main()
