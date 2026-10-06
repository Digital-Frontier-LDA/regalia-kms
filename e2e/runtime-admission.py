#!/usr/bin/env python3
"""runtime-admission.py — the REAL regalia-kms daemon serves key operations only while this node holds a
runtime lease (regalia-kms#74). The token is SoftHSM; the lease is real: node a re-attests to peer b on
software TPMs, b's TPM signs the lease, and deploy/baremetal/admission.py turns it into the admission file
the daemon reads. No hardware.

    python3 -Es e2e/runtime-admission.py

  1  no admission file yet: the daemon is up, NOT ready, and a sign request is a 503
  2  the lease service's first round: the node is admitted, the daemon is ready, and it returns a
     signature openssl verifies; the transition is in the audit journal
  3  renewal stops (the peer is unreachable) with the lease close to its end: the daemon serves until
     serve_until and then stops BY ITSELF, with nobody rewriting the file
  4  the peer is back: admitted again
  5  a file from another boot, with times that look valid, is refused
  6  the node is revoked: the next round writes serve_until 0 and the daemon refuses at once

Needs sudo, for one thing only: the boot session and the run directory must be root's, with nothing above
them anyone else could swap (the daemon refuses anything else), so they are placed with `sudo install`,
in a directory directly under /tmp. The lease service is played by the invoking user, as on a host it is
its own user (#191): the daemon is told so (runtime_admission_owner) and is given that user's directory
inside root's. The daemon itself runs as the invoking user too, and nothing is installed on the machine.
"""
import base64
import datetime
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

from deploy.baremetal import admission, lease                 # noqa: E402
from deploy.baremetal import membership as m                  # noqa: E402
import tests.test_baremetal_heartbeat as hbt                  # noqa: E402
import tests.test_baremetal_lease as lt                       # noqa: E402

SITE, DEVICE, OBJECT, PRINCIPAL = "e2e-site", "softhsm-e2e", "e2e-signing-key", "spiffe://regalia/workload/e2e"
passed, failed = 0, 0


def ok(condition, text, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  \033[32mPASS\033[0m %s" % text, flush=True)
    else:
        failed += 1
        print("  \033[31mFAIL\033[0m %s%s" % (text, (": " + str(detail)[:600]) if detail else ""), flush=True)


def header(text):
    print("\n\033[1m### %s\033[0m" % text, flush=True)


def die(text):
    print("runtime-admission: %s" % text, file=sys.stderr)
    sys.exit(2)


def run(argv, **kw):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, **kw)
    if done.returncode != 0:
        die("%s failed (%d): %s" % (" ".join(str(a) for a in argv[:3]), done.returncode, done.stderr.strip()[-600:]))
    return done.stdout


def main():
    for tool in ("go", "softhsm2-util", "pkcs11-tool", "openssl", "swtpm", "tpm2_createak", "tpm2_quote", "sudo"):
        if not shutil.which(tool):
            die("%s is required (go, softhsm2, opensc, openssl, swtpm, tpm2-tools, sudo)" % tool)
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        die("needs sudo, to place the root-owned admission file")
    module = next((c for c in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if os.path.exists(c)), None)
    if not module:
        die("libsofthsm2.so not found")

    w = Path(tempfile.mkdtemp(dir="/tmp"))               # 0700, this user's: only the root-owned run/ inside it is the gate's concern
    # root's run directory, directly under /tmp (root's, sticky): under this user's w/ it would not be
    # trusted, since this user could swap it
    etc, state, runtime = w / "etc", w / "state", Path("/tmp") / ("regalia-run-" + w.name)
    for d in (etc, state, state / "tokens", w / "collector"):
        d.mkdir(mode=0o700)
    processes = []
    fixture = lt.OnSwtpm("test_issue_hold_revoke_and_reboot_on_real_tpm_quotes")

    def cleanup():
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
        try:
            fixture.doCleanups()
        finally:
            subprocess.run(["sudo", "rm", "-rf", str(runtime)], capture_output=True)
            shutil.rmtree(w, ignore_errors=True)

    try:
        return scenario(w, etc, state, runtime, module, processes, fixture)
    finally:
        cleanup()


def scenario(w, etc, state, runtime, module, processes, fixture):
    # ---- build ---------------------------------------------------------------------------------------
    env = dict(os.environ, GOFLAGS=os.environ.get("GOFLAGS", ""))
    for name in ("regalia-kms", "regalia-audit-collector"):
        # the production build: with admission required, a daemon without PC/SC refuses to start (#72, G2)
        tags = ["-tags", "piv"] if name == "regalia-kms" else []
        run(["go", "-C", ROOT, "build", *tags, "-o", w / name, "./cmd/" + name], env=env)

    # ---- the token: SoftHSM, in the temporary state directory ------------------------------------------
    softhsm = dict(os.environ, SOFTHSM2_CONF=str(etc / "softhsm2.conf"))
    (etc / "softhsm2.conf").write_text("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n" % (state / "tokens"))
    pin = os.urandom(8).hex()
    run(["softhsm2-util", "--init-token", "--free", "--label", "regalia-e2e", "--so-pin", os.urandom(8).hex(), "--pin", pin], env=softhsm)
    token = ["pkcs11-tool", "--module", module, "--token-label", "regalia-e2e"]
    run(token + ["--login", "--pin", "env:P", "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", "regalia-e2e", "--id", "01"],
        env=dict(softhsm, P=pin))
    run(token + ["--read-object", "--type", "pubkey", "--id", "01", "--output-file", w / "pub.der"], env=softhsm)
    run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", w / "pub.der", "-out", w / "pub.pem"])
    serial = next(line.split(":", 1)[1].strip() for line in run(token + ["--list-slots"], env=softhsm).splitlines() if "serial num" in line)
    keypin = "sha256:" + hashlib.sha256((w / "pub.der").read_bytes()).hexdigest()
    (etc / "card.pin").write_text(pin)
    (etc / "card.pin").chmod(0o600)

    # ---- PKI: a CA, the daemon (also the audit client), the collector, one workload client --------------
    def ossl(*args):
        run(["openssl", *args])
    ossl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", etc / "ca.key")
    ossl("req", "-new", "-x509", "-key", etc / "ca.key", "-subj", "/CN=regalia e2e CA", "-days", "2", "-out", etc / "ca.pem",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    for name, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature"),
                      ("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"),
                      ("client", "subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature" % PRINCIPAL)):
        ossl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", etc / (name + ".key"))
        ossl("req", "-new", "-key", etc / (name + ".key"), "-subj", "/CN=regalia e2e " + name, "-out", etc / (name + ".csr"))
        (etc / (name + ".ext")).write_text(ext + "\n")
        ossl("x509", "-req", "-in", etc / (name + ".csr"), "-CA", etc / "ca.pem", "-CAkey", etc / "ca.key", "-set_serial",
             str(int.from_bytes(os.urandom(8), "big")), "-days", "2", "-extfile", etc / (name + ".ext"), "-out", etc / (name + ".pem"))

    # ---- the daemon's documents ------------------------------------------------------------------------
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp, tomorrow = now.strftime("%Y-%m-%dT%H:%M:%SZ"), (now + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    documents = {
        "secure-channel.json": {"schema_version": 1, "devices": [{"device_serial": serial, "verified_by": "e2e", "verified_at": stamp,
                                                                   "expires_at": tomorrow, "firmware": "softhsm", "secure_messaging_established": True}]},
        "manifest.json": {"schema_version": 1, "manifest_id": "runtime-admission-e2e", "generated_at": stamp, "objects": [{
            "id": OBJECT, "name": "E2E P-256 signing key", "kind": "asymmetric-key", "classification": "restricted",
            "environment": "staging", "owner": "security", "purpose": "e2e-signing", "custody": "direct-hardware",
            "algorithm": "p256", "operations": ["sign"], "policy_id": "e2e-sign",
            "bindings": [{"site": SITE, "backend": "nitrokey-pkcs11", "device_id": DEVICE, "device_serial": serial, "object_id": "01",
                          "public_key_sha256": keypin, "public_fingerprint": keypin, "state": "active"}],
            "recovery": {"mode": "shamir-4-of-6", "authority_id": "e2e", "minimum_replicas": 2, "status": "tested"},
            "rotation": {"maximum_age_days": 90, "last_rotated": None}, "migration": {"status": "migrated", "source": "e2e"},
            "verification": {"status": "verified", "last_verified": stamp[:10], "evidence": "e2e"}}]},
        "policy.json": {"schema_version": 1, "policies": [{"id": "e2e-sign", "object_id": OBJECT, "purpose": "e2e-signing", "environment": "staging",
                                                           "operation": "sign", "algorithm": "p256", "content_types": ["application/vnd.regalia.digest"],
                                                           "max_payload_bytes": 32, "max_future_seconds": 300, "required_approvals": 0,
                                                           "approvers": ["spiffe://regalia/approver/e2e"]}]},
        "rbac.json": {"schema_version": 1, "principals": [{"uri": PRINCIPAL, "grants": [
            {"objects": [OBJECT], "operations": ["sign"], "environments": ["staging"]}]}]},
    }
    port, sink = 18453, 18454
    documents["config.json"] = {
        "listen_address": "127.0.0.1:%d" % port, "site": SITE,
        "registry_path": str(etc / "manifest.json"), "rbac_policy_path": str(etc / "rbac.json"),
        "policy_path": str(etc / "policy.json"), "policy_state_path": str(state / "policy-state.jsonl"),
        "tls_certificate_path": str(etc / "server.pem"), "tls_private_key_path": str(etc / "server.key"), "tls_client_ca_path": str(etc / "ca.pem"),
        "pkcs11_module_path": module, "secure_channel_evidence_path": str(etc / "secure-channel.json"),
        "pin_paths": {DEVICE: str(etc / "card.pin")},
        "audit_journal_path": str(state / "audit.jsonl"), "audit_sink_url": "https://127.0.0.1:%d" % sink,
        # what this test is about: the node is "a", as the membership manifest spells it
        "runtime_admission": "required", "runtime_admission_path": str(runtime / "admission" / "admission.json"),
        "runtime_admission_owner": pwd.getpwuid(os.getuid()).pw_name,
        "node_id": "a", "boot_session_path": str(runtime / "boot-session")}
    for name, document in documents.items():
        (etc / name).write_text(json.dumps(document, indent=1) + "\n")
    for path in etc.iterdir():
        path.chmod(0o600)

    # ---- root's directory: the admission file and this boot's session -----------------------------------
    def as_root(source, name):
        """Place a file as the root lease service does: whole, root's, readable by the daemon."""
        run(["sudo", "install", "-m", "0644", "-o", "root", "-g", "root", source, runtime / ("." + name + ".new")])
        run(["sudo", "mv", "-f", runtime / ("." + name + ".new"), runtime / name])
    run(["sudo", "install", "-d", "-m", "0755", "-o", "root", "-g", "root", runtime])
    # the lease service's own directory inside root's, as regalia.tmpfiles.conf makes it on a host
    run(["sudo", "install", "-d", "-m", "0755", "-o", str(os.getuid()), "-g", str(os.getgid()), runtime / "admission"])
    (w / "boot-session").write_text(lt.SESSION + "\n")
    as_root(w / "boot-session", "boot-session")

    # ---- the collector and the daemon -------------------------------------------------------------------
    processes.append(subprocess.Popen([str(w / "regalia-audit-collector"), "-state", str(w / "collector"), "-listen", "127.0.0.1:%d" % sink,
                                       "-tls-cert", str(etc / "collector.pem"), "-tls-key", str(etc / "collector.key"), "-client-ca", str(etc / "ca.pem")],
                                      stdout=open(w / "collector.log", "w"), stderr=subprocess.STDOUT))
    time.sleep(2)
    daemon = subprocess.Popen([str(w / "regalia-kms"), "-config", str(etc / "config.json")], env=softhsm,
                              stdout=open(w / "daemon.log", "w"), stderr=subprocess.STDOUT)
    processes.append(daemon)
    context = ssl.create_default_context(cafile=str(etc / "ca.pem"))
    context.load_cert_chain(str(etc / "client.pem"), str(etc / "client.key"))

    def call(method, path, body=None, nonce=None):
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=60)
        headers = {"X-Request-ID": str(uuid.uuid4())}
        if body is not None:
            headers.update({"Content-Type": "application/json", "Idempotency-Key": nonce})
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        try:
            return response.status, json.loads(payload) if payload else {}
        except ValueError:
            return response.status, {"raw": payload.decode(errors="replace")}

    def ready():
        try:
            return call("GET", "/v1/health/ready")[0]
        except OSError:
            return None

    def sign(message):
        nonce = "e2e-nonce-" + os.urandom(12).hex()
        expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return call("POST", "/v1/operations/sign", {
            "object_id": OBJECT, "context": {"environment": "staging", "purpose": "e2e-signing", "expires_at": expires, "nonce": nonce},
            "content_type": "application/vnd.regalia.digest", "payload_base64": base64.b64encode(hashlib.sha256(message).digest()).decode()}, nonce)

    def verifies(message, result):
        raw = base64.b64decode(result["result_base64"], validate=True)

        def integer(value):
            value = value.lstrip(b"\x00") or b"\x00"
            value = (b"\x00" + value) if value[0] & 0x80 else value
            return b"\x02" + bytes([len(value)]) + value
        body = integer(raw[:32]) + integer(raw[32:])
        (w / "sig.der").write_bytes(b"\x30" + bytes([len(body)]) + body)
        (w / "message").write_bytes(message)
        return len(raw) == 64 and subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(w / "pub.pem"), "-signature", str(w / "sig.der"),
                                                  str(w / "message")], capture_output=True).returncode == 0

    def wait_for(want, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if daemon.poll() is not None:
                return "the daemon exited (%s)" % daemon.returncode
            if ready() == want:
                return want
            time.sleep(0.5)
        return ready()

    def journal():
        try:
            return (state / "audit.jsonl").read_text()
        except OSError:
            return ""

    def log():
        return (w / "daemon.log").read_text()

    # ---- 1 ------------------------------------------------------------------------------------------------
    header("1  no admission file yet: up, not ready, and no key operation")
    status = wait_for(503, 60)
    ok(status == 503 and daemon.poll() is None, "the daemon started with no admission file and reports NOT ready (503)", "%s\n%s" % (status, log()[-900:]))
    status, answer = sign(b"before any lease")
    ok(status == 503 and answer.get("error", {}).get("code", answer.get("code")) == "DEPENDENCY_UNAVAILABLE",
       "a sign request is refused: 503 DEPENDENCY_UNAVAILABLE", "%s %s" % (status, answer))
    ok('"outcome":"not-admitted"' in journal().replace(" ", ""), "the audit journal records the refusal as not-admitted", journal()[-400:])
    ok("NOT admitted" in log() and "the admission file" in log(), "the daemon's log says why: there is no admission file")

    # ---- the lease side: node a and peer b on software TPMs (the fixture of tests/test_baremetal_lease.py) -------
    fixture.hsm_serials = {"a": [serial]}   # the daemon serves only from a token the manifest lists for this node (#72 G1)
    fixture.setUp()
    world = {"manifest": fixture.m1, "peer_up": True}
    holder = lease.Holder("a", lt.SESSION, fixture.clock, hbt.simulated_ticks(fixture, fixture.tcti["a"]), str(w / "holder.json"))

    def renew(request):
        if not world["peer_up"]:
            raise ConnectionError("peer b is unreachable")
        manifest = world["manifest"]
        return lease.issue(manifest, "b", request, fixture.attester, fixture.evidence(lt.SESSION, manifest), fixture.freshness, fixture.signer)
    # As on a host: the service knows when the daemon's process started, from the kernel, by its PID.
    def daemon_started():
        return admission.process_started_ms(daemon.pid)
    service = admission.Service(holder, lambda: world["manifest"], renew, str(runtime / "admission" / "admission.json"), daemon_started=daemon_started)

    def round_():
        """One round of the lease service, which writes its file itself, as its own user."""
        return service.step()

    # ---- 2 ------------------------------------------------------------------------------------------------
    header("2  the lease service's first round: admitted, ready, serving")
    document = round_()
    left = (document["serve_until_boottime_ms"] - admission.boottime_ms()) / 1000
    full = lease.MAX_LIFETIME - admission.MARGIN
    ok(document["serve_until_boottime_ms"] > 0 and full - 10 <= left <= full,
       "a lease from b's TPM became an admission of %.0f s (%d s less the margin)" % (left, lease.MAX_LIFETIME), document)
    status = wait_for(200, 20)
    ok(status == 200, "the daemon is ready (200)", "%s\n%s" % (status, log()[-600:]))
    message = b"regalia-kms runtime admission e2e " + stamp.encode()
    status, answer = sign(message)
    ok(status == 200 and verifies(message, answer), "POST /v1/operations/sign: 200, and openssl verifies the signature against the token's key", "%s %s" % (status, answer))
    ok(not verifies(message + b"!", answer) if status == 200 else False, "an altered message does not verify")
    compact = journal().replace(" ", "")
    ok('"operation":"runtime-admission"' in compact and '"outcome":"admitted"' in compact and '"purpose":"epoch-1"' in compact,
       "the transition is in the audit journal: runtime-admission, admitted, epoch-1")

    # ---- 3 ------------------------------------------------------------------------------------------------
    header("3  renewal stops near the lease's end: the daemon stops by itself at serve_until")
    world["peer_up"] = False
    fixture.now += lease.MAX_LIFETIME - (admission.MARGIN + 12)   # authenticated time: the lease has 12 s left after the margin
    document = round_()
    left = (document["serve_until_boottime_ms"] - admission.boottime_ms()) / 1000
    ok(0 < left <= 12, "the peer is unreachable; the admission now ends in %.0f s and nobody will rewrite it" % left, document)
    status, answer = sign(b"still inside the lease")
    ok(status == 200, "inside the lease the daemon still serves", "%s %s" % (status, answer))
    time.sleep(max(left, 0) + 1.5)
    status, answer = sign(b"after the lease")
    ok(status == 503, "after serve_until the same daemon refuses, with the file untouched (503)", "%s %s" % (status, answer))
    ok(ready() == 503, "and reports not ready")
    ok("the admission ran out" in log(), "the daemon's log: the admission ran out")

    # ---- 4 ------------------------------------------------------------------------------------------------
    header("4  the peer is back: admitted again")
    world["peer_up"] = True
    fixture.now += 30
    document = round_()
    ok(document["serve_until_boottime_ms"] > admission.boottime_ms() and document["requested_boottime_ms"] > 0, "a new lease, asked for just now", document)
    ok(wait_for(200, 20) == 200, "the daemon is ready again")
    status, answer = sign(b"renewed")
    ok(status == 200, "and serves", "%s %s" % (status, answer))

    # ---- 4b: the daemon restarts (#72: every token is "just arrived" for a new process) ------------------------
    header("4b the daemon restarts: it waits for a lease asked for since, and the lease service asks at once")
    before = round_()                                    # a fresh lease, nowhere near its scheduled renewal
    daemon.terminate()
    daemon.wait(timeout=30)
    daemon = subprocess.Popen([str(w / "regalia-kms"), "-config", str(etc / "config.json")], env=softhsm,
                                 stdout=open(w / "daemon.log", "a"), stderr=subprocess.STDOUT)
    processes.append(daemon)                             # every helper above now means the new process
    started = None
    for _ in range(150):                                 # until it listens: "not ready" is an answer, no answer is not
        if ready() is not None:
            started = admission.process_started_ms(daemon.pid)
            break
        time.sleep(0.2)
    ok(started is not None and started > before["requested_boottime_ms"], "the new daemon started after the held lease was asked for", (started, before))
    status, answer = sign(b"new process, old lease")
    ok(status == 503 and ready() == 503, "the admission file is still valid, yet the new daemon serves nothing on that lease (503, not ready)", "%s %s" % (status, answer))
    service.daemon_started = None                        # a lease service that does not look at the daemon: its schedule says "not yet"
    unchanged = round_()
    ok(unchanged["requested_boottime_ms"] == before["requested_boottime_ms"] and ready() == 503,
       "left to the schedule, the lease is not renewed and the daemon keeps waiting", unchanged)
    service.daemon_started = daemon_started
    document = round_()
    ok(document["requested_boottime_ms"] > started, "the lease service sees the daemon's start and asks at once", (document, started))
    ok(wait_for(200, 20) == 200, "the daemon is ready again, without waiting for the scheduled renewal")
    status, answer = sign(b"new process, new lease")
    ok(status == 200, "and signs", "%s %s" % (status, answer))

    # ---- 5 ------------------------------------------------------------------------------------------------
    header("5  a file from another boot is refused, whatever its times say")
    ok(ready() == 200, "(admitted before the file is swapped)")
    forged = dict(document, boot_id="0f3a9c1e-1111-4222-8333-444455556666", serve_until_boottime_ms=admission.boottime_ms() + 200_000,
                  requested_boottime_ms=1, lease_issued_at=stamp, reason="")
    admission.write(str(runtime / "admission" / "admission.json"), forged)
    status, answer = sign(b"another boot")
    ok(status == 503 and ready() == 503, "refused (503), not ready", "%s %s" % (status, answer))
    ok("from another boot" in log(), "the daemon's log: the admission file is from another boot")
    round_()                                             # the lease service's next round puts the real file back
    ok(wait_for(200, 20) == 200, "the lease service's next round restores the real file, and the daemon is ready again")

    # ---- 6 ------------------------------------------------------------------------------------------------
    header("6  the node is revoked: the next round writes zero and the daemon refuses at once")
    revoked = fixture.manifest(2, m.digest(fixture.m1), a="REVOKED_STOLEN")
    fixture.freshness.accept(hbt.beat(revoked, 2, issued=fixture.now), revoked)   # peer b holds the revoking manifest and a heartbeat for it
    world["manifest"] = revoked                                                    # ... and it has reached node a
    document = round_()
    ok(document["serve_until_boottime_ms"] == 0 and "a may not serve under epoch 2 (REVOKED_STOLEN)" in document["reason"],
       "the lease service writes serve_until 0 with the reason", document)
    status, answer = sign(b"revoked")
    ok(status == 503, "the daemon refuses the very next request (503), minutes before the old lease would have run out", "%s %s" % (status, answer))
    ok(ready() == 503, "and reports not ready")
    ok("a may not serve under epoch 2 (REVOKED_STOLEN)" in log(), "the daemon's log carries the lease service's reason")
    ok('"purpose":"epoch-2"' in journal().replace(" ", ""), "the audit journal has the transition under epoch 2")

    print("\nruntime-admission: %d passed, %d failed" % (passed, failed))
    if failed:
        print("--- daemon log (tail) ---\n" + log()[-3000:])
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
