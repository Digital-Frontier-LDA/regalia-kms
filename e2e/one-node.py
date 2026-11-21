#!/usr/bin/env python3
"""regalia-kms-dx7.10 (docs/design/single-node.md 8): ONE KMS node as a supported topology, end to end, on the fixture of the
three-node scenarios (e2e/lib/threenode.py) under Cluster(topology="single-node"): node a in its own namespace with its own
software TPM, its real services, a real LUKS2 volume, and the owner's machine beside it on the switch as its one unlock peer;
and the REAL regalia-kms daemon (SoftHSM token) judging a's admission against a's published chain.

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> REGALIA_AUDIT_BIN=<dir with regalia-audit-ship, regalia-audit-collector> \
    REGALIA_KMS_BIN=<built cmd/regalia-kms, -tags piv> \
        sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN,REGALIA_AUDIT_BIN,REGALIA_KMS_BIN python3 -Es e2e/one-node.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs only on a
GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

  1  genesis (dx7.2): epoch 1 of schema v5, topology single-node, made by manifest.propose_genesis with the signer rules from
     the topology (a alone heartbeats and activates, the owner alone revokes) and the owner's WireGuard key pinned (dx7.6);
     the shipped limits text printed verbatim and the acknowledgement phrase typed; another phrase refused; a holds the chain
  2  owner-assisted unlock (dx7.5) on swtpm + LUKS2: one owner path beside the recovery keyslot, its contribution written
     nowhere on the node; with no owner answering the disk stays locked although the TPM releases its half; the owner's
     machine answering over the boot tunnel (owner.serve_unlock, its key on SoftHSM): the real pre-root client opens the volume
     through the owner's keyslot, and the owner says it SENT a signed response
  3  self-lease serving (dx7.3): a's admission holds a lease a issued itself, in mode single; the daemon is ready, signs (the
     signature verifies under the token's key), refuses the same nonce again (409), and still refuses it after a restart
     (the spend is state, on disk, not memory)
  4  a refused survivor authorization (dx7.3): the owner's tool refuses to make one for the single-node chain, by name; one
     made by hand and installed where admission reads it is refused by survivor.verify_authorization, and a's admission keeps
     serving in mode single over its next renewals, never recovery
  5  owner revocation (dx7.4): the owner's revocation of a (owner.py sign-manifest, revoke.py import on a) is refused at
     import without the typed shutdown phrase, and committed with it (the phrase in a's sync trail); within ONE lease
     (lease.MAX_LIFETIME) the daemon refuses to sign and a's admission stops serving, its own lease refused naming the state
  6  TODO (dx7.7, dx7.8): the owner-chain re-anchor and the planned-outage update are not run here: printed as TODO, never
     counted as a pass, until those beads land and extend this scenario
  7  #340: every line of a's sync, admission and ESP-advance trail is in the audit collector, and the shutdown's commit is in
     a's sync stream
"""
import base64
import datetime
import hashlib
import http.client
import json
import os
import pathlib
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402
from deploy.baremetal import lease, membership, node, ownerunlock, revoke, survivor, unlock   # noqa: E402
from deploy.baremetal import manifest as manifest_tool   # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")
OBJECT, SITE, DEVICE, PRINCIPAL = "e2e1-signing-key", "e2e1-site", "softhsm-e2e1", "spiffe://regalia/workload/e2e1"
PORT, SINK = 18463, 18464                           # the daemon, and its own audit collector (the nodes' is COLLECTOR_PORT)
SOFTHSM = threenode.SOFTHSM


def ok(condition, text, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  \033[32mPASS\033[0m %s" % text)
    else:
        failed += 1
        print("  \033[31mFAIL\033[0m %s%s" % (text, (": %s" % (detail,)) if detail != "" else ""))
    sys.stdout.flush()


def todo(text):
    """A step this scenario does not run yet: said, and counted neither as a pass nor as a failure."""
    print("  \033[33mTODO\033[0m %s" % text, flush=True)


def header(text):
    print("\n\033[1m### %s\033[0m" % text, flush=True)


def refusal(fn, *args, **kw):
    """The text of the Refused `fn` raises, or None when it raises none."""
    try:
        fn(*args, **kw)
    except membership.Refused as refused:
        return str(refused)
    return None


def admission_trail(cluster, name):
    path = cluster.nodes[name].admission_log / "audit.jsonl"
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]
    except OSError:
        return []


class Daemon:
    """The real regalia-kms (REGALIA_KMS_BIN) for node a: a SoftHSM token with one P-256 key, a one-run PKI, and a
    configuration that requires runtime admission from a's admission file, judged against a's published chain under the
    pinned root (membership_chain_path), with its boot session from a's run directory. It runs as root in the host's network
    namespace on 127.0.0.1 (the node's namespace has nothing it needs: every file it reads is a's)."""

    def __init__(self, work):
        self.d = work / "kms"
        self.etc, self.state = self.d / "etc", self.d / "state"
        for d in (self.d, self.etc, self.state, self.state / "tokens"):
            d.mkdir(mode=0o700)
        self.env = dict(os.environ, SOFTHSM2_CONF=str(self.etc / "softhsm2.conf"))
        self.processes = []

    def token(self):
        """The daemon's token; returns its serial (the manifest names it for a)."""
        (self.etc / "softhsm2.conf").write_text("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n"
                                                % (self.state / "tokens"))
        self.pin = os.urandom(8).hex()
        sh("softhsm2-util", "--init-token", "--free", "--label", "regalia-e2e1", "--so-pin", os.urandom(8).hex(), "--pin", self.pin, env=self.env)
        tool = ["pkcs11-tool", "--module", SOFTHSM, "--token-label", "regalia-e2e1"]
        sh(*(tool + ["--login", "--pin", "env:P", "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", "regalia-e2e1", "--id", "01"]),
           env=dict(self.env, P=self.pin))
        sh(*(tool + ["--read-object", "--type", "pubkey", "--id", "01", "--output-file", str(self.d / "pub.der")]), env=self.env)
        sh("openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(self.d / "pub.der"), "-out", str(self.d / "pub.pem"))
        self.serial = next(line.split(":", 1)[1].strip() for line in sh(*(tool + ["--list-slots"]), env=self.env).stdout.splitlines()
                           if "serial num" in line)
        return self.serial

    def configure(self, cluster, name):
        n = cluster.nodes[name]
        etc = self.etc
        sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(etc / "ca.key"))
        sh("openssl", "req", "-new", "-x509", "-key", str(etc / "ca.key"), "-subj", "/CN=regalia e2e1 CA", "-days", "2", "-out", str(etc / "ca.pem"),
           "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
        for who, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature"),
                         ("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"),
                         ("client", "subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature" % PRINCIPAL)):
            sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(etc / (who + ".key")))
            sh("openssl", "req", "-new", "-key", str(etc / (who + ".key")), "-subj", "/CN=regalia e2e1 " + who, "-out", str(etc / (who + ".csr")))
            (etc / (who + ".ext")).write_text(ext + "\n")
            sh("openssl", "x509", "-req", "-in", str(etc / (who + ".csr")), "-CA", str(etc / "ca.pem"), "-CAkey", str(etc / "ca.key"), "-set_serial",
               str(int.from_bytes(os.urandom(8), "big")), "-days", "2", "-extfile", str(etc / (who + ".ext")), "-out", str(etc / (who + ".pem")))
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp, tomorrow = now.strftime("%Y-%m-%dT%H:%M:%SZ"), (now + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        keypin = "sha256:" + hashlib.sha256((self.d / "pub.der").read_bytes()).hexdigest()
        (etc / "card.pin").write_text(self.pin)
        (etc / "root-key.json").write_bytes(membership.canonical(threenode.hbt.pub(threenode.hbt.ROOT)))   # the image's pinned root
        documents = {
            "secure-channel.json": {"schema_version": 1, "devices": [{"device_serial": self.serial, "verified_by": "e2e", "verified_at": stamp,
                                                                       "expires_at": tomorrow, "firmware": "softhsm", "secure_messaging_established": True}]},
            "manifest.json": {"schema_version": 1, "manifest_id": "one-node-e2e", "generated_at": stamp, "objects": [{
                "id": OBJECT, "name": "E2E one-node P-256 signing key", "kind": "asymmetric-key", "classification": "restricted",
                "environment": "staging", "owner": "security", "purpose": "e2e-signing", "custody": "direct-hardware",
                "algorithm": "p256", "operations": ["sign"], "policy_id": "e2e1-sign",
                "bindings": [{"site": SITE, "backend": "nitrokey-pkcs11", "device_id": DEVICE, "device_serial": self.serial, "object_id": "01",
                              "public_key_sha256": keypin, "public_fingerprint": keypin, "state": "active"}],
                "recovery": {"mode": "shamir-4-of-6", "authority_id": "e2e", "minimum_replicas": 2, "status": "tested"},
                "rotation": {"maximum_age_days": 90, "last_rotated": None}, "migration": {"status": "migrated", "source": "e2e"},
                "verification": {"status": "verified", "last_verified": stamp[:10], "evidence": "e2e"}}]},
            "policy.json": {"schema_version": 1, "policies": [{"id": "e2e1-sign", "object_id": OBJECT, "purpose": "e2e-signing", "environment": "staging",
                                                               "operation": "sign", "algorithm": "p256", "content_types": ["application/vnd.regalia.digest"],
                                                               "max_payload_bytes": 32, "max_future_seconds": 300, "required_approvals": 0,
                                                               "approvers": ["spiffe://regalia/approver/e2e"]}]},
            "rbac.json": {"schema_version": 1, "principals": [{"uri": PRINCIPAL, "grants": [
                {"objects": [OBJECT], "operations": ["sign"], "environments": ["staging"]}]}]},
            "config.json": {
                "listen_address": "127.0.0.1:%d" % PORT, "site": SITE,
                "registry_path": str(etc / "manifest.json"), "rbac_policy_path": str(etc / "rbac.json"),
                "policy_path": str(etc / "policy.json"), "policy_state_path": str(self.state / "policy-state.jsonl"),
                "tls_certificate_path": str(etc / "server.pem"), "tls_private_key_path": str(etc / "server.key"), "tls_client_ca_path": str(etc / "ca.pem"),
                "pkcs11_module_path": SOFTHSM, "secure_channel_evidence_path": str(etc / "secure-channel.json"),
                "pin_paths": {DEVICE: str(etc / "card.pin")},
                "audit_journal_path": str(self.state / "audit.jsonl"), "audit_sink_url": "https://127.0.0.1:%d" % SINK,
                # what this scenario is about: a's admission, written by a's regalia-admission, judged against a's chain
                "runtime_admission": "required", "runtime_admission_path": str(n.run / "admission" / "admission.json"),
                "runtime_admission_owner": "regalia-admission", "node_id": name, "boot_session_path": str(n.run / "boot-session"),
                "membership_chain_path": str(n.state / node.PUBLISHED), "membership_chain_owner": "regalia-sync",
                "membership_root_key_path": str(etc / "root-key.json")},
        }
        for file, document in documents.items():
            (etc / file).write_text(json.dumps(document, indent=1) + "\n")
        for path in etc.iterdir():
            path.chmod(0o600)
        context = ssl.create_default_context(cafile=str(etc / "ca.pem"))
        context.load_cert_chain(str(etc / "client.pem"), str(etc / "client.key"))
        self.context = context

    def start(self):
        if not self.processes:
            collector = pathlib.Path(os.environ["REGALIA_AUDIT_BIN"]) / "regalia-audit-collector"
            (self.d / "collector").mkdir(mode=0o700, exist_ok=True)
            self.processes.append(subprocess.Popen([str(collector), "-state", str(self.d / "collector"), "-listen", "127.0.0.1:%d" % SINK,
                                                    "-tls-cert", str(self.etc / "collector.pem"), "-tls-key", str(self.etc / "collector.key"),
                                                    "-client-ca", str(self.etc / "ca.pem")],
                                                   stdout=open(self.d / "collector.log", "a"), stderr=subprocess.STDOUT))
            time.sleep(2)
        self.daemon = subprocess.Popen([os.environ["REGALIA_KMS_BIN"], "-config", str(self.etc / "config.json")], env=self.env,
                                       stdout=open(self.d / "daemon.log", "a"), stderr=subprocess.STDOUT)
        self.processes.append(self.daemon)

    def stop_daemon(self):
        self.daemon.send_signal(signal.SIGTERM)
        try:
            self.daemon.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.daemon.kill()
            self.daemon.wait()

    def close(self):
        for process in self.processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def call(self, method, path, body=None, nonce=None):
        connection = http.client.HTTPSConnection("127.0.0.1", PORT, context=self.context, timeout=60)
        headers = {"X-Request-ID": str(uuid.uuid4())}
        if body is not None:
            headers.update({"Content-Type": "application/json", "Idempotency-Key": nonce})
        try:
            connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()
        try:
            return response.status, json.loads(payload) if payload else {}
        except ValueError:
            return response.status, {"raw": payload.decode(errors="replace")}

    def ready(self):
        try:
            return self.call("GET", "/v1/health/ready")[0]
        except OSError:
            return None

    def wait_ready(self, want, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.daemon.poll() is not None:
                return "the daemon exited (%s)" % self.daemon.returncode
            if self.ready() == want:
                return want
            time.sleep(0.5)
        return self.ready()

    def sign(self, message, nonce=None):
        nonce = nonce or "e2e1-nonce-" + os.urandom(12).hex()
        expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=240)).strftime("%Y-%m-%dT%H:%M:%SZ")
        status, answer = self.call("POST", "/v1/operations/sign", {
            "object_id": OBJECT, "context": {"environment": "staging", "purpose": "e2e-signing", "expires_at": expires, "nonce": nonce},
            "content_type": "application/vnd.regalia.digest", "payload_base64": base64.b64encode(hashlib.sha256(message).digest()).decode()}, nonce)
        return status, answer, nonce

    def verifies(self, message, answer):
        try:
            raw = base64.b64decode(answer["result_base64"], validate=True)
        except (KeyError, TypeError, ValueError):
            return False

        def integer(value):
            value = value.lstrip(b"\x00") or b"\x00"
            value = (b"\x00" + value) if value[0] & 0x80 else value
            return b"\x02" + bytes([len(value)]) + value
        body = integer(raw[:32]) + integer(raw[32:])
        (self.d / "sig.der").write_bytes(b"\x30" + bytes([len(body)]) + body)
        (self.d / "message").write_bytes(message)
        return len(raw) == 64 and subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(self.d / "pub.pem"), "-signature",
                                                  str(self.d / "sig.der"), str(self.d / "message")], capture_output=True).returncode == 0

    def log(self, limit=1500):
        try:
            return (self.d / "daemon.log").read_text()[-limit:]
        except OSError:
            return ""


def scenario(cluster, kms):
    header("1  genesis: schema v5, topology single-node, the limits acknowledged")
    cluster.build()
    m1 = cluster.manifest
    ok(m1["schema"] == membership.SCHEMA_V5 and m1["topology"] == {"profile": membership.SINGLE_NODE, "nodes": 1,
                                                                    "single_node_limits_sha256": manifest_tool.SINGLE_NODE_LIMITS_SHA256}
       and m1["epoch"] == 1, "epoch 1 is schema v5 with topology single-node, 1 node, and the shipped limits text's SHA-256",
       {k: m1.get(k) for k in ("schema", "epoch", "topology")})
    ok({k: m1[k] for k in ("heartbeat_signers", "activation_signers", "revocation_signers")} ==
       {"heartbeat_signers": {"threshold": 1, "parties": ["a"]}, "activation_signers": {"threshold": 1, "parties": ["a"]},
        "revocation_signers": [{"threshold": 1, "parties": [membership.OWNER]}]} and m1["owner_wg_pub"] == cluster.owner_wg[1],
       "the signer rules are the topology's (a alone heartbeats and activates, the owner alone revokes) and the owner's "
       "WireGuard key is pinned", {k: m1.get(k) for k in ("heartbeat_signers", "activation_signers", "revocation_signers")})
    limits = manifest_tool.single_node_limits()
    phrase = manifest_tool.ACKNOWLEDGEMENT % manifest_tool.SINGLE_NODE_LIMITS_SHA256[:8]
    said = cluster.genesis_said
    ok(said[:1] == [limits[:-1] if limits.endswith("\n") else limits] and any(phrase in line for line in said[1:]),
       "the genesis printed the shipped limits text verbatim first, then asked for \"%s\"" % phrase, [line[:120] for line in said])
    wrong = refusal(manifest_tool.acknowledge_single_node, lambda prompt: "single node: I accept the limits 00000000", lambda text: None)
    ok(wrong is not None and "the acknowledgement typed is not" in wrong, "another phrase is refused, and nothing is written", wrong)
    with cluster.tpm_of("a"):
        held = cluster.node("a").store().load()
    ok(held["epoch"] == 1 and membership.profile(held) == membership.SINGLE_NODE and membership.digest(held) == membership.digest(m1),
       "a holds that genesis, verified from the pinned root, and reads its profile as single-node",
       {"epoch": held.get("epoch"), "profile": membership.profile(held)})

    header("2  owner-assisted unlock on swtpm + LUKS2")
    loop = cluster.disk("a")
    got = cluster.enrol("a")
    meta = unlock.luks_meta(loop)
    peers = sorted(t["peer"] for _, t in unlock.path_tokens(meta))
    ok(got == {"path_epoch": 1, "keyslot": 1} and sorted(meta["keyslots"]) == ["0", "1"] and peers == [unlock.OWNER],
       "enrolment made one owner path (keyslot 1) beside the recovery keyslot (0), and no peer path", {"got": got, "peers": peers})
    secret = ownerunlock.read_plaintext(cluster.owner_cards[cluster.owner_envelope])[2]
    forms, found = (secret, secret.hex().encode(), base64.b64encode(secret)), []
    keep, tail = max(len(f) for f in forms) - 1, b""
    with open(loop, "rb") as f:                       # in bounded chunks: a 32 MiB volume
        for chunk in iter(lambda: f.read(1 << 20), b""):
            window = tail + chunk
            found += [i for i, form in enumerate(forms) if form in window]
            tail = window[-keep:]
    ok(not found, "the owner's contribution is written nowhere on the node's volume (raw, hex or base64)", found)
    alone = cluster.unlock("a", timeout=90, rounds=1)          # the owner's machine is not answering
    ok(alone["rc"] not in (0, None) and alone["peer"] is None and not alone["marker"],
       "with no owner answering, the disk stays locked although the TPM releases its half", alone)
    cluster.stop("a")                                 # a new boot: the next initrd asks again, in a new TPM session
    with cluster.owner_answering("a") as owner_said:
        opened = cluster.unlock("a")
        ok(opened["rc"] == 0 and opened["peer"] == unlock.OWNER and opened["marker"],
           "with the owner's machine answering over the boot tunnel, the real pre-root client opens the volume through the "
           "owner's keyslot and its filesystem reads back", opened)
        sent = until(lambda: any(line.startswith("SENT: signed response") for line in owner_said), 15, 0.5)
    ok(bool(sent), "the owner's machine says it SENT a signed response to a (owner.py unlock)", owner_said[-6:])

    header("3  self-lease serving: mode single, a signature, a stateful spend")
    cluster.start("a", SERVICES)
    serving = until(lambda: cluster.lease("a"), 180, 3)
    ok(bool(serving) and serving.get("mode") == "single" and cluster.lease_issuer("a") == "a",
       "a's admission holds a lease a issued itself, in mode single", {"admission": serving, "issuer": cluster.lease_issuer("a"),
                                                                        "journal": cluster.journal("a", "admission")[-600:]})
    own = [e for e in admission_trail(cluster, "a") if e.get("event") == "admission-renew" and e.get("outcome") == "ALLOW"]
    ok(bool(own) and all(e.get("peer") == "a" for e in own), "every lease a renewed is its own (admission-renew ALLOW, peer a)", own[-3:])
    kms.configure(cluster, "a")
    kms.start()
    ready = kms.wait_ready(200, 90)
    ok(ready == 200, "the KMS daemon is READY on a's admission, judged against a's single-node chain", "%s | %s" % (ready, kms.log()))
    message = b"one node signs"
    status, answer, nonce = kms.sign(message)
    ok(status == 200 and kms.verifies(message, answer), "a sign request is served, and the signature verifies under the token's key",
       "%s %s" % (status, answer))
    again, answer2, _ = kms.sign(message, nonce)
    ok(again == 409, "the same nonce again is refused (409): the spend is held", "%s %s" % (again, answer2))
    kms.stop_daemon()
    kms.start()
    back = kms.wait_ready(200, 90)
    restarted, answer3, _ = kms.sign(message, nonce)
    ok(back == 200 and restarted == 409, "after a daemon restart the spent nonce is still refused (409): the spend is state",
       "%s %s %s | %s" % (back, restarted, answer3, kms.log()))

    header("4  a refused survivor authorization")
    tip = cluster.manifest
    asked = []
    made = refusal(survivor.make_authorization, tip, "a", "nothing to fence: one node", int(time.time()),
                   lambda text: asked.append(text) or "", lambda: cluster.owner_signer(0))
    ok(made is not None and "a survivor authorization is refused under the %s profile" % membership.SINGLE_NODE in made and not asked,
       "the owner's tool refuses to make a survivor authorization for the single-node chain, by name, before asking anything",
       {"refusal": made, "asked": asked})
    now = int(time.time())
    auth = {"schema": survivor.AUTH_SCHEMA, "node_id": "a", "quarantine_epoch": tip["epoch"], "quarantine_digest": membership.digest(tip),
            "not_before": survivor._stamp(now), "expires_at": survivor._stamp(now + 3600), "fenced": "made by hand, past the tool",
            "scope": "full", "fence": {"method": "attested", "nodes": {}}}
    signer = cluster.owner_signer(0)
    forged = {"authorization": auth, "signature": {"party": membership.OWNER, "key": signer.public(),
                                                   "sig": signer.sign(survivor.AUTH_DOMAIN + membership.canonical(auth)).hex()}}
    installed = cluster.nodes["a"].run / survivor.AUTH_FILE
    installed.write_text(json.dumps(forged))
    os.chmod(installed, 0o644)
    taken = refusal(survivor.verify_authorization, forged, tip, "a")
    ok(taken is not None and "a survivor authorization is refused under the %s profile" % membership.SINGLE_NODE in taken,
       "an owner-signed authorization made by hand is refused by survivor.verify_authorization, by name", taken)
    before, seen = (cluster.lease("a") or {}).get("lease_issued_at"), set()

    def renewed_since():
        doc = cluster.lease("a")
        if doc:
            seen.add(doc.get("mode"))                 # every admission file read meanwhile, by its mode
        return doc if doc and doc.get("lease_issued_at") != before else None
    renewed = until(renewed_since, lease.MAX_LIFETIME + 60, 1)
    status, answer, _ = kms.sign(b"still one node")
    ok(bool(renewed) and seen == {"single"} and status == 200,
       "with it installed, a's admission renews in mode single (no file in any other mode meanwhile) and the daemon still serves",
       {"admission": renewed, "modes": sorted(map(str, seen)), "sign": status})
    installed.unlink()

    header("5  owner revocation: the typed shutdown, and a stops within one lease")
    reason = "e2e: the owner revokes the only node"
    try:
        cluster.revoke_by_owner("a", "a", "REVOKED_STOLEN", reason)
        unphrased = None
    except RuntimeError as error:                     # the fixture's sh(): the unit's exit and its output
        unphrased = str(error)
    denied = [e for e in cluster.trail("a") if e.get("event") == "revoke-commit" and e.get("outcome") == "DENY"]
    ok(unphrased is not None and cluster.held_epoch("a") == 1 and any("shutdown phrase" in e.get("reason", "") for e in denied),
       "without the typed shutdown phrase the import is refused, and a stays at epoch 1", {"denied": denied[-1:], "said": (unphrased or "")[-300:]})
    phrase = revoke.shutdown_phrase("a")
    committed_at = time.time()
    cluster.revoke_by_owner("a", "a", "REVOKED_STOLEN", reason, shutdown=phrase)
    commits = [e for e in cluster.trail("a") if e.get("event") == "revoke-commit" and e.get("outcome") == "ALLOW"]
    ok(cluster.held_epoch("a") == 2 and commits and commits[-1].get("shutdown") == phrase and commits[-1].get("signers") == [membership.OWNER],
       "with \"%s\" typed, the owner's revocation is committed on a (epoch 2), the phrase in a's sync trail" % phrase, commits[-1:])
    refused = until(lambda: kms.sign(b"after the shutdown")[0] == 503, lease.MAX_LIFETIME, 1)
    took = time.time() - committed_at
    ok(bool(refused) and took <= lease.MAX_LIFETIME, "the daemon refuses to sign (503) within one lease of the commit (%.0f s; "
       "MAX_LIFETIME %d s)" % (took, lease.MAX_LIFETIME), kms.log())
    stopped = until(lambda: cluster.lease("a") is None, lease.MAX_LIFETIME + 5, 1)
    stop_took = time.time() - committed_at
    ok(bool(stopped) and stop_took <= lease.MAX_LIFETIME + 5, "a's admission stops serving within one lease of the commit (%.0f s)" % stop_took,
       cluster.journal("a", "admission")[-600:])
    print("  MEASURED: the owner's revocation of the only node -> the daemon refuses after %.0f s, admission stops after %.0f s "
          "(MAX_LIFETIME %d s)" % (took, stop_took, lease.MAX_LIFETIME), flush=True)
    named = until(lambda: [e for e in admission_trail(cluster, "a") if e.get("event") == "admission-renew" and e.get("outcome") == "DENY"
                           and "REVOKED_STOLEN" in e.get("reason", "")], 60, 2)
    ok(bool(named), "a's own lease is refused, naming its state (admission-renew DENY: REVOKED_STOLEN)", admission_trail(cluster, "a")[-3:])

    header("6  not here yet: dx7.7 and dx7.8 extend this scenario")
    # TODO(regalia-kms-dx7.7): the owner-chain re-anchor and recovery (recount floor) on this one node, once that bead lands
    todo("regalia-kms-dx7.7: re-anchor a from the owner's chain plus the collector (not run; not counted)")
    # TODO(regalia-kms-dx7.8): the rolling update under --planned-outage, retire evidence from the owner tool
    todo("regalia-kms-dx7.8: a planned-outage measured-boot update of a (not run; not counted)")

    header("7  #340: a's trails in the audit collector")
    wrong = cluster.audit_complete()
    ok(wrong == {}, "every line of a's sync, admission and ESP-advance trail is in the collector, chained from genesis",
       {"%s.%s" % k: v for k, v in wrong.items()})
    shutdown = cluster.audit_has("a", "sync", since=committed_at, event="revoke-commit", epoch=2, outcome="ALLOW", shutdown=phrase)
    ok(bool(shutdown), "the shutdown's commit, with its typed phrase, is in a's sync stream", shutdown[-1:] if shutdown else None)


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("one-node: refused: this changes the machine (namespaces, interfaces, loop devices, transient units). It runs on a "
              "GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH, "/run/netns/e2e3-a", "/run/netns/e2e3-owner") if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("one-node: refused: %s exists: another run's leftovers are here" % ", ".join(present))
        return 2
    needed = ("REGALIA_UNLOCK_BIN", "REGALIA_KMS_BIN")
    if os.geteuid() != 0 or not all(os.access(os.environ.get(v, "/nonexistent"), os.X_OK) for v in needed) or SOFTHSM is None:
        print("one-node: run as root, with REGALIA_UNLOCK_BIN and REGALIA_KMS_BIN naming built cmd/regalia-unlock and cmd/regalia-kms "
              "(-tags piv), REGALIA_AUDIT_BIN the audit binaries, and SoftHSM installed")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="one-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    os.chmod(work, 0o711)
    kms = Daemon(work)
    cluster = None
    try:
        cluster = threenode.Cluster(work, audit=True, topology=membership.SINGLE_NODE, hsm_serials={"a": [kms.token()]})
        scenario(cluster, kms)
    except Exception:                     # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-2000:])
        if cluster is not None:
            for service in ("sync", "admission"):
                print("----- a %s\n%s" % (service, cluster.journal("a", service)))
        print("----- the daemon\n%s" % kms.log(4000))
    finally:
        kms.close()
        if cluster is not None:
            cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\none-node: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
