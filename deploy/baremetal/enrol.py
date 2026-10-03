"""regalia-node enrol, phase 1: `init` makes this host's keys, on this host, and prints what the
manifest ceremony needs to name it (#190).

    sudo python3 -Es -m deploy.baremetal.enrol init --node-id a

WHAT IT MAKES, each on the host and never imported (ADR-0002 D5's rule, applied to node keys):
  * the EK and a restricted signing AK, persistent in the TPM (attest.node_init, 0x81010001/0x81010002);
  * the WG-SERVICE key, /etc/regalia/wg-service.key, root 0600;
  * the WG-BOOT key, kept root 0600 in the enrolment directory until `commit` seals it to this TPM.
The local unlock contribution is NOT made here: it is made and sealed in one step at `commit`, so it is
never on disk in the clear between the two phases.

WHAT IT PRINTS: the identity bundle (bundle.json in the enrolment directory), public values only: the EK
and AK public areas and Names, the EK certificate when the TPM carries one (checked here to certify THIS
EK; the ceremony verifies it to the manufacturer's CA), both WireGuard public keys, and the TPM's
firmware version. Without an EK certificate, the EK Name and its SHA-256 are shown on screen, to be copied
by hand to the ceremony (the fallback the ceremony records).

WHAT IT REFUSES: a persistent object at the EK or AK handle, or a WG-SERVICE key, that this enrolment did
not make. A host that was enrolled is re-enrolled only as a new node, through replacement (#76).

A CRASH AT ANY STEP: every step is recorded in the journal (journal.json, root, in a 0700 directory)
as started before it acts and as done, with what it produced, after. Run `init` again: a done step is
checked against what it recorded and skipped; a step that started and did not finish has produced
nothing anyone has seen yet, so its outputs at OUR handles and paths are removed and it runs again.
Nothing else is ever removed.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

from deploy.baremetal import attest

SCHEMA_JOURNAL = "regalia.enrol-journal/v1"
SCHEMA_BUNDLE = "regalia.enrol-bundle/v1"
ENROL_DIR = "/var/lib/regalia-enrol"
WG_SERVICE_KEY = "/etc/regalia/wg-service.key"
EK_CERT_INDICES = ("0x01c00002", "0x01c0000a")       # TCG EK credential profile: RSA 2048, ECC P-256
NODE_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
WG_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


def _write_private(path, data, exclusive=True):
    """data to path, 0600, fsynced; with exclusive, a file already there is a refusal, not a replacement."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path, value):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".journal-")
    try:
        os.write(fd, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class Journal:
    def __init__(self, directory, node_id):
        self.path = os.path.join(directory, "journal.json")
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.doc = json.load(f)
            require(self.doc.get("schema") == SCHEMA_JOURNAL, "%s is not an enrolment journal" % self.path)
            require(self.doc.get("node_id") == node_id,
                    "this host's enrolment was started as node %r, not %r: one host is one node (replacement is #76)"
                    % (self.doc.get("node_id"), node_id))
        else:
            self.doc = {"schema": SCHEMA_JOURNAL, "node_id": node_id, "steps": {}}
            _atomic_json(self.path, self.doc)

    def state(self, step):
        return self.doc["steps"].get(step, {}).get("state")

    def get(self, step):
        return self.doc["steps"].get(step, {})

    def started(self, step):
        self.doc["steps"][step] = {"state": "started", "at": int(time.time())}
        _atomic_json(self.path, self.doc)

    def done(self, step, **facts):
        self.doc["steps"][step] = dict(facts, state="done", at=int(time.time()))
        _atomic_json(self.path, self.doc)


def _run(argv, run, check=True, **kwargs):
    done = run(argv, capture_output=True, **kwargs)
    if check:
        err = done.stderr if isinstance(done.stderr, str) else (done.stderr or b"").decode(errors="replace")
        require(done.returncode == 0, "%s failed: %s" % (argv[0], err.strip()[-300:]))
    return done


def persistent_handles(run):
    out = _run(["tpm2_getcap", "handles-persistent"], run, text=True).stdout
    return {h.lower() for h in re.findall(r"0x[0-9a-fA-F]{8}", out)}


def _evict(handle, run):
    _run(["tpm2_evictcontrol", "-C", "o", "-c", handle], run, text=True)


def identity(journal, directory, run):
    """The EK and AK, persistent; their public areas in the enrolment directory."""
    ours = {attest.EK_HANDLE.lower(), attest.AK_HANDLE.lower()}
    if journal.state("identity") == "done":
        facts = journal.get("identity")
        for k in ("ek", "ak"):
            with open(os.path.join(directory, k + ".pub"), "rb") as f:
                require(attest.name_of(attest.public_area(f.read(), k)).hex() == facts[k + "_name"],
                        "%s.pub no longer matches the journal" % k)
        require(ours <= persistent_handles(run), "the EK or AK this enrolment made is no longer in the TPM")
        return facts
    present = ours & persistent_handles(run)
    if journal.state("identity") == "started":
        for handle in sorted(present):          # ours, and nobody has seen them yet: made again
            _evict(handle, run)
        for k in ("ek", "ak"):
            p = os.path.join(directory, k + ".pub")
            if os.path.exists(p):
                os.unlink(p)
    else:
        require(not present, "the TPM already holds a persistent object at %s, which this enrolment did not make. "
                "A host that was enrolled is re-enrolled only as a new node, through replacement (#76)"
                % ", ".join(sorted(present)))
    journal.started("identity")
    attest.node_init(directory, run=run)
    facts = {}
    for k in ("ek", "ak"):
        with open(os.path.join(directory, k + ".pub"), "rb") as f:
            blob = f.read()
        facts[k + "_public"] = blob.hex()
        facts[k + "_name"] = attest.name_of(attest.public_area(blob, k)).hex()
    journal.done("identity", **facts)
    return facts


def ek_certificate(journal, directory, run):
    """The TPM's EK certificate, when it carries one, checked to certify THIS EK. Not a trust decision: the
    ceremony verifies it to the manufacturer's CA."""
    if journal.state("ek_certificate") == "done":
        return journal.get("ek_certificate")
    journal.started("ek_certificate")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _run(["tpm2_readpublic", "-c", attest.EK_HANDLE, "-f", "pem", "-o", os.path.join(directory, "ek.pem")], run, text=True)
    with open(os.path.join(directory, "ek.pem"), "rb") as f:
        ek_spki = serialization.load_pem_public_key(f.read()).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    found = None
    for index in EK_CERT_INDICES:
        done = _run(["tpm2_nvread", index, "-o", os.path.join(directory, "ek-cert.der")], run, check=False, text=True)
        if done.returncode != 0:
            continue
        with open(os.path.join(directory, "ek-cert.der"), "rb") as f:
            raw = f.read()
        try:
            cert = x509.load_der_x509_certificate(raw.rstrip(b"\x00") if raw.endswith(b"\x00") else raw)
        except ValueError:
            continue
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if spki == ek_spki:
            found = {"index": index, "der": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
                     "issuer": cert.issuer.rfc4514_string(), "certifies_this_ek": True}
            break
        require(False, "the EK certificate at %s certifies another key than this TPM's EK: refused, the ceremony "
                "could not tell this TPM from another" % index)
    facts = {"certificate": found}
    journal.done("ek_certificate", **facts)
    return facts


def _wg_pair(run):
    private = _run(["wg", "genkey"], run, text=True).stdout.strip()
    require(WG_KEY.fullmatch(private), "wg genkey gave no key")
    public = _run(["wg", "pubkey"], run, text=True, input=private + "\n").stdout.strip()
    require(WG_KEY.fullmatch(public), "wg pubkey gave no key")
    return private, public


def _wg_public_of(path, run):
    with open(path) as f:
        private = f.read().strip()
    require(WG_KEY.fullmatch(private), "%s does not hold a WireGuard key" % path)
    return _run(["wg", "pubkey"], run, text=True, input=private + "\n").stdout.strip()


def wg_key(journal, step, path, run):
    if journal.state(step) == "done":
        recorded = journal.get(step)["public"]
        require(os.path.exists(path) and _wg_public_of(path, run) == recorded,
                "%s no longer holds the key this enrolment made" % path)
        return recorded
    if journal.state(step) == "started":
        if os.path.exists(path):
            os.unlink(path)                      # ours, and its public half was never shown to anyone
    else:
        require(not os.path.exists(path), "%s already exists and this enrolment did not make it. A host that was "
                "enrolled is re-enrolled only as a new node, through replacement (#76)" % path)
    journal.started(step)
    private, public = _wg_pair(run)
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    _write_private(path, (private + "\n").encode())
    journal.done(step, public=public, path=path)
    return public


def firmware_version(run):
    out = _run(["tpm2_getcap", "properties-fixed"], run, text=True).stdout
    words = []
    for name in ("TPM2_PT_FIRMWARE_VERSION_1", "TPM2_PT_FIRMWARE_VERSION_2"):
        m = re.search(name + r":\s*\n?\s*raw:\s*(0x[0-9a-fA-F]+)", out)
        words.append(int(m.group(1), 16) if m else None)
    return "%08x%08x" % tuple(words) if None not in words else None


def init(node_id, directory=ENROL_DIR, wg_service_key=WG_SERVICE_KEY, run=subprocess.run, out=sys.stdout):
    require(NODE_ID.fullmatch(node_id or ""), "a node ID is a lower-case name, such as a")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    journal = Journal(directory, node_id)
    ids = identity(journal, directory, run)
    cert = ek_certificate(journal, directory, run)
    service = wg_key(journal, "wg_service", wg_service_key, run)
    boot = wg_key(journal, "wg_boot", os.path.join(directory, "wg-boot.key"), run)
    bundle = {"schema": SCHEMA_BUNDLE, "node_id": node_id,
              "ek_public": ids["ek_public"], "ek_name": ids["ek_name"],
              "ak_public": ids["ak_public"], "ak_name": ids["ak_name"],
              "ek_certificate": cert["certificate"],
              "wg_service_pub": service, "wg_boot_pub": boot,
              "tpm_firmware_version": firmware_version(run)}
    _atomic_json(os.path.join(directory, "bundle.json"), bundle)
    os.chmod(os.path.join(directory, "bundle.json"), 0o644)
    print("ENROL INIT: node %s, identity bundle %s (public values only; take it to the manifest ceremony)"
          % (node_id, os.path.join(directory, "bundle.json")), file=out)
    if cert["certificate"] is None:
        print("NO EK CERTIFICATE in this TPM. Copy BY HAND to the ceremony:\n  EK Name   %s\n  sha256    %s"
              % (ids["ek_name"], hashlib.sha256(bytes.fromhex(ids["ek_name"])).hexdigest()), file=out)
    else:
        print("EK certificate from %s, issued by %s; it certifies this TPM's EK (the ceremony verifies the issuer)"
              % (cert["certificate"]["index"], cert["certificate"]["issuer"]), file=out)
    return bundle


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.enrol", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="make this host's keys and print its identity bundle")
    p.add_argument("--node-id", required=True)
    p.add_argument("--enrol-dir", default=ENROL_DIR)
    p.add_argument("--wg-service-key", default=WG_SERVICE_KEY)
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("REFUSED: enrolment runs as root, at the host's console", file=sys.stderr)
        return 2
    try:
        init(args.node_id, args.enrol_dir, args.wg_service_key)
    except (Refused, attest.Refused, OSError) as error:
        print("REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
