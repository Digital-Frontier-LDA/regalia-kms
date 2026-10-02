"""Disposable software-only bootstrap experiments; never production evidence."""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def run(*args, env=None, data=None, required=True):
    result = subprocess.run(list(map(str, args)), input=data, env=env,
                            capture_output=True, timeout=60)
    if required and result.returncode:
        # Output can contain plaintext unsealed material. Never include it in errors.
        raise RuntimeError(f"{args[0]} failed (exit {result.returncode})")
    return result


def tpm_refused(result, expected_code):
    """Do not count a transport/tool failure as a successful security refusal."""
    codes = [int(value, 16) for value in re.findall(rb"0x[0-9a-fA-F]+", result.stderr)]
    if result.returncode != 1 or expected_code not in codes:
        raise RuntimeError(f"expected TPM refusal {expected_code:#x} was not observed")
    return True


class TPM:
    def __init__(self, root, name):
        self.root = root / name
        self.root.mkdir(mode=0o700)
        self.name = name
        self.process = None
        self.socket = self.root / "tpm.sock"
        self.env = dict(os.environ, TPM2TOOLS_TCTI=f"swtpm:path={self.socket}")

    def start(self, provision=True):
        seccomp = os.environ.get("REGALIA_LAB_SWTPM_SECCOMP", "kill")
        if seccomp not in ["kill", "none"]:
            raise ValueError("lab swtpm seccomp must be kill or none")
        state = self.root / "state"
        state.mkdir(exist_ok=not provision)
        self.process = subprocess.Popen([
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
            "--server", f"type=unixio,path={self.socket}",
            "--ctrl", f"type=unixio,path={self.socket}.ctrl",
            "--flags", "not-need-init,startup-clear",
            "--seccomp", f"action={seccomp}",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.process.poll() is not None:
                raise RuntimeError(f"swtpm {self.name} exited before startup")
            if self.socket.exists() and self.call("tpm2_getcap", "properties-fixed", required=False).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"swtpm {self.name} startup timed out")
        if not provision:
            return
        self.call("tpm2_createek", "-G", "rsa", "-c", "0x81010001", "-Q")
        self.call("tpm2_createak", "-C", "0x81010001", "-G", "rsa", "-g", "sha256",
                  "-s", "rsassa", "-c", self.root / "ak.ctx", "-u", self.root / "ak.pem", "-f", "pem", "-Q")
        self.call("tpm2_evictcontrol", "-C", "o", "-c", self.root / "ak.ctx", "0x81010002", "-Q")
        self.call("tpm2_flushcontext", "-t")

    def restart(self):
        self.close()
        self.socket.unlink(missing_ok=True)
        Path(str(self.socket) + ".ctrl").unlink(missing_ok=True)
        self.start(provision=False)

    def call(self, *args, **kwargs):
        return run(*args, env=self.env, **kwargs)

    def quote(self, challenge, prefix, selection="sha256:7"):
        paths = [self.root / f"{prefix}.{suffix}" for suffix in ["msg", "sig", "pcrs"]]
        self.call("tpm2_quote", "-c", "0x81010002", "-l", selection, "-q", challenge.hex(),
                  "-m", paths[0], "-s", paths[1], "-o", paths[2], "-F", "values", "-g", "sha256", "-Q")
        return paths

    def prepare_storage(self):
        self.call("tpm2_createprimary", "-C", "o", "-G", "rsa", "-c", self.root / "storage.ctx", "-Q")
        self.call("tpm2_evictcontrol", "-C", "o", "-c", self.root / "storage.ctx", "0x81010003", "-Q")
        self.call("tpm2_flushcontext", "-t")
        self.call("tpm2_pcrread", "sha256:7", "-o", self.root / "approved.pcr", "-Q")
        self.call("tpm2_createpolicy", "--policy-pcr", "-l", "sha256:7", "-L", self.root / "pcr.policy", "-Q")

    def seal(self, name, secret, handle):
        self.call("tpm2_create", "-C", "0x81010003", "-L", self.root / "pcr.policy", "-i", "-",
                  "-u", self.root / f"{name}.pub", "-r", self.root / f"{name}.priv",
                  "-c", self.root / f"{name}.ctx", "-Q", data=secret)
        self.call("tpm2_evictcontrol", "-C", "o", "-c", self.root / f"{name}.ctx", handle, "-Q")
        self.call("tpm2_flushcontext", "-t")

    def unseal(self, handle):
        return self.call("tpm2_unseal", "-c", handle, "-p", "pcr:sha256:7", required=False)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def verify_quote(public, paths, challenge, approved_pcr=None, selection="sha256:7"):
    pcr_args = ["-f", paths[2] if approved_pcr is None else approved_pcr, "-l", selection]
    return run("tpm2_checkquote", "-u", public, "-m", paths[0], "-s", paths[1],
               *pcr_args, "-g", "sha256", "-q", challenge.hex(),
               env=dict(os.environ, TPM2TOOLS_TCTI="none"), required=False).returncode == 0


def derive_credential(local, peer, source, node_id="A"):
    if len(local) != 32 or len(peer) != 32 or node_id not in ["A", "B", "C"] or source not in ["A", "B", "C"]:
        raise ValueError("invalid lab contributions or path")
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
                info=f"regalia-bootstrap-lab/v1/luks/{node_id}/via/{source}".encode()).derive(local + peer)


def luks_cases(root, local_secret, peer_b, peer_c):
    """Real LUKS2 header/keyslot checks; no device-mapper privileges required."""
    derive = derive_credential

    key_b = derive(local_secret, peer_b, "B")
    key_c = derive(local_secret, peer_c, "C")
    image = root / "disk.luks"
    with image.open("wb") as disk:
        disk.truncate(64 * 1024 * 1024)
    # Small fixed PBKDF cost is for disposable random test credentials only.
    pbkdf = ["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"]
    run("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", *pbkdf,
        "--key-file", "-", image, data=key_b)
    existing_key = root / "existing.key"
    existing_key.write_bytes(key_b)
    try:
        run("cryptsetup", "luksAddKey", *pbkdf, "--key-file", existing_key,
            "--new-keyfile", "-", image, data=key_c)
    finally:
        existing_key.unlink()

    def accepts(key, slot=None):
        options = [] if slot is None else ["--key-slot", str(slot)]
        result = run("cryptsetup", "open", "--type", "luks2", "--test-passphrase",
                     "--key-file", "-", *options, image, data=key, required=False)
        # Exit 2 is a credential refusal; environmental/tool errors cannot count as a denial.
        if result.returncode not in [0, 2]:
            raise RuntimeError(f"cryptsetup credential check failed (exit {result.returncode})")
        return result.returncode == 0

    cases = [
        ("TPM plus B contribution opens B keyslot", accepts(key_b, 0)),
        ("TPM plus C contribution opens C keyslot", accepts(key_c, 1)),
        ("B and C keyslots are independent", not accepts(key_b, 1) and not accepts(key_c, 0)),
        ("TPM contribution alone cannot unlock", not accepts(local_secret)),
        ("peer contribution alone cannot unlock", not accepts(peer_b)),
        ("wrong TPM contribution cannot unlock", not accepts(derive(os.urandom(32), peer_b, "B"))),
        ("wrong peer contribution cannot unlock", not accepts(derive(local_secret, os.urandom(32), "B"))),
        ("substituted peer path cannot unlock", not accepts(derive(local_secret, peer_b, "C"))),
    ]
    run("cryptsetup", "luksKillSlot", "--batch-mode", "--key-file", "-", image, "0", data=key_c)
    cases.extend([
        ("removed B path no longer unlocks", not accepts(key_b)),
        ("C path survives removal of B path", accepts(key_c, 1)),
    ])
    return cases


def main():
    os.umask(0o077)
    report = {
        "schema_version": 1,
        "evidence_class": "emulated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(),
        "docker_daemon_platform": os.environ.get("REGALIA_LAB_DAEMON_PLATFORM", "unknown"),
        "swtpm_seccomp": os.environ.get("REGALIA_LAB_SWTPM_SECCOMP", "kill"),
        "source_commit": os.environ.get("REGALIA_LAB_COMMIT", "unknown"),
        "image_id": os.environ.get("REGALIA_LAB_IMAGE_ID", "unknown"),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "sources_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                           for name in ["lab.py", "peer.py", "peer_cases.py"]},
        "status": "failed",
        "debian_version": Path("/etc/debian_version").read_text().strip(),
        "packages": Path("/opt/packages.tsv").read_text().splitlines(),
        "checks": [],
    }
    nodes = []
    try:
        for tool in ["swtpm", "tpm2_quote", "tpm2_checkquote", "tpm2_print", "cryptsetup", "wg"]:
            if shutil.which(tool) is None:
                raise RuntimeError(f"missing lab tool: {tool}")
        print("PASS Debian 13 arm64/amd64 lab toolchain")
        report["checks"].append({"name": "toolchain", "status": "passed"})
        with ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="regalia-lab-"))
            root = Path(directory)
            for name in ["A", "B"]:
                node = TPM(root, name)
                nodes.append(node)
                stack.callback(node.close)
                node.start()
            a, b = nodes
            for node in nodes:
                node.prepare_storage()
            wg_key = run("wg", "genkey").stdout
            a.seal("wg", wg_key, "0x81010004")
            local_secret = os.urandom(32)
            a.seal("local", local_secret, "0x81010005")
            unsealed = a.unseal("0x81010005")
            unsealed_wg = a.unseal("0x81010004")
            challenge = os.urandom(32)
            quote = a.quote(challenge, "fresh")
            cases = [
                ("fresh quote verifies against enrolled AK", verify_quote(a.root / "ak.pem", quote, challenge)),
                ("quote replay fails with fresh challenge", not verify_quote(a.root / "ak.pem", quote, os.urandom(32))),
                ("substituted TPM identity is rejected", not verify_quote(b.root / "ak.pem", quote, challenge)),
                ("quote matches approved PCR values", verify_quote(a.root / "ak.pem", quote, challenge, a.root / "approved.pcr")),
                ("TPM unseals local contribution under approved PCR", unsealed.returncode == 0 and unsealed.stdout == local_secret),
                ("TPM unseals WireGuard key under approved PCR", unsealed_wg.returncode == 0 and run("wg", "pubkey", data=unsealed_wg.stdout).stdout == run("wg", "pubkey", data=wg_key).stdout),
                ("empty password cannot bypass PCR policy", tpm_refused(a.call("tpm2_unseal", "-c", "0x81010004", required=False), 0x12F)),
                ("sealed blob cannot be loaded by another TPM", tpm_refused(b.call("tpm2_load", "-C", "0x81010003", "-u", a.root / "wg.pub", "-r", a.root / "wg.priv", "-c", b.root / "foreign.ctx", required=False), 0x1DF)),
            ]
            for index, label in enumerate(["quote message", "quote signature", "quoted PCR data"]):
                altered = list(quote)
                data = bytearray(quote[index].read_bytes())
                data[-1] ^= 1
                altered[index] = root / f"tampered-{index}"
                altered[index].write_bytes(data)
                cases.append((f"tampered {label} is rejected", not verify_quote(a.root / "ak.pem", altered, challenge)))
            request = {"node_id": "A", "manifest_epoch": 1, "boot_session_id": os.urandom(16).hex(),
                       "ephemeral_public_key": X25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
                       "peer_nonce": os.urandom(32).hex()}
            def qualification(value):
                return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).digest()
            bound = a.quote(qualification(request), "bound")
            cases.append(("quote binds the bootstrap request", verify_quote(a.root / "ak.pem", bound, qualification(request))))
            for field, value in [("node_id", "B"), ("manifest_epoch", 2), ("boot_session_id", os.urandom(16).hex()),
                                 ("ephemeral_public_key", X25519PrivateKey.generate().public_key().public_bytes_raw().hex()),
                                 ("peer_nonce", os.urandom(32).hex())]:
                changed = dict(request, **{field: value})
                cases.append((f"changed {field} is rejected", not verify_quote(a.root / "ak.pem", bound, qualification(changed))))
            from peer_cases import peer_cases
            peer_checks, peer_b, peer_c = peer_cases(root, a, b, verify_quote)
            cases.extend(peer_checks)
            a.call("tpm2_pcrextend", "7:sha256=" + hashlib.sha256(b"unexpected boot change").hexdigest())
            changed_quote = a.quote(challenge, "changed")
            cases.extend([
                ("changed-PCR quote is still cryptographically authentic", verify_quote(a.root / "ak.pem", changed_quote, challenge)),
                ("peer rejects an authentic but unapproved PCR state", not verify_quote(a.root / "ak.pem", changed_quote, challenge, a.root / "approved.pcr")),
                ("changed PCR prevents WireGuard key release", tpm_refused(a.unseal("0x81010004"), 0x99D)),
                ("changed PCR prevents local contribution release", tpm_refused(a.unseal("0x81010005"), 0x99D)),
            ])
            cases.extend(luks_cases(root, unsealed.stdout, peer_b, peer_c))
            for name, passed in cases:
                report["checks"].append({"name": name, "status": "passed" if passed else "failed"})
                print(("PASS " if passed else "FAIL ") + name)
            if not all(passed for _, passed in cases):
                raise RuntimeError("one or more lab assertions failed")
            report["status"] = "passed"
    finally:
        Path(os.environ["REGALIA_LAB_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
