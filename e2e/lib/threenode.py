"""Three KMS nodes on one machine, for the recovery rehearsals (#70: automatic recovery; #71: total outage).

Each node is what a host is, less the boot (tier N of #70's design): its own network namespace, its own
software TPM (EK, AK, the membership anchor and the heartbeat counter in it), its own configuration and
state directories, and its own processes: the node's real programs (deploy/baremetal/node.py's services),
each a transient systemd unit (systemd-run) in the node's namespace, with the IDENTITY of its installed unit
(User, Group, SupplementaryGroups, capabilities, NoNewPrivileges, UMask: read from the unit file itself, so
the two cannot drift) and no view of the other nodes' directories (InaccessiblePaths). The rest of the
installed units' sandbox is e2e/node-units-systemd.py's test, for one node.

    cluster = Cluster(work)          # namespaces, TPMs, identities, the chain, the configurations
    cluster.build()
    cluster.start("a")               # sync, then wg-apply (as a host's path unit would run it)
    cluster.stop("a")                # a power cycle: its processes stop, its /run is emptied, its TPM restarts
                                     # (Startup(CLEAR): resetCount up, PCRs reset), its time unauthenticated
    cluster.stop("a", power=None)    # a service crash: the processes only
    cluster.close()                  # everything this made, removed

Stand-ins, each named where it is made, and each replaceable when the real piece runs here:
  * authenticated time: authtime.Service with a reading that says chrony is synchronised with two NTS
    sources. It writes the real status file the services read; `cluster.time[n] = False` makes it say
    not authenticated (#70 blackout 3b);
  * heartbeats: none from here (#199, membership v4): the nodes sign their own (beat.py) with their TPM
    signing keys, each node's PCR 11 extended as a booted image's and signed by a fixture system-phase PCR key
    (its tpm2-pcr-signature.json and the key bound at /run/systemd in its units), and the owner's two keys
    (ADR-0002 D30) on a SoftHSM token, signed through Pkcs11Signer as the YubiKeys are; owner_beat() is the hand
    recovery;
  * a new epoch (advance): a root- or owner-signed envelope given to one seed node while its services are down;
    the running nodes pull it from there with their real sync (revoke_by_nodes and revoke_by_owner are revoke.py's
    own paths);
  * the pre-root client's two systemd roles: the local half, unsealed by this fixture from the node's TPM,
    passed as a plain credential (on a host LoadCredentialEncrypted= unseals it under the TPM's policy), and
    the key socket (socket activation, systemd-cryptsetup's side played by this fixture);
  * regalia-wg-apply.path: the same trigger (PathChanged= on the published chain), a transient path unit.
  * regalia-esp-advance (#66 B3): the node's real command, as root with the installed unit's identity, at start and
    from a transient path unit on the published chain; its ESP is a directory of the node's own (esp/, not a FAT
    partition, and nothing boots from it) and its anchor lock is in the node's run directory. sync (and deliver,
    through the node's Store) never moves the TPM anchor: this does, so advance() checks that each running node's
    anchor follows the epoch.

Underlay: a bridge in a switch namespace, node i at 192.0.2.(10*i)/24. Each node's site configuration names
the others' underlay addresses, its boot mesh (wg-unlock) and its service mesh (wg-svc), as on a host.
Root only; it changes the machine (namespaces, interfaces, transient units), so its callers run only on a
throwaway machine (a GitHub-hosted runner)."""
import configparser
import contextlib
import grp
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
# regalia-admission's StateDirectoryMode, read from the shipped unit: the fixture's directory is what a host's is, so
# whether its trail's shipper can pass it is the unit's to decide (#340, #345)
def _state_directory_mode(unit):
    for line in (ROOT / "deploy" / "baremetal" / "units" / unit).read_text().splitlines():
        if line.startswith("StateDirectoryMode="):
            return int(line.split("=", 1)[1], 8)
    raise RuntimeError("%s declares no StateDirectoryMode" % unit)


ADMISSION_DIR_MODE = _state_directory_mode("regalia-admission.service")

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.baremetal import attest, authtime, bootnet, heartbeat, measurements, membership, node, signkey, sitecfg, unlock, uki, wgsvc   # noqa: E402
import tests.test_baremetal_heartbeat as hbt                                                        # noqa: E402  the test root key

NAMES = ("a", "b", "c")
RECOVERY = b"cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"     # the TEST recovery key (as the unlock tests')
MARKER = b"regalia-kms root volume marker"
SWITCH = "e2e3-sw"
UNIT_PREFIX = "e2e3-"
AUDIT_TRAILS = (("sync", "state", "sync-audit.jsonl"), ("admission", "admission", "audit.jsonl"))   # each node's own (#340)
COLLECTOR_UNIT = UNIT_PREFIX + "audit-collector"
COLLECTOR_PORT = 18443


def sh(*argv, check=True, **kw):
    done = subprocess.run(list(argv), capture_output=True, text=True, **kw)
    if check and done.returncode != 0:
        raise RuntimeError("%s failed (%d): %s %s" % (" ".join(argv[:4]), done.returncode, done.stdout.strip()[-600:], done.stderr.strip()[-600:]))
    return done


def until(what, seconds, interval=1.0):
    """`what()` until it is true or the time is up; its last value (or the exception it raised)."""
    deadline, last = time.monotonic() + seconds, None
    while time.monotonic() < deadline:
        try:
            last = what()
            if last:
                return last
        except Exception as failure:       # noqa: BLE001 - keep trying until the deadline, then say what it was
            last = failure
        time.sleep(interval)
    return last


def beat_stamp(seconds):
    """A heartbeat's time field (beat.stamp)."""
    from deploy.baremetal import beat
    return beat.stamp(int(seconds))


def _replace(path, text):
    """`path` written whole: a temporary file beside it, then renamed over it."""
    tmp = pathlib.Path(str(path) + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


class NodeHere:
    """One node's paths, keys and identity."""

    def __init__(self, work, name, index):
        self.name, self.index = name, index
        self.dir = work / name
        self.ns = "e2e3-" + name
        self.underlay = "192.0.2.%d" % (10 * index)
        self.boot_address = "10.89.0.%d" % index
        self.tpm_sock = self.dir / "tpm.sock"
        self.tcti = "swtpm:path=%s" % self.tpm_sock
        self.cfg_path = self.dir / "etc" / "node.json"
        self.state, self.admission, self.run = self.dir / "state", self.dir / "admission", self.dir / "run"

    def in_ns(self, *argv, check=True, **kw):
        return sh("ip", "netns", "exec", self.ns, *argv, check=check, **kw)


# The image the fixture boots (v4, #199): PCR 11 extended with this after every TPM start, as a booted UKI extends it, so
# that the system-phase PCR key's signature over it lets the node's TPM signing key sign
BOOTED = b"e2e3: an approved image, booted"
# ...and, once the node leaves its initrd (start(): its services come up), extended once more, as systemd-pcrphase
# extends "leave-initrd": PCR 11 takes one value in the initrd phase (an unlock is judged by it) and another in the
# system phase (a lease, and the system-phase key's signature its policy sessions use), as a signed UKI's do
LEAVE_INITRD = b"e2e3: leave-initrd"


def extended(value, data):
    """PCR 11 `value` (hex) once `data` is extended into it (SHA-256 bank), as tpm2_pcrextend with SHA-256(data) does."""
    return hashlib.sha256(bytes.fromhex(value) + hashlib.sha256(data).digest()).hexdigest()


def unlock_pcr11(entry):
    """The PCR 11 a node on measurement set `entry` quotes for an unlock: its initrd phase's under v4, else its only one."""
    return entry["phases"]["initrd"]["11"] if "phases" in entry else entry["pcrs"]["11"]


SOFTHSM = next((c for c in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if os.path.exists(c)), None)
OWNER_PIN = "246813"                              # the SoftHSM owner token's TEST PIN


class Cluster:
    def __init__(self, work, names=NAMES, audit=False):
        self.work = pathlib.Path(work)
        # #199: the cluster is v4. The nodes sign their own heartbeats with their TPM signing keys (beat.py), the owner's
        # party is two Ed25519 keys on a SoftHSM token (the two owner YubiKeys of ADR-0002 D30), and each node boots an
        # image whose PCR 11 a fixture system-phase key signed
        self.pcr_values = {n: set() for n in names}   # the PCR 11 values each node's signature file covers
        self.left_initrd = set()                      # v4: the nodes whose PCR 11 is in the system phase (start), until a TPM start
        # the real audit trail shippers and collector (#340): each node's own trails shipped as a host ships them,
        # so a scenario can hold every event it caused to the collector's chained stream (audit_complete)
        self.audit = audit
        self.audit_bin = pathlib.Path(os.environ.get("REGALIA_AUDIT_BIN", "/nonexistent"))
        self.nodes = {n: NodeHere(self.work, n, i + 1) for i, n in enumerate(names)}
        self.time = {n: True for n in names}          # authenticated time, per node
        self.stop_threads = False
        self.threads = []
        self.chain = []                               # the signed envelopes, epoch 1 first
        self.manifest = None
        self.keys = {}
        self.authtimes = {}
        self.loops = {}
        self.services = {n: () for n in names}        # what start() last started on each node, until stop()
        self.client = os.environ.get("REGALIA_UNLOCK_BIN", "")
        self.code = self.work / "src"                 # the package as a host installs it: root's, readable by the services

    def members(self):
        """The nodes: everything with a namespace, a TPM and a clock."""
        return list(self.nodes.values())

    def member(self, name):
        return self.nodes[name]

    # ---- building ----

    def build(self):
        # the services' users and groups, from the shipped file (regalia-sync, regalia-admission, their trails' groups)
        sh("systemd-sysusers", str(ROOT / "deploy" / "baremetal" / "units" / "regalia.sysusers.conf"))
        os.chmod(self.work, 0o711)                    # each node's directory is reached through it, read in it only
        # the checkout may sit where the services' users cannot go (a runner's home is 0750): they run a root-owned copy
        shutil.copytree(ROOT / "deploy", self.code / "deploy", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        sh("chown", "-R", "root:root", str(self.code))
        sh("chmod", "-R", "u=rwX,go=rX", str(self.code))
        self._pcr_key()
        self._owner_token()
        self._network()
        for n in self.members():
            for d in (n.dir / "etc", n.state, n.admission, n.run):
                d.mkdir(parents=True)
            os.chmod(n.dir, 0o711)
            self._tpm(n)
            self._wg_keys(n)
        self._identities_and_chain()
        for n in self.nodes.values():
            self._configure(n)
            self._anchor_and_store(n)
        self._authtime()
        for n in self.nodes.values():                 # no heartbeat from here: the nodes sign their own (#199)
            # owned as the units' StateDirectory= would make them: the services are not root
            sh("chown", "-R", "regalia-sync:regalia-sync", str(n.state))
            os.chmod(n.state, 0o755)
            sh("chown", "-R", "regalia-admission:regalia-admission", str(n.admission))
            os.chmod(n.admission, ADMISSION_DIR_MODE)
        if self.audit:
            self._audit_start()

    def _network(self):
        sh("ip", "netns", "add", SWITCH)
        sh("ip", "netns", "exec", SWITCH, "ip", "link", "add", "br0", "type", "bridge")
        sh("ip", "netns", "exec", SWITCH, "ip", "link", "set", "br0", "up")
        for n in self.members():
            self._wire(n)

    def _wire(self, n):
        """The member's namespace, on the switch at its underlay address."""
        sh("ip", "netns", "add", n.ns)
        port = "sw-" + n.name
        sh("ip", "link", "add", port, "netns", SWITCH, "type", "veth", "peer", "name", "eth0", "netns", n.ns)
        sh("ip", "netns", "exec", SWITCH, "ip", "link", "set", port, "master", "br0")
        sh("ip", "netns", "exec", SWITCH, "ip", "link", "set", port, "up")
        n.in_ns("ip", "link", "set", "lo", "up")
        n.in_ns("ip", "address", "add", n.underlay + "/24", "dev", "eth0")
        n.in_ns("ip", "link", "set", "eth0", "up")

    def _tpm(self, n):
        (n.dir / "tpm").mkdir(exist_ok=True)
        for leftover in (n.tpm_sock, pathlib.Path(str(n.tpm_sock) + ".ctrl")):
            if leftover.exists():
                leftover.unlink()
        # the socket is the tss group's, 0660, as /dev/tpmrm0 is on a host: the services reach it through the group.
        # The control socket too: tpm2-tools' swtpm TCTI opens it (a host has none; only this stand-in needs it)
        tss = grp.getgrnam("tss").gr_gid
        server = "type=unixio,path=%s,mode=0660,gid=%d" % (n.tpm_sock, tss)
        ctrl = "type=unixio,path=%s.ctrl,mode=0660,gid=%d" % (n.tpm_sock, tss)
        done = sh("swtpm", "socket", "--tpm2", "--server", server, "--ctrl", ctrl,
                  "--tpmstate", "dir=%s" % (n.dir / "tpm"), "--flags", "not-need-init,startup-clear", "--daemon",
                  "--pid", "file=%s" % (n.dir / "tpm.pid"), "--log", "file=%s" % (n.dir / "tpm.log"), check=False)
        if done.returncode != 0 or not until(lambda: n.tpm_sock.exists(), 10, 0.2):
            log = (n.dir / "tpm.log").read_text()[-800:] if (n.dir / "tpm.log").exists() else ""
            denied = sh("journalctl", "-k", "--since", "-2min", "-g", "apparmor", "--no-pager", check=False).stdout[-800:]
            raise RuntimeError("%s's software TPM did not start (%d): %s %s | log: %s | apparmor: %s"
                               % (n.name, done.returncode, done.stdout.strip(), done.stderr.strip(), log, denied))
        self.left_initrd.discard(n.name)              # a TPM start: PCR 11 at its reset value, the node in its initrd again
        self._booted(n)

    # ---- v4 (#199): the booted image's signed PCR 11, and the owner's two keys ----

    def _pcr_key(self):
        """The fixture's system-phase PCR key (RSA-2048, as uki.py's): what the nodes' signing keys are bound to. Beside
        it, what a signed image's measurement set names with it (uki.py's signed record, attest.SIGNING_KEYS): an
        initrd-phase PCR key of its own and a Secure Boot certificate, both made here. Nothing in the fixture signs
        with either, but the set names them as the root approves a signed UKI's (#242: the system key is the one a
        node's anchor and counters are written by)."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID

        def public(key):
            return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.pcr_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pcr_pem = public(self.pcr_private)
        self.pcr_sigs = {}                            # PCR 11 value -> its signature entry
        initrd_pem = public(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        sb = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e2e3 Secure Boot")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(sb.public_key()).serial_number(1) \
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(sb, hashes.SHA256())
        self.image_signing = {"initrd": signkey.pcr_key_fingerprint(initrd_pem), "system": signkey.pcr_key_fingerprint(self.pcr_pem),
                              "secure_boot_cert": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()}

    def _pcr11(self, n):
        out = n.dir / "pcr11.bin"
        sh("tpm2_pcrread", "-T", n.tcti, "sha256:11", "-o", str(out))
        return out.read_bytes().hex()

    def _booted(self, n):
        """The node's TPM, as a host's once systemd-stub has measured an approved image into PCR 11: the value extended
        (the INITRD phase's), and the value it takes when the node leaves its initrd (start) signed by the system-phase
        key in the node's tpm2-pcr-signature.json (properties() binds it, and the key's PEM, where systemd puts them:
        /run/systemd)."""
        sh("tpm2_pcrextend", "-T", n.tcti, "11:sha256=" + hashlib.sha256(BOOTED).hexdigest())
        self._sign_pcr11(n.name, extended(self._pcr11(n), LEAVE_INITRD))

    def _leave_initrd(self, name):
        """v4: the node's PCR 11 into its system phase, ONCE per boot (systemd-pcrphase's leave-initrd): a service
        restarted without a TPM start finds it there already."""
        if name in self.nodes and name not in self.left_initrd:
            sh("tpm2_pcrextend", "-T", self.nodes[name].tcti, "11:sha256=" + hashlib.sha256(LEAVE_INITRD).hexdigest())
            self.left_initrd.add(name)

    @contextlib.contextmanager
    def _as_booted(self, name):
        """This process as node `name`'s booted system for signkey: its system-phase PCR key and PCR signatures where its
        units have them bound (/run/systemd), for a node's own step run here (node.define_policy reads the key).
        NOT THREAD-SAFE: it swaps signkey's module paths for this whole process, so never use it while another thread
        (the unlock threads of recovery steps 4 and 5) may touch signkey (3e's read)."""
        d = self.nodes[name].dir / "pcr"
        saved = signkey.PCR_PUBLIC_KEY_PATH, signkey.PCR_SIGNATURE_PATHS
        signkey.PCR_PUBLIC_KEY_PATH, signkey.PCR_SIGNATURE_PATHS = str(d / "tpm2-pcr-public-key.pem"), (str(d / "tpm2-pcr-signature.json"),)
        try:
            yield
        finally:
            signkey.PCR_PUBLIC_KEY_PATH, signkey.PCR_SIGNATURE_PATHS = saved

    def _sign_pcr11(self, name, value):
        """`value` added to the PCR 11 values the node's signature file covers (an image it may boot), the file rewritten."""
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        if value not in self.pcr_sigs:
            pol = uki.policy_digest(value)
            sig = self.pcr_private.sign(bytes.fromhex(pol), padding.PKCS1v15(), hashes.SHA256())
            self.pcr_sigs[value] = {"pcrs": [11], "pkfp": signkey.pcr_key_fingerprint(self.pcr_pem), "pol": pol, "sig": base64.b64encode(sig).decode()}
        self.pcr_values.setdefault(name, set()).add(value)
        d = self.nodes[name].dir / "pcr"
        d.mkdir(mode=0o755, exist_ok=True)
        # written IN PLACE, never renamed over: a running unit's BindReadOnlyPaths= holds the inode it was started with,
        # so a replaced file would stay unseen by it (an image approved while the node runs, #75's rolling update)
        for f, text in ((d / "tpm2-pcr-signature.json", json.dumps({"sha256": [self.pcr_sigs[v] for v in sorted(self.pcr_values[name])]})),
                        (d / "tpm2-pcr-public-key.pem", self.pcr_pem.decode())):
            with open(f, "r+" if f.exists() else "w") as out:
                out.seek(0)
                out.write(text)
                out.truncate()
                out.flush()
                os.fsync(out.fileno())
            os.chmod(f, 0o644)

    def _owner_token(self):
        """The owner's party (ADR-0002 D30: the owner YubiKey and its backup): two Ed25519 keys on a SoftHSM token, signed
        through the real p11sign.Pkcs11Signer(alg="ed25519"), CKM_EDDSA, as the YubiKeys' OpenPGP applet is through OpenSC."""
        if SOFTHSM is None:
            raise RuntimeError("v4 needs SoftHSM (softhsm2), pkcs11-tool (opensc) and PyKCS11 (python3-pykcs11) for the owner's keys")
        d = self.work / "owner-hsm"
        (d / "tokens").mkdir(parents=True)
        conf = d / "softhsm2.conf"
        conf.write_text("directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" % d)
        os.environ["SOFTHSM2_CONF"] = str(conf)       # this process's: the fixture signs as the owner
        sh("softhsm2-util", "--init-token", "--free", "--label", "owner", "--so-pin", "12345678", "--pin", OWNER_PIN)
        for key_id, label in (("01", "owner"), ("02", "owner-backup")):
            sh("pkcs11-tool", "--module", SOFTHSM, "--token-label", "owner", "--login", "--pin", "env:P", "--keypairgen",
               "--key-type", "EC:edwards25519", "--id", key_id, "--label", label, env=dict(os.environ, P=OWNER_PIN))
        listing = sh("pkcs11-tool", "--module", SOFTHSM, "--list-slots").stdout
        self.owner_serial = next(line.split(":", 1)[1].strip() for line in listing.splitlines() if "serial num" in line)
        self.owner_keys = [{"alg": "ed25519", "key": self.owner_signer(i).public()} for i in range(2)]

    def owner_signer(self, which=0):
        """The owner's key `which` (0: the owner's, 1: the backup), as owner.py opens a YubiKey: by serial, Ed25519. Both
        sit on ONE SoftHSM token here (key ids 01 and 02), where the real pair is two YubiKeys with two serials and the
        same slot, chosen by --serial: a fixture's simplification, accepted on #369 (24, after 3e's read)."""
        from deploy.baremetal import p11sign
        return p11sign.Pkcs11Signer(SOFTHSM, self.owner_serial, "%02x" % (which + 1), None, pin=lambda: OWNER_PIN, alg="ed25519")

    def power_cycle(self, name, orderly=True):
        """The node's TPM through a power loss: (orderly) TPM2_Shutdown(CLEAR) first, then the process stopped and
        started again on the same state, which sends TPM2_Startup(CLEAR): resetCount one higher, the PCRs back to
        their reset values, every transient object and session gone, as on a host. Without `orderly`, a cut: no
        Shutdown, which a TPM counts against its dictionary-attack limit (#57)."""
        n = self.member(name)
        if orderly:
            sh("tpm2_shutdown", "-c", "-T", n.tcti, check=False)
        pid = int((n.dir / "tpm.pid").read_text())
        os.kill(pid, 15)
        if not until(lambda: not os.path.exists("/proc/%d" % pid), 10, 0.2):
            raise RuntimeError("%s's software TPM did not stop" % name)
        self._tpm(n)

    # ---- images (#75, Phase 15's tier N) ----
    # CURRENT is the node as the fixture boots it: its PCRs at TPM2_Startup, recorded at build (_reference). Another
    # image is modelled by what a UKI changes, PCR 11: boot(name, image) extends it with SHA-256(image) after a power
    # cycle, before the node asks for its disk; image_set says what that boot measures, for a document to accept.
    # The local half is sealed to PCR 7 alone (enrol), so it opens on every image, as on a host (PIN-CUSTODY.md).

    def boot(self, name, image=None):
        """`name` boots `image` (None: CURRENT, nothing to extend). Call after power_cycle (or stop) and before unlock."""
        if image is not None:
            sh("tpm2_pcrextend", "-T", self.member(name).tcti, "11:sha256=" + hashlib.sha256(image.encode()).hexdigest())

    def image_set(self, name, image=None):
        """The measurement set `name` is accepted in when it boots `image` (None: its CURRENT set, as built)."""
        base = self.reference[name]
        if image is None:
            return dict(base)
        # an image the root approves: the system-phase key signs its system phase's PCR 11
        initrd = extended(base["phases"]["initrd"]["11"], image.encode())
        system = extended(initrd, LEAVE_INITRD)
        self._sign_pcr11(name, system)
        return dict(base, label=image, phases={"initrd": {"11": initrd}, "system": {"11": system}})
        return dict(base, label=image, pcrs=dict(base["pcrs"], **{"11": value}))

    def accept(self, seed, sets, name):
        """A new document, {node: [image, ...]} (None: CURRENT), and the epoch that commits to it. The seed takes both;
        every other running node pulls the epoch from it and, with it, the document it commits to, before it commits
        (#332). No service is stopped for it: a node holds documents side by side by digest and judges each epoch by
        its own, so there is no moment at which one is judged by the other's. Returns what advance returns."""
        document = {"schema": measurements.SCHEMA, "name": name,
                    "nodes": {node: {"accepted": [self.image_set(node, image) for image in images]} for node, images in sets.items()}}
        return self.advance(seed, document=document)

    def reset_count(self, name):
        """The TPM's resetCount (TPM2_ReadClock): one higher after each power cycle."""
        out = sh("tpm2_readclock", "-T", self.member(name).tcti).stdout
        return int(next(line.split(":", 1)[1] for line in out.splitlines() if "reset_count" in line))

    def _wg_keys(self, n):
        keys = {}
        for use in ("service", "boot"):
            private = sh("wg", "genkey").stdout.strip()
            keys[use] = (private, wgsvc.hex_key(sh("wg", "pubkey", input=private + "\n").stdout.strip()))
        self.keys[n.name] = keys
        path = n.dir / "etc" / "wg-service.key"
        path.write_text(keys["service"][0] + "\n")
        os.chmod(path, 0o600)
        (n.dir / "etc" / "wg-boot.key").write_text(keys["boot"][0] + "\n")      # the initrd's, for #70's tier N unlock client
        os.chmod(n.dir / "etc" / "wg-boot.key", 0o600)

    def _identity(self, n):
        """An EK and a persistent AK, as attest.node_init makes them: (EK name, AK name, AK public area hex)."""
        out = n.dir / "ids"
        out.mkdir()
        before = os.environ.get("TPM2TOOLS_TCTI")
        os.environ["TPM2TOOLS_TCTI"] = n.tcti
        try:
            attest.node_init(str(out))
            sh("tpm2_flushcontext", "-t", check=False)
        finally:
            os.environ.pop("TPM2TOOLS_TCTI") if before is None else os.environ.__setitem__("TPM2TOOLS_TCTI", before)
        ek, ak = (out / "ek.pub").read_bytes(), (out / "ak.pub").read_bytes()
        ek_name = attest.name_of(attest.public_area(ek, "the EK public area")).hex()
        # #199: the signing key, made in the node's TPM and certified by its AK, accepted as `enrol entry` accepts it
        blob = signkey.create(self.pcr_pem, tcti=n.tcti)
        info, sig = signkey.certify(tcti=n.tcti)
        self.signing[n.name] = signkey.verify_certification(blob, info, sig, ak, ek_name, self.pcr_pem)
        return ek_name, attest.ak_identity(ak)[0].hex(), ak.hex()

    def _reference(self, n, pcrs):
        """The node's accepted measurement set, read from its TPM, as pcr_survey.py records it on a host."""
        sh("tpm2_pcrread", "-T", n.tcti, "sha256:" + ",".join(str(i) for i in pcrs), "-o", str(n.dir / "pcrs.bin"))
        raw = (n.dir / "pcrs.bin").read_bytes()
        sh("tpm2_quote", "-T", n.tcti, "-c", attest.AK_HANDLE, "-g", "sha256", "-l", "sha256:%d" % pcrs[0], "-q", "00" * 32,
           "-m", str(n.dir / "ref.quote"), "-s", str(n.dir / "ref.sig"), "-f", "plain")
        sh("tpm2_flushcontext", "-T", n.tcti, "-t", check=False)
        entry = {"label": "e2e-image", "tpm_firmware_version": attest.parse_quote((n.dir / "ref.quote").read_bytes())["firmware_version"],
                 "pcrs": {str(i): raw[32 * k:32 * (k + 1)].hex() for k, i in enumerate(pcrs)}}
        # a signed UKI's set (#199, #242): PCR 11 per phase, read here in the initrd phase (before start), and the keys
        # it is signed with, the system-phase one naming the node's write policy
        initrd = entry["pcrs"].pop("11")
        entry.update(phases={"initrd": {"11": initrd}, "system": {"11": extended(initrd, LEAVE_INITRD)}}, signing=dict(self.image_signing))
        return entry

    def _identities_and_chain(self):
        example = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
        self.signing = {}
        self.ids = {n.name: self._identity(n) for n in self.nodes.values()}
        self.reference = {n.name: self._reference(n, example["pcrs"]) for n in self.nodes.values()}
        self.document = {"schema": measurements.SCHEMA, "name": "e2e3",
                         "nodes": {n.name: {"accepted": [dict(self.reference[n.name])]} for n in self.nodes.values()}}
        # #199: the first real manifest is v4 (no ceremony has run): the nodes and the owner sign, by quorum
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        names = [n.name for n in self.nodes.values()]
        self.manifest = {"schema": membership.SCHEMA_V4, "epoch": 1, "prev_digest": "", "policy_version": measurements.version(self.document),
                         "issued_at": "2026-10-01T00:00:00Z", "heartbeat_max_lifetime_s": 21600, "owner_heartbeat_lifetime_s": 3600,
                         "owner_keys": self.owner_keys,
                         "heartbeat_signers": {"threshold": 2, "parties": names + [membership.OWNER]},
                         "activation_signers": {"threshold": 2, "parties": names},
                         "revocation_signers": [{"threshold": 2, "parties": names}, {"threshold": 1, "parties": [membership.OWNER]}],
                         "nodes": [{"node_id": n.name, "state": "ACTIVE", "ek_name": self.ids[n.name][0], "ak_name": self.ids[n.name][1],
                                    "wg_boot_pub": self.keys[n.name]["boot"][1], "wg_service_pub": self.keys[n.name]["service"][1],
                                    "hsm_serials": ["E2E3%s" % n.name.upper()]} for n in self.nodes.values()]}
        for entry in self.manifest["nodes"]:
            ssh = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            entry.update(ssh_host_pub=ssh.hex(), signing_key=self.signing[entry["node_id"]])
        self.chain = [self.signed(self.manifest)]

    @staticmethod
    def signed(manifest, key=None):
        """The root's envelope (the test root key, or `key`)."""
        key = key or hbt.ROOT
        return {"manifest": manifest, "signature": {"signer": "root", "key": hbt.pub(key), "sig": key.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}

    def _configure(self, n):
        example = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
        others = [o for o in self.nodes.values() if o is not n]
        site = {"schema": "regalia.baremetal-site/v1", "site": "e2e3-" + n.name, "host_ipv4": n.underlay, "kms_port": 8443, "ssh_port": 22,
                "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["203.0.113.128/32"], "admin_cidrs": ["203.0.113.0/28"],
                "outbound": [{"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514}],
                "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["203.0.113.193/32"]}, {"name": "nts-b.lab", "cidrs": ["203.0.113.195/32"]}]},
                "boot_mesh": {"node_id": n.name, "interface": "wg-unlock", "listen_port": 51820, "address": n.boot_address, "unlock_port": 7443,
                              "nic_mac": "52:54:00:12:34:%02x" % (0x50 + n.index), "prefix": 24, "gateway": None,
                              "peers": [{"node_id": o.name, "underlay": o.underlay, "address": o.boot_address} for o in others]},
                "service_mesh": {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444}}
        _replace(n.dir / "etc" / "site.json", json.dumps(site))            # whole, never torn: running services read them
        # no measurements.json: the document is in the node's store by digest, and later ones come by sync (#332)
        cfg = dict(example, node_id=n.name, site=str(n.dir / "etc" / "site.json"), root_key=hbt.pub(hbt.ROOT), tcti=n.tcti,
                   state_dir=str(n.state), admission_dir=str(n.admission), run_dir=str(n.run),
                   wg_service_key=str(n.dir / "etc" / "wg-service.key"), measurements=str(n.dir / "etc" / "measurements.json"),
                   time_servers=["nts1.e2e3.invalid", "nts2.e2e3.invalid"], pull_interval=10,
                   beat_interval_s=heartbeat.MIN_INTERVAL_S)    # #199: the shortest the product allows (600 s)
        _replace(n.cfg_path, json.dumps(cfg))

    def node(self, name):
        """The node as its services see it (deploy/baremetal/node.Node), from its configuration."""
        return node.Node(node.load(str(self.nodes[name].cfg_path)))

    @staticmethod
    def enrolled_store(here):
        """The store as enrolment builds it (enrol.py commit): ANCHORING, so a node starts with its anchor at the chain
        it was enrolled with. The node's own services use node.store(), which never anchors (#66 B3)."""
        return membership.Store(here.path("membership.json"), here.cfg["root_key"], here.anchor(), documents=here.documents().require_for)

    def _anchor_and_store(self, n):
        here = self.node(n.name)
        anchor = here.anchor()
        anchor.define()
        here.documents().put(self.document)          # as enrol commit does, before the first commit (#332)
        self.enrolled_store(here).commit(self.chain[0])
        with self._as_booted(n.name):                 # laid down by the node's policy (node.define_policy: the system key its measurements name)
            node.heartbeat_counter(here.cfg).define()
            node.signing_counter(here.cfg).define()  # #199: the highest sequence this node has signed

    # ---- the stand-ins ----

    def _authtime(self):
        """Authenticated time, per node: authtime's own Service and status file, with a reading that says chrony
        is synchronised to two NTS sources, or (cluster.time[n] False) that no source answers."""
        for n in self.members():
            self._authtime_for(n)

    def _authtime_for(self, n):
        def reading(name=n.name):
            now = time.time()
            answering = self.time[name]
            return {"leap": "Normal" if answering else "Not synchronised", "reference_time": now, "system_offset": 0.0,
                    "sources": [{"name": s, "state": state, "reaching": answering, "mode": "NTS", "keyed": True}
                                for s, state in (("nts1.e2e3.invalid", "*"), ("nts2.e2e3.invalid", "+"))]}
        service = authtime.Service(str(n.run / "authtime.json"), ["nts1.e2e3.invalid", "nts2.e2e3.invalid"], reading=reading)
        self.authtimes[n.name] = service
        service.step()
        thread = threading.Thread(target=service.run, args=(lambda: self.stop_threads,), kwargs={"interval": 5}, daemon=True)
        thread.start()
        self.threads.append(thread)

    # ---- running ----

    def unit(self, name, service):
        return "%s%s-%s" % (UNIT_PREFIX, name, service)

    IDENTITY = ("User", "Group", "SupplementaryGroups", "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges", "UMask")

    @staticmethod
    def identity(service):
        """The installed unit's identity settings, read from deploy/baremetal/units/regalia-<service>.service."""
        parser = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
        parser.optionxform = str
        parser.read(ROOT / "deploy" / "baremetal" / "units" / ("regalia-%s.service" % service))
        unit = parser["Service"]
        return {key: unit[key] for key in Cluster.IDENTITY if key in unit}

    def properties(self, name, service):
        """systemd-run -p for one service of one member: its namespace, the installed unit's identity, and no view
        of the other members' directories."""
        n = self.member(name)
        props = ["NetworkNamespacePath=/run/netns/" + n.ns, "WorkingDirectory=" + str(self.code), "Environment=PYTHONDONTWRITEBYTECODE=1"]
        props += ["%s=%s" % (key, value) for key, value in self.identity(service).items()]
        props += ["InaccessiblePaths=" + str(o.dir) for o in self.members() if o is not n]
        # where a booted host's systemd-stub puts the image's PCR signatures and its system-phase key: the node's own
        pcr = n.dir / "pcr"
        props += ["BindReadOnlyPaths=%s:%s" % (pcr / "tpm2-pcr-signature.json", "/run/systemd/tpm2-pcr-signature.json"),
                  "BindReadOnlyPaths=%s:%s" % (pcr / "tpm2-pcr-public-key.pem", signkey.PCR_PUBLIC_KEY_PATH)]
        return props

    def start(self, name, services=("sync", "wg-apply")):
        """The node's services, each a transient unit in its namespace, as a host runs them: sync first (it
        publishes the chain the others verify), wg-apply once the chain is published."""
        n = self.nodes[name]
        admission_run = n.run / "admission"                # as regalia.tmpfiles.conf makes it at every boot
        if not admission_run.exists():
            admission_run.mkdir()
            shutil.chown(admission_run, "regalia-admission", "regalia-admission")
            os.chmod(admission_run, 0o755)
        self._leave_initrd(name)                      # v4: its services run in the system phase
        if not self.time[name]:                       # booted again: its time is checked again (chrony, on a host)
            self.time[name] = True
            self.authtimes[name].step()
        if "sync" in services:                        # its path unit FIRST, as paths.target precedes the services on a host:
            self._esp_watch(n)                        # sync publishes at once, and a change before the watch is missed
        for service in services:
            if service == "wg-apply" and not until(lambda: (n.state / node.PUBLISHED).exists(), 30, 0.5):
                raise RuntimeError("%s's sync published no chain" % name)
            if service == "admission":                # regalia-boot-session.service, Before= it: a session when the unlock client left none
                self._run(n, "boot-session", oneshot=True)
            self._run(n, service, oneshot=(service == "wg-apply"))
            if service == "wg-apply":                 # and again at every new chain, as regalia-wg-apply.path runs it
                self._run(n, "wg-apply", unit=self.unit(name, "wg-watch"),
                          extra=["--path-property=PathChanged=%s" % (n.state / node.PUBLISHED), "-p", "Type=oneshot"])
        if "sync" in services:                        # and regalia-esp-advance's run at start, as its unit's WantedBy= gives
            self._esp_advance(n)
        self.services[name] = tuple(dict.fromkeys(self.services[name] + tuple(services)))   # stop() clears it
        if self.audit and name in self.nodes:         # the node's trail shippers run with it, as regalia-audit-ship@ does
            self._ship_start(name)
        if "sync" in services:
            self._caught_up(name)

    def _caught_up(self, name):
        """v4: a node started behind the cluster's epoch takes the epochs it missed by its OWN sync from a running peer, as
        a host does when it comes back (#332's path, each epoch with its document); nothing commits into a stopped node's
        store from here (#242 B3: its anchor is written by its booted system's policy only). Waited for when the node may
        authorize and a peer that may is running; a node the epoch revoked or quarantined is left as it is (its peers
        refuse it, and the scenario says what it finds). A store that does not load (a rolled-back disk) is the
        scenario's own: its sync recovers it, or not."""
        try:
            held = self.node(name).store().load()["epoch"]
        except membership.Refused:
            return
        if held >= self.manifest["epoch"] or not membership.may(self.manifest, name, "authorize"):
            return
        if not any(other != name and self.running(other) and membership.may(self.manifest, other, "authorize") for other in self.nodes):
            return
        def epoch():
            try:
                return self.node(name).store().load()["epoch"]
            except membership.Refused:                # a read during its own restore: asked again (3e's read)
                return None
        if not until(lambda: epoch() == self.manifest["epoch"], 180, 2):
            raise RuntimeError("%s, started at epoch %d, did not take epoch %d by its sync" % (name, held, self.manifest["epoch"]))
        # #66 B3 (regalia-kms-48's read): and its regalia-esp-advance wrote what it caught up on to its ESP, then anchored it
        target = self.manifest["epoch"]
        if not until(lambda: self.anchored(name) == target and self.esp_epoch(name) == target, 60, 1):
            raise RuntimeError("%s caught up on epoch %d, but its TPM anchor is at %s and its ESP at %s: regalia-esp-advance did not "
                               "follow | %s" % (name, target, self.anchored(name), self.esp_epoch(name), self.journal(name, "esp-watch")[-800:]))

    def esp(self, name):
        """The node's ESP stand-in (a directory: what regalia-esp-advance writes; nothing boots from it here)."""
        return self.nodes[name].dir / "esp"

    def _esp_args(self, n):
        esp = self.esp(n.name)
        if not esp.exists():
            esp.mkdir(mode=0o755)
            os.chmod(esp, 0o755)
        return ("--esp", str(esp), "--esp-lock", str(n.run / "esp-advance.lock"))

    def _esp_watch(self, n):
        """#66 B3: regalia-esp-advance.path's stand-in, at every new published chain: the chain to the node's ESP, then
        the TPM anchor. A run that fails is in its journal; anchored() says where the anchor is."""
        self._run(n, "esp-advance", unit=self.unit(n.name, "esp-watch"), args=self._esp_args(n),
                  extra=["--path-property=PathChanged=%s" % (n.state / node.PUBLISHED), "-p", "Type=oneshot"])

    def _esp_advance(self, n):
        """regalia-esp-advance's run at start (its unit is WantedBy=multi-user.target), once sync has published: the path
        unit's own service, started and waited for, so that two runs never overlap (one unit, as on a host)."""
        if not until(lambda: (n.state / node.PUBLISHED).exists(), 30, 0.5):
            raise RuntimeError("%s's sync published no chain" % n.name)
        unit = self.unit(n.name, "esp-watch") + ".service"
        if sh("systemctl", "start", unit, check=False).returncode != 0:
            raise RuntimeError("%s's regalia-esp-advance failed at start: %s" % (n.name, self.journal(n.name, "esp-watch")[-1500:]))

    def anchored(self, name):
        """The node's TPM anchor epoch (read as root)."""
        return self.node(name).anchor().value()

    def esp_epoch(self, name):
        """The epoch of the chain on the node's ESP stand-in, or None."""
        path = self.esp(name) / "EFI" / "regalia" / "membership.json"
        return membership.load(path.read_bytes(), membership.MAX_CHAIN_BYTES)[-1]["manifest"]["epoch"] if path.exists() else None

    def _run(self, n, service, oneshot=False, unit=None, extra=(), args=()):
        argv = ["systemd-run", "--unit", unit or self.unit(n.name, service), "--collect"] + list(extra)
        for prop in self.properties(n.name, service):
            argv += ["-p", prop]
        if oneshot:
            argv += ["--wait", "-p", "Type=oneshot"]
        done = sh(*(argv + ["/usr/bin/python3", "-Es", "-m", "deploy.baremetal.node", "--config", str(n.cfg_path), service] + list(args)), check=False)
        if done.returncode != 0:                      # what the unit itself said: a oneshot's own output is in its journal
            said = sh("journalctl", "-u", unit or self.unit(n.name, service), "-n", "30", "--no-pager", "-o", "cat", check=False).stdout
            raise RuntimeError("%s's %s failed (%d): %s | %s" % (n.name, service, done.returncode, done.stderr.strip()[-300:], said[-1500:]))

    # ---- a node replaced (#76, Phase 16) ----

    def add_node(self, name):
        """A new host for a node that failed for good: its own namespace on the switch, a fresh TPM (a new EK and
        AK), new WireGuard keys, its directories and clock. Not yet in any manifest."""
        n = NodeHere(self.work, name, max(m.index for m in self.members()) + 1)
        self.nodes[name], self.time[name], self.services[name] = n, True, ()
        for d in (n.dir / "etc", n.state, n.admission, n.run):
            d.mkdir(parents=True)
        os.chmod(n.dir, 0o711)
        self._wire(n)
        self._tpm(n)
        self._wg_keys(n)
        self.ids[name] = self._identity(n)
        self._authtime_for(n)
        return n

    def replacement(self, old, new, reuse=None, same_policy=False):
        """The manifest replacing `old` by `new` (one root-signed step, replacement.py), and the measurements
        document it binds: `new` enrolled ACTIVE with its own identities (or, for a refusal test, `reuse` of them
        taken from another node), `old` kept as RETIRED. Returns (candidate, document)."""
        example = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
        n = self.nodes[new]
        document = self.document if same_policy else \
            dict(self.document, nodes=dict(self.document["nodes"], **{new: {"accepted": [self._reference(n, example["pcrs"])]}}))
        entry = {"node_id": new, "state": "ACTIVE", "ek_name": self.ids[new][0], "ak_name": self.ids[new][1],
                 "wg_boot_pub": self.keys[new]["boot"][1], "wg_service_pub": self.keys[new]["service"][1], "hsm_serials": ["E2E3%s" % new.upper()]}
        current = self.manifest
        # #199: its SSH host key and its signing key; it takes the old one's place in every signer rule
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        ssh = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        entry.update(ssh_host_pub=ssh.hex(), signing_key=self.signing[new])
        if reuse:
            source = next(m for m in self.manifest["nodes"] if m["node_id"] == reuse[0])
            entry.update({k: source[k] for k in reuse[1]})
        nodes = [dict(m, state="RETIRED") if m["node_id"] == old else m for m in current["nodes"]] + [entry]
        candidate = dict(current, epoch=current["epoch"] + 1, prev_digest=membership.digest(current), nodes=nodes,
                         policy_version=measurements.version(document), issued_at="2026-10-%02dT00:00:00Z" % (1 + current["epoch"]))
        # the new node takes the old one's place in every signer rule, and nothing else changes (replacement.py)
        for k in ("heartbeat_signers", "activation_signers", "revocation_signers"):
            candidate[k] = membership.rename_party(current[k], old, new)
        return candidate, document

    def replace(self, old, new):
        """#76: `old` replaced by `new`, as an operator does it with the root. The candidate is checked as the root's
        operator checks it (measurements.check_replacement) and signed by the root; it is given to a running node (the
        seed) as advance() gives an epoch, and pulled by the other running node; neither `old` (the hardware that left keeps
        the chain it had) nor `new` (not yet set up) is touched by that. Every node's site configuration changes first (the
        operator's site change: a node that takes the epoch must know where the new node is), and the new node gets its anchor, the chain, the epoch's document and its two counters at 0: its first heartbeat comes
        from the nodes by sync (#199). #279's `enrol --replace` instead defines the counter AT a heartbeat the node
        verifies (Freshness.accept_first). Returns the envelope."""
        candidate, document = self.replacement(old, new)
        measurements.check_replacement(self.manifest, candidate, self.document, document, old, new)
        # the operator's site change first (every node's site configuration names c2), as on hosts: a node that takes the
        # epoch and runs wg-apply for it must already know where c2 is
        seed = next((name for name in self.nodes if name not in (old, new) and self.running(name)), None)
        if seed is None:                              # before any site file is rewritten (CodeRabbit)
            raise RuntimeError("replacing %s by %s needs a running node to take the epoch" % (old, new))
        for n in self.nodes.values():
            if n.name != old:
                self._configure(n)
        self.advance(seed, candidate=candidate, document=document)
        envelope = self.chain[-1]
        n = self.nodes[new]
        here = self.node(new)
        here.anchor().define()
        here.documents().put(document)
        for i, held in enumerate(self.chain):
            self.enrolled_store(here).commit(held, final=i == len(self.chain) - 1)
        with self._as_booted(new):                    # laid down by its policy, as at build (#389: the system key its set names)
            node.heartbeat_counter(here.cfg).define()
            node.signing_counter(here.cfg).define()
        sh("chown", "-R", "regalia-sync:regalia-sync", str(n.state))
        os.chmod(n.state, 0o755)
        sh("chown", "-R", "regalia-admission:regalia-admission", str(n.admission))
        os.chmod(n.admission, ADMISSION_DIR_MODE)            # as the shipped unit makes it (#345)
        return envelope

    # ---- #199: restrictive changes without the root (revoke.py), as the operators make them ----

    REVOKE_PROPOSE = ("import json, sys\nfrom deploy.baremetal import beat, node, revoke\nd = json.load(sys.stdin)\n"
                      "n = node.Node(node.load(d['cfg']))\nm = n.store().load()\n"
                      "nxt = revoke.candidate(m, d['target'], d['state'], beat._now(n.clock()))\ns = node.node_beat_signer(n)\n"
                      "sig = dict(revoke.node_signature(n.node_id, s._sign, nxt), key=s.key)\n"
                      "print(json.dumps({'manifest': nxt, 'signatures': [sig], 'reason': revoke.reason_ok(d['reason'])}))\n")
    REVOKE_COSIGN = ("import json, sys\nfrom deploy.baremetal import membership, node, revoke\nd = json.load(sys.stdin)\n"
                     "n = node.Node(node.load(d['cfg']))\nm = n.store().load()\ns = node.node_beat_signer(n)\n"
                     "half = revoke.cosign(m, d['half'], n.node_id, s.key, s._sign, lambda text: d['typed'])\n"
                     "full = {'manifest': half['manifest'], 'signatures': half['signatures']}\n"
                     "membership.require(revoke.met(m, full)[0], 'the signatures meet no revocation rule')\n"
                     "revoke.commit(n, full, node.Trail(n.path('sync-audit.jsonl'), 'sync'))\nprint(json.dumps(full))\n")
    REVOKE_IMPORT = ("import json, sys\nfrom deploy.baremetal import membership, node, revoke\nd = json.load(sys.stdin)\n"
                     "n = node.Node(node.load(d['cfg']))\nm = n.store().load()\n"
                     "membership.require(revoke.met(m, d['full'])[0], 'the signatures meet no revocation rule')\n"
                     "revoke.commit(n, d['full'], node.Trail(n.path('sync-audit.jsonl'), 'sync'))\nprint('{}')\n")

    @staticmethod
    def typed(manifest):
        """What the operator types to confirm a manifest signature: its epoch and the first eight hex digits of the SHA-256
        of what is signed (revoke.shown)."""
        return "%d %s" % (manifest["epoch"], hashlib.sha256(membership.DOMAIN + membership.canonical(manifest)).hexdigest()[:8])

    def revoke_by_nodes(self, proposer, cosigner, target, state, reason, owner_recovery=False, pull=None, beat=True):
        """`target` made `state` by two nodes, each at its own console (revoke.py propose, then cosign): the proposer's TPM
        signs the next manifest as its sync unit; the cosigner checks it against its own manifest, confirms (the operator's
        typing, played here), signs and commits it as its sync unit; the running nodes pull it from there. Returns the
        envelope, once the counting nodes running hold a heartbeat for its epoch (_beaten)."""
        half = json.loads(self._as_sync(proposer, self.REVOKE_PROPOSE, {"cfg": str(self.nodes[proposer].cfg_path), "target": target,
                                                                        "state": state, "reason": reason}).strip().splitlines()[-1])
        full = json.loads(self._as_sync(cosigner, self.REVOKE_COSIGN, {"cfg": str(self.nodes[cosigner].cfg_path), "half": half,
                                                                       "typed": self.typed(half["manifest"])}).strip().splitlines()[-1])
        return self._spread(cosigner, full, owner_recovery, pull, beat)

    def revoke_by_owner(self, importer, target, state, reason, owner_recovery=False, pull=None, beat=True):
        """`target` made `state` by the owner alone, off the nodes (revoke.py export, owner.py sign-manifest against the chain
        this machine holds, revoke.py import on `importer`, as its sync unit). Returns the envelope, as revoke_by_nodes."""
        from deploy.baremetal import owner, revoke
        nxt = revoke.candidate(self.manifest, target, state, int(time.time()))
        proposal = {"manifest": nxt, "signatures": [], "reason": reason}
        signed = owner.sign_manifest(self.manifest, proposal, lambda: self.owner_signer(0), lambda text: self.typed(nxt), say=lambda text: None)
        full = {"manifest": nxt, "signatures": signed["signatures"]}
        self._as_sync(importer, self.REVOKE_IMPORT, {"cfg": str(self.nodes[importer].cfg_path), "full": full})
        return self._spread(importer, full, owner_recovery, pull, beat)

    def _spread(self, committer, full, owner_recovery, pull=None, beat=True):
        """A restrictive envelope committed on `committer`: the fixture's view follows; the nodes in `pull` (default: every
        other running node that may authorize) take it by sync; with `beat`, the counting nodes running then hold its
        heartbeat (_beaten). A scenario that cuts a node off names who should take it, and waits for nothing more."""
        manifest = full["manifest"]
        self.chain.append(full)
        self.manifest = manifest
        if pull is None:
            pull = [n for n in self.nodes if n != committer and self.running(n) and membership.may(manifest, n, "authorize")]
        for name in pull:
            if not until(lambda name=name: self.node(name).store().load()["epoch"] == manifest["epoch"], 120, 2):
                raise RuntimeError("%s did not take epoch %d from %s" % (name, manifest["epoch"], committer))
        if beat:
            self._beaten(manifest, owner_recovery)
        return full

    def running(self, name):
        return sh("systemctl", "is-active", self.unit(name, "sync"), check=False).stdout.strip() == "active"

    def _as_sync(self, name, code, data):
        """Python `code` run as the node's sync unit runs (its identity, its namespace, blind to the others), `data`
        (JSON) on its standard input: for a write into the state a running sync holds, with no root-owned window."""
        argv = ["systemd-run", "--unit", self.unit(name, "as-sync"), "--collect", "--wait", "--pipe", "--quiet"]
        for prop in self.properties(name, "sync"):
            argv += ["-p", prop]
        return sh(*(argv + ["/usr/bin/python3", "-Es", "-c", code]), input=json.dumps(data)).stdout

    ASK = ("import json, sys\nfrom deploy.baremetal import membership, node, sync\nd = json.load(sys.stdin)\n"
           "n = node.Node(node.load(d['cfg']))\nsend = n.sources(n.manifest())[d['peer']]\nout = []\n"
           "for _ in range(d['times']):\n"
           "    out.append(json.loads(send(membership.canonical(dict({'v': sync.VERSION, 'op': d['op']}, **d['fields'])))))\n"
           "print(json.dumps(out))\n")

    def ask(self, name, peer, op, times=1, **fields):
        """`times` raw sync requests `op` from the node to `peer`, over its own service tunnel, as its sync unit
        sends them (its identity, its namespace, its tunnel address): the peer's answers, in order."""
        return json.loads(self._as_sync(name, self.ASK, {"cfg": str(self.nodes[name].cfg_path), "peer": peer, "op": op,
                                                         "times": times, "fields": fields}))

    def stop(self, name, power="cycle"):
        """The node's services stopped. power="cycle" (an orderly power-off and on) or "cut" (power lost): its /run
        emptied (tmpfs on a host), its tunnels gone, its TPM through the power loss (power_cycle) and its time no
        longer authenticated until it starts again. power=None: the services only, as a crash."""
        n = self.member(name)
        for unit in [self.unit(name, s) for s in ("admission", "sync", "wg-apply")] + \
                [self.unit(name, w) + t for w in ("wg-watch", "esp-watch") for t in (".path", ".service")] + \
                [self.unit(name, "ship-" + trail) for trail, _, _ in AUDIT_TRAILS]:
            sh("systemctl", "stop", unit, check=False)
            sh("systemctl", "reset-failed", unit, check=False)
        self.services[name] = ()
        if os.path.exists("/dev/mapper/e2e3-" + name):
            sh("cryptsetup", "close", "e2e3-" + name, check=False)
        if power:
            self.time[name] = False
            for entry in n.run.iterdir():
                shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
            for interface in ("wg-svc", "wg-unlock", "wg-boot"):
                n.in_ns("ip", "link", "del", interface, check=False)
            self.power_cycle(name, orderly=(power == "cycle"))

    # ---- the disks, the peer paths, the unlock (#70 PR 2) ----

    def disk(self, name):
        """The node's root volume: LUKS2 on a loop device, the recovery key in keyslot 0 (and its systemd-recovery
        token), a filesystem holding the marker."""
        n = self.nodes[name]
        image = n.dir / "disk.img"
        with open(image, "wb") as f:
            f.truncate(32 * 1024 * 1024)
        loop = sh("losetup", "--find", "--show", str(image)).stdout.strip()
        self.loops[name] = loop
        sh("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", *unlock.PBKDF, "--key-file", "-", loop, input=RECOVERY.decode())
        sh("cryptsetup", "token", "import", "--json-file", "-", loop, input='{"type":"systemd-recovery","keyslots":["0"]}')
        mapped = "e2e3-" + name
        sh("cryptsetup", "open", "--key-file", "-", loop, mapped, input=RECOVERY.decode())
        mnt = n.dir / "mnt"
        mnt.mkdir(exist_ok=True)
        sh("mkfs.ext4", "-q", "/dev/mapper/" + mapped)
        sh("mount", "/dev/mapper/" + mapped, str(mnt))
        (mnt / "marker").write_bytes(MARKER)
        sh("umount", str(mnt))
        sh("cryptsetup", "close", mapped)
        return loop

    def enrol(self, name, peers=None):
        """One peer path from each of `peers` (by default every other node the manifest lets authorize), as unlock's
        tests and #190 do it: the local half sealed to the node's own TPM under PCR 7 (the one its paths already
        share, when it has some); each peer mints a contribution in its real contributions file and wraps it to the
        node's one-time key; a keyslot and token per peer. And the node's AK enrolled in each peer's verifier (the
        credential challenge, activated by the node's TPM). Run while neither the node's nor the peers' services
        run (the fixture writes the peers' stores)."""
        n, loop = self.nodes[name], self.loops[name]
        held = [t for _, t in unlock.path_tokens(unlock.luks_meta(loop))]
        if held:                                          # the client unseals one local half for every path
            sealed = held[0]["local"]
            local = unlock.unseal_local(sealed, tpm2_device=n.tcti)
        else:
            local = os.urandom(32)
            sealed = unlock.seal_local(local, pcrs="7", tpm2_device=n.tcti)
        ek, ak = (n.dir / "ids" / "ek.pub").read_bytes(), (n.dir / "ids" / "ak.pub").read_bytes()
        if peers is None:
            peers = [p for p in self.nodes if p != name and membership.may(self.manifest, p, "authorize")]
        for peer in peers:
            here = self.node(peer)
            enrolment = unlock.Enrolment(name)
            wrapped = unlock.contribute(unlock.Contributions(here.path("contributions.json")), self.manifest, peer, name, enrolment.public, enrolment.fingerprint)
            epoch, secret = enrolment.open(wrapped, peer)
            unlock.enrol_path(loop, name, peer, epoch, local, sealed, secret, RECOVERY)
            attester = here.attester_for(self.manifest)
            credential, activated = n.dir / ("cred-" + peer), n.dir / ("secret-" + peer)
            credential.write_bytes(attester.challenge(name, ek, ak))
            before = os.environ.get("TPM2TOOLS_TCTI")
            os.environ["TPM2TOOLS_TCTI"] = n.tcti
            try:
                attest.node_activate(str(credential), str(activated))
                sh("tpm2_flushcontext", "-t", check=False)
            finally:
                os.environ.pop("TPM2TOOLS_TCTI") if before is None else os.environ.__setitem__("TPM2TOOLS_TCTI", before)
            attester.enroll(name, activated.read_bytes())
            for leftover in (credential, activated):
                leftover.unlink()
            sh("chown", "-R", "regalia-sync:regalia-sync", str(self.nodes[peer].state))
        del local, secret

    def recover(self, name):
        """#71's manual recovery: the node's volume opened by hand with its recovery key (the systemd-recovery
        keyslot, S1's one exception), its filesystem read back, closed again for the boot to open. Returns
        {rc, slot, peer, marker}: `peer` None for the recovery keyslot."""
        loop, mapped, mnt = self.loops[name], "e2e3-" + name, self.nodes[name].dir / "mnt"
        result = {"rc": None, "slot": None, "peer": "?", "marker": False}
        mounted = False
        try:
            opened = subprocess.run(["cryptsetup", "open", "--key-file", "-", "-v", loop, mapped], input=RECOVERY, capture_output=True)
            result["rc"] = opened.returncode
            found = re.search(rb"Key slot (\d+) unlocked", opened.stdout)
            if opened.returncode == 0 and found:
                result["slot"] = int(found.group(1))
                result["peer"] = self.keyslot_peer(name, result["slot"])
                sh("mount", "-o", "ro", "/dev/mapper/" + mapped, str(mnt))
                mounted = True
                result["marker"] = (mnt / "marker").read_bytes() == MARKER
        finally:
            if mounted:
                sh("umount", str(mnt), check=False)
            if os.path.exists("/dev/mapper/" + mapped):
                sh("cryptsetup", "close", mapped, check=False)
        return result

    def keyslot_peer(self, name, slot):
        """The peer whose path token names `slot` on the node's volume (None for the recovery keyslot)."""
        for _, token in unlock.path_tokens(unlock.luks_meta(self.loops[name])):
            if str(slot) in token["keyslots"]:
                return token["peer"]
        return None

    def unlock(self, name, timeout=180, rounds=5):
        """What the node's initrd does, less the boot: its WG-BOOT tunnel up in its namespace (bootnet's
        configuration, from the chain it holds), then the pre-root client (cmd/regalia-unlock, the real binary)
        with this fixture in systemd's two roles: the local half unsealed from the node's TPM and given as a
        credential (LoadCredentialEncrypted=), and systemd-cryptsetup asking for the volume's passphrase through
        the ask-password protocol (#70: the client is a password agent), in an ask directory of the node's own.
        The volume is opened with the answer (cryptsetup open -v), and the client, seeing it open, stands down.
        `rounds` is the client's -attempts. Returns {rc, peer, marker, stderr}: `peer` the one whose keyslot
        opened it, `marker` whether the filesystem reads back; rc "timeout" when it was still asking. rc 0 with
        no peer is NOT an unlock: an earlier session of this boot was on record, and the client asked nobody."""
        n, loop, mapped = self.nodes[name], self.loops[name], "e2e3-" + name
        manifest = self.node(name).store().load()          # the chain the node holds: its initrd's credentials say the same
        site = sitecfg.load(str(n.dir / "etc" / "site.json"))
        n.in_ns("ip", "link", "add", "wg-boot", "type", "wireguard")
        n.in_ns("wg", "setconf", "wg-boot", "/dev/stdin", input=bootnet.with_key(bootnet.boot_wg_conf(site, manifest), self.keys[name]["boot"][0]))
        n.in_ns("wg", "set", "wg-boot", "listen-port", str(site["boot_mesh"]["listen_port"]))
        n.in_ns("ip", "address", "add", "%s/%d" % (n.boot_address, site["boot_mesh"]["prefix"]), "dev", "wg-boot")
        n.in_ns("ip", "link", "set", "wg-boot", "up")
        config = n.dir / "unlock.json"
        config.write_text(json.dumps(unlock.boot_config(manifest, name, loop, [7, 11], bootnet.unlock_endpoints(site, manifest))))
        creds = n.dir / "creds"
        shutil.rmtree(creds, True)
        creds.mkdir(mode=0o700)
        tokens = [t for _, t in unlock.path_tokens(unlock.luks_meta(loop))]
        local = unlock.unseal_local(tokens[0]["local"], tpm2_device=n.tcti)
        with open(os.open(str(creds / unlock.LOCAL_NAME), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb") as f:
            f.write(local)
        del local
        # systemd-cryptsetup's request, as it writes one: ask.1 naming its reply socket and the volume's Id
        # in /tmp, and short: a UNIX socket path holds 108 bytes (not under the node's directory, whose paths are
        # longer); askpass.Find takes only a socket root owns inside this directory, and the fixture runs as root
        asks = pathlib.Path(tempfile.mkdtemp(prefix="ask-"))
        request = "cryptsetup:" + loop
        reply = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        reply.bind(str(asks / "sck.1"))
        (asks / "ask.1").write_text("[Ask]\nPID=%d\nSocket=%s\nAcceptCached=0\nEcho=0\nNotAfter=0\nSilent=0\nId=%s\n"
                                     % (os.getpid(), asks / "sck.1", request))
        volume = "/dev/mapper/" + mapped                                # there once opened: then the client stands down
        # In its own mount namespace, the other nodes' directories covered (as InaccessiblePaths= does for the units)
        blind = "".join("mount -t tmpfs -o ro,size=4k e2e3-blind %s; " % shlex.quote(str(o.dir)) for o in self.nodes.values() if o is not n)
        script = blind + 'exec "$@"'
        result = {"rc": None, "peer": None, "marker": False, "stderr": ""}
        mnt, mounted = n.dir / "mnt", False
        client = None
        try:
            env = dict(os.environ, CREDENTIALS_DIRECTORY=str(creds))
            argv = ["unshare", "--mount", "--propagation", "private", "bash", "-c", script, "bash",
                    "ip", "netns", "exec", n.ns, self.client, "-config", str(config), "-tpm", "unix:" + str(n.tpm_sock),
                    "-session-dir", str(n.run), "-ask-dir", str(asks), "-request", request, "-volume", volume, "-attempts", str(rounds)]
            client = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
            key, deadline = b"", time.monotonic() + timeout
            reply.settimeout(0.2)
            while time.monotonic() < deadline and client.poll() is None and not key:
                try:
                    datagram = reply.recv(4096)
                except socket.timeout:
                    continue
                if datagram.startswith(b"+"):
                    key = datagram[1:]
            if key:
                opened = subprocess.run(["cryptsetup", "open", "--key-file", "-", "-v", loop, mapped], input=key, capture_output=True)
                found = re.search(rb"Key slot (\d+) unlocked", opened.stdout)
                (asks / "ask.1").unlink()                               # answered: systemd-cryptsetup removes its request
                if opened.returncode == 0 and found:
                    result["peer"] = self.keyslot_peer(name, int(found.group(1)))
                    sh("mount", "-o", "ro", volume, str(mnt))
                    mounted = True
                    result["marker"] = (mnt / "marker").read_bytes() == MARKER
            try:
                _, err = client.communicate(timeout=max(5.0, deadline - time.monotonic()) if not key else 30)
                result["rc"], result["stderr"] = client.returncode, err[-1500:]
            except subprocess.TimeoutExpired:                         # still asking when the time ran out: no key
                client.kill()
                _, err = client.communicate()
                result["rc"], result["stderr"] = "timeout", (err or "")[-1500:]
        finally:
            if client is not None and client.poll() is None:
                client.kill()
                client.wait()
            if mounted:
                sh("umount", str(mnt), check=False)
            if os.path.exists(volume):
                sh("cryptsetup", "close", mapped, check=False)
            reply.close()
            shutil.rmtree(asks, True)
            shutil.rmtree(creds, True)
            n.in_ns("ip", "link", "del", "wg-boot", check=False)
        return result

    def lease(self, name):
        """The node's admission file, if it holds a lease that has not run out: {epoch, ...}; else None."""
        from deploy.baremetal import admission
        path = self.nodes[name].run / "admission" / "admission.json"
        try:
            document = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        return document if document.get("serve_until_boottime_ms", 0) > admission.boottime_ms() else None

    def lease_issuer(self, name):
        """The peer that issued the lease the node's admission holds (its lease.json), or None."""
        try:
            return json.loads((self.nodes[name].admission / "lease.json").read_text())["envelope"]["lease"]["issuer"]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    # ---- a partition (#69, 9.4) ----

    def partition(self, name, from_):
        """`name` cut off from the members `from_` on the service mesh (wg-svc's underlay port, both ways): an nftables
        table in `name`'s namespace ONLY, never on the host. heal() removes it. Deliberately not a full cut: the boot
        mesh (wg-unlock, 51820) stays up, because the window #69 measures is a node that cannot learn the new epoch
        yet can still be asked for a key (regalia-kms-3e)."""
        hosts = ", ".join(self.member(m).underlay for m in from_)
        rules = ("table inet e2e3cut {\n"
                 " chain out { type filter hook output priority 0; policy accept; ip daddr { %s } udp dport 51821 drop; }\n"
                 " chain in { type filter hook input priority 0; policy accept; ip saddr { %s } udp sport 51821 drop; }\n}\n") % (hosts, hosts)
        self.member(name).in_ns("nft", "-f", "-", input=rules)

    def heal(self, name):
        self.member(name).in_ns("nft", "delete", "table", "inet", "e2e3cut", check=False)

    def heartbeat_left(self, name):
        """Seconds until the heartbeat the node holds expires (its freshness state, read as root), or None."""
        import calendar
        held = self.node(name).freshness().held()
        if not held:
            return None
        return calendar.timegm(time.strptime(held["heartbeat"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ")) - time.time()

    def wg_peers(self, name, interface):
        """The public keys `interface` in the node's namespace has as peers."""
        return set(self.member(name).in_ns("wg", "show", interface, "peers", check=False).stdout.split())

    def owner_signature(self, manifest, which=0):
        """The owner's signature over a manifest (a restrictive change, which the owner alone may sign under v4)."""
        signer = self.owner_signer(which)
        return {"party": membership.OWNER, "key": signer.public(),
                "sig": signer.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}

    OWNER_PROPOSE = ("import json, sys\nfrom deploy.baremetal import node, owner\nd = json.load(sys.stdin)\n"
                     "n = node.Node(node.load(d['cfg']))\nt = node.Trail(n.path('sync-audit.jsonl'), 'sync')\n"
                     "print(json.dumps(owner.propose(n, node.node_beat_signer(n), t)))\n")
    OWNER_ACCEPT = ("import json, sys\nfrom deploy.baremetal import node, owner\nd = json.load(sys.stdin)\n"
                    "n = node.Node(node.load(d['cfg']))\nt = node.Trail(n.path('sync-audit.jsonl'), 'sync')\n"
                    "print(json.dumps({'left': int(owner.accept(n, d['envelope'], t))}))\n")

    def owner_beat(self, name, which=0):
        """#199's hand recovery (owner.py beat): `name` proposes and signs as its sync unit, the owner's key `which` co-signs
        after the operator's confirmation (played here: the epoch and the digest's first eight hex digits, as typed), and
        the node takes it as its sync unit. Returns the envelope."""
        from deploy.baremetal import owner
        cfg = str(self.nodes[name].cfg_path)
        proposal = json.loads(self._as_sync(name, self.OWNER_PROPOSE, {"cfg": cfg}).strip().splitlines()[-1])
        body = proposal["heartbeat"]
        typed = "%d %s" % (body["epoch"], owner.shown(body)[1][:8])
        envelope = owner.owner_sign(proposal, self.manifest, lambda: self.owner_signer(which), lambda text: typed, say=lambda text: None)
        self._as_sync(name, self.OWNER_ACCEPT, {"cfg": cfg, "envelope": envelope})
        return envelope

    def _beaten(self, manifest, owner_recovery=False, timeout=300):
        """#199: with two counting nodes running, each holds the heartbeat their own proposers sign for the new epoch
        (beat.Proposer goes at once when it holds none for it). With one, nobody can co-sign it: the node stays without a
        heartbeat for the epoch, as a host does until a human acts, and nothing is done here unless the scenario asked
        for the hand recovery (`owner_recovery`: owner_beat for that node). Never implicit (regalia-kms-3e's read)."""
        from deploy.baremetal import beat
        counting = [n for n in beat.counting_nodes(manifest) if self.running(n)]
        if len(counting) >= 2:
            missing = [n for n, held in self.fresh(counting, manifest["epoch"], timeout).items() if not held]
            if missing:
                raise RuntimeError("%s signed no heartbeat for epoch %d; their last beat events: %s" % (", ".join(missing), manifest["epoch"],
                                   json.dumps(self.beat_events(counting))[:3000]))
        elif owner_recovery:
            for name in counting:
                self.owner_beat(name)

    def fresh(self, names=None, epoch=None, timeout=300):
        """#199: wait until each node in `names` (default: every running node) holds a heartbeat for `epoch` (default: the
        current manifest's) that the NODES signed: no owner among its signers (an owner's hand-recovery heartbeat is
        owner_beat's, and says so). Returns {node: whether it does}."""
        epoch = self.manifest["epoch"] if epoch is None else epoch
        names = [n for n in self.nodes if self.running(n)] if names is None else list(names)
        return {name: bool(until(lambda name=name: self.holds_heartbeat(name, epoch) and membership.OWNER not in self.heartbeat_signers(name),
                                 timeout, 2)) for name in names}

    def beat_events(self, names, last=4):
        """{node: its last `last` heartbeat-signing events (beat-propose, the beat-sign answers it gave), from its sync trail}:
        why a node holds no heartbeat, when it holds none."""
        keep = ("event", "outcome", "epoch", "sequence", "subject", "reason")
        return {n: [{k: e.get(k) for k in keep if k in e} for e in self.trail(n)
                    if str(e.get("event", "")).startswith(("beat", "sync-beat", "owner-beat"))][-last:] for n in names}

    def heartbeat_signers(self, name):
        """The parties that signed the heartbeat the node holds (its freshness state, read as root): [] for none."""
        held = self.node(name).freshness().held()
        return [s.get("party") for s in (held or {}).get("signatures", [])]

    def holds_heartbeat(self, name, epoch):
        """Whether the node holds a heartbeat for `epoch` (its freshness state, read as root)."""
        held = self.node(name).freshness().held()
        return bool(held) and held["heartbeat"]["epoch"] == epoch

    def advance(self, seed, signer="root", document=None, owner_recovery=False, candidate=None, **states):
        """A new epoch with nodes' states changed ({node: state}), signed by the root or (signer "owner", a restrictive
        change) by the owner alone. A root-signed epoch reaches `seed`, a running node, as an operator gives it one:
        `deploy.baremetal.deliver` run as root (the real command: it commits as regalia-sync through the node's Store and
        republishes, the services running). An owner-signed one is committed into the seed's store with its services
        stopped (a crash: the same boot), and they start again. Nodes whose services are stopped are NOT written to:
        they take the epochs they missed by their own sync when they start (start(), _caught_up). The other running
        nodes are left to pull it from the seed with their real sync (their trails say from whom); the counting nodes
        then sign the epoch's heartbeat themselves (_beaten). Returns (the new manifest, when the seed
        started again). With `document`, the epoch commits to that measurement document (its policy_version). It goes
        into the seed's store with the epoch (deliver's --documents, or put beside the commit), as an operator's
        `measurements install` does on one host; every other node fetches it by sync with the epoch,
        and no node is ever judged by another epoch's document (#332)."""
        current = self.manifest
        nodes = [dict(n, state=states.get(n["node_id"], n["state"])) for n in current["nodes"]]
        manifest = candidate or dict(current, epoch=current["epoch"] + 1, prev_digest=membership.digest(current), nodes=nodes,
                                     issued_at="2026-10-%02dT00:00:00Z" % (1 + current["epoch"]))
        if document is not None and candidate is None:
            manifest["policy_version"] = measurements.version(document)
        if signer == "owner":
            # #199: no revocation key under v4: a restrictive change is the owner's alone (or two nodes', revoke.py)
            envelope = {"manifest": manifest, "signatures": [self.owner_signature(manifest)]}
        elif signer == "root":
            envelope = self.signed(manifest)
        else:
            raise ValueError("signer must be root or owner, not %r" % signer)
        others = [name for name in self.nodes if name != seed and self.running(name)]
        running = [name for name in others if membership.may(manifest, name, "authorize")]   # they pull it from the seed
        services = self.services[seed]
        delivered = signer == "root" and self.running(seed)
        if not delivered:
            self.stop(seed, power=None)
        if document is not None:
            self.document = document
        if not delivered:                             # the seed only: every other node's store is its own sync's
            if document is not None:                  # by digest, beside the documents it holds: nothing is replaced (#332)
                self.node(seed).documents().put(document)
            with self._as_booted(seed):               # its booted system's key: it stopped in the same boot, in its system phase
                self.node(seed).store().commit(envelope)
            sh("chown", "-R", "regalia-sync:regalia-sync", str(self.nodes[seed].state))
        self.chain.append(envelope)
        self.manifest = manifest
        since = time.time()
        if delivered:
            self.deliver(seed, [envelope], [document] if document is not None else [])
        else:
            self.start(seed, services)
        for name in running:
            if not until(lambda: self.node(name).store().load()["epoch"] == manifest["epoch"], 120, 2):
                raise RuntimeError("%s did not take epoch %d from %s" % (name, manifest["epoch"], seed))
        # #66 B3: neither deliver nor sync moves the anchor; each running node's regalia-esp-advance writes the epoch to its
        # ESP and then anchors it. Checked at every advance, so tier N keeps the anchor's progression (regalia-kms-24)
        for name in [seed] + running:
            if not until(lambda: self.anchored(name) == manifest["epoch"] and self.esp_epoch(name) == manifest["epoch"], 60, 1):
                raise RuntimeError("%s's TPM anchor is at %s and its ESP at %s, not epoch %d: regalia-esp-advance did not follow | %s"
                                   % (name, self.anchored(name), self.esp_epoch(name), manifest["epoch"],
                                      self.journal(name, "esp-watch")[-800:]))
        self._beaten(manifest, owner_recovery)
        return manifest, since

    def deliver(self, name, envelopes, documents):
        """`sudo python3 -Es -m deploy.baremetal.deliver --config … --chain … --documents …` for the running node `name`, as
        an operator gives a node the root's epochs (#199: what `authority accept` did): root reads the files, the node's
        regalia-sync commits them through its Store and republishes. Run here in a transient unit of root's, named
        e2e3-<node>-deliver-<epoch>, that sees /run/systemd as the node's services see it. Returns the command's output."""
        d = self.work / "deliver"
        d.mkdir(mode=0o700, exist_ok=True)
        chain = d / ("chain-%d.json" % envelopes[-1]["manifest"]["epoch"])
        chain.write_text(json.dumps(envelopes))
        args = ["/usr/bin/python3", "-Es", "-m", "deploy.baremetal.deliver", "--config", str(self.nodes[name].cfg_path), "--chain", str(chain)]
        if documents:
            args.append("--documents")
            for i, document in enumerate(documents):
                path = d / ("document-%d-%d.json" % (envelopes[-1]["manifest"]["epoch"], i))
                path.write_text(json.dumps(document))
                args.append(str(path))
        # in a transient unit of root's with the node's /run/systemd as its services see it (the system-phase PCR key and
        # its signatures, bound as _props binds them): where an operator runs it on the host, and what the node's policy
        # sessions read when the anchor is written by policy (#242 B3, 95's read); the other nodes' directories hidden
        n = self.member(name)
        pcr = n.dir / "pcr"
        props = ["WorkingDirectory=" + str(self.code), "Environment=PYTHONDONTWRITEBYTECODE=1",
                 "BindReadOnlyPaths=%s:%s" % (pcr / "tpm2-pcr-signature.json", "/run/systemd/tpm2-pcr-signature.json"),
                 "BindReadOnlyPaths=%s:%s" % (pcr / "tpm2-pcr-public-key.pem", signkey.PCR_PUBLIC_KEY_PATH)]
        props += ["InaccessiblePaths=" + str(o.dir) for o in self.members() if o is not n]
        done = sh("systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit", self.unit(name, "deliver-%d" % envelopes[-1]["manifest"]["epoch"]),
                  *[a for p in props for a in ("-p", p)], *args, check=False,
                  stdin=subprocess.DEVNULL)
        if done.returncode != 0:
            raise RuntimeError("deliver to %s failed (%d): %s" % (name, done.returncode, (done.stderr or done.stdout).strip()[-600:]))
        return done.stdout

    def journal(self, name, service, lines=40):
        return sh("journalctl", "-u", self.unit(name, service), "-n", str(lines), "--no-pager", "-o", "cat", check=False).stdout

    def trail(self, name):
        """The node's sync trail, parsed."""
        path = self.nodes[name].state / "sync-audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]

    # ---- audit completeness (#340) ----

    def _audit_start(self):
        """A one-run CA, the real collector on the host's loopback (mutual TLS), and the shippers' client identity,
        readable by regalia-audit-ship only (its user, from the shipped sysusers file)."""
        sh("systemd-sysusers", str(ROOT / "deploy" / "baremetal" / "units" / "regalia-audit-ship.sysusers.conf"))
        for binary in ("regalia-audit-ship", "regalia-audit-collector"):
            if not os.access(self.audit_bin / binary, os.X_OK):
                raise RuntimeError("audit=True needs REGALIA_AUDIT_BIN naming a directory with %s" % binary)
        d = self.audit_dir = self.work / "audit"
        d.mkdir(mode=0o711)
        # the binaries as a host installs them: root's, 0755, where the shipper's user can reach them. Built under a
        # runner's home (0750), regalia-audit-ship could not even execute its own binary (#355's CI: status 203/EXEC)
        bin_dir = d / "bin"
        bin_dir.mkdir(mode=0o755)
        for binary in ("regalia-audit-ship", "regalia-audit-collector"):
            shutil.copy(self.audit_bin / binary, bin_dir / binary)
            os.chmod(bin_dir / binary, 0o755)
        self.audit_bin = bin_dir

        def issue(name, extensions):
            sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(d / (name + ".key")),
               "-out", str(d / (name + ".csr")), "-subj", "/CN=" + name)
            (d / (name + ".ext")).write_text(extensions)
            sh("openssl", "x509", "-req", "-in", str(d / (name + ".csr")), "-CA", str(d / "ca.pem"), "-CAkey", str(d / "ca.key"),
               "-CAcreateserial", "-days", "1", "-out", str(d / (name + ".pem")), "-extfile", str(d / (name + ".ext")))
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(d / "ca.key"),
           "-out", str(d / "ca.pem"), "-subj", "/CN=e2e3-audit-ca", "-days", "1",
           "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
        issue("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        issue("shipper", "extendedKeyUsage=clientAuth\n")
        ship = d / "ship"                             # as /etc/regalia/audit-ship: root's, its key the shipper's group's
        ship.mkdir(mode=0o750)
        shutil.chown(ship, "root", "regalia-audit-ship")
        for source, target, mode in (("shipper.pem", "client.crt", 0o644), ("shipper.key", "client.key", 0o640), ("ca.pem", "collector-ca.pem", 0o644)):
            shutil.copy(d / source, ship / target)
            shutil.chown(ship / target, "root", "regalia-audit-ship")
            os.chmod(ship / target, mode)
        heads = d / "heads"                           # as its StateDirectory: the shipper's own
        heads.mkdir(mode=0o700)
        shutil.chown(heads, "regalia-audit-ship", "regalia-audit-ship")
        # the receipt key, as the collector holds it on a host (PKCS#8 Ed25519, 0600): receipts are signed, as on a real
        # collector, and audit_complete checks each stream's head receipt against it (regalia-kms-48 on #355)
        sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", str(d / "receipt.key"))
        os.chmod(d / "receipt.key", 0o600)
        sh("openssl", "pkey", "-in", str(d / "receipt.key"), "-pubout", "-out", str(d / "receipt.pub"))
        self.collector_state = d / "collector"
        sh("systemd-run", "--unit", COLLECTOR_UNIT, "--collect", str(self.audit_bin / "regalia-audit-collector"), "-state", str(self.collector_state),
           "-listen", "127.0.0.1:%d" % COLLECTOR_PORT, "-tls-cert", str(d / "collector.pem"), "-tls-key", str(d / "collector.key"),
           "-client-ca", str(d / "ca.pem"), "-receipt-key", str(d / "receipt.key"))
        if not until(lambda: sh("systemctl", "is-active", COLLECTOR_UNIT, check=False).stdout.strip() == "active", 20, 0.5):
            raise RuntimeError("the audit collector did not start")

    def _trail_path(self, name, trail):
        n = self.nodes[name]
        return {"sync": n.state / "sync-audit.jsonl", "admission": n.admission / "audit.jsonl"}[trail]

    def _trail_groups(self, name):
        """Each of the node's trails (and its rotated archives) back in its reader group, 0640, as its writer keeps it on a
        host (trails.py, #286). This fixture's `chown -R <service>:<service>` of a node's directories, made where a unit's
        StateDirectory= would make the owner, also resets the GROUP, which no host does: the shipper, in the trail's
        reader group only, could then read nothing (the first CI run of #355 shipped no line at all)."""
        for trail, _, _ in AUDIT_TRAILS:
            path = self._trail_path(name, trail)
            for f in [path] + sorted(path.parent.glob(path.name + ".*")):
                if f.is_file() and not f.is_symlink():
                    shutil.chown(f, group="regalia-audit-" + trail)
                    os.chmod(f, 0o640)

    def _ship_start(self, name):
        """regalia-audit-ship for each of the node's own trails, with regalia-audit-ship@<trail>'s identity: its own user, the
        trail's reader group and nothing else (the shipped drop-ins, #286), no capability, a read-only system but for its
        head files; one stream per node, e2e3-<node>.<trail>. (Not its whole sandbox, nor its metrics file:
        e2e/audit-ship-systemd.py runs the shipped unit itself.)"""
        d = self.audit_dir
        self._trail_groups(name)
        for trail, _, _ in AUDIT_TRAILS:
            unit = self.unit(name, "ship-" + trail)
            if sh("systemctl", "is-active", unit, check=False).stdout.strip() == "active":
                continue
            sh("systemctl", "reset-failed", unit, check=False)
            sh("systemd-run", "--unit", unit, "--collect", "-p", "User=regalia-audit-ship", "-p", "SupplementaryGroups=regalia-audit-" + trail,
               "-p", "CapabilityBoundingSet=", "-p", "NoNewPrivileges=yes", "-p", "ProtectSystem=strict",
               "-p", "ReadWritePaths=%s" % (d / "heads"),
               str(self.audit_bin / "regalia-audit-ship"), "-trail", trail, "-path", str(self._trail_path(name, trail)),
               "-collector", "https://127.0.0.1:%d" % COLLECTOR_PORT, "-site", "e2e3-" + name,
               "-tls-cert", str(d / "ship" / "client.crt"), "-tls-key", str(d / "ship" / "client.key"),
               "-server-ca", str(d / "ship" / "collector-ca.pem"), "-head", str(d / "heads" / ("%s-%s.head.json" % (name, trail))),
               "-interval", "1s")

    def audit_stream(self, name, trail):
        """The collector's committed events for the node's trail (its stream e2e3-<node>.<trail>), in order."""
        found = list((self.collector_state / "streams").glob("*/site-e2e3-%s.%s.jsonl" % (name, trail)))
        if len(found) != 1:
            return []
        return [json.loads(line) for line in found[0].read_text().splitlines() if line.strip()]

    GENESIS = "sha256:" + "0" * 64            # internal/audit: the previous hash of a stream's first event

    def receipt(self, name, trail, sequence):
        """The collector's signed receipt for position `sequence` of the node's stream, asked as its shipper asks: over
        mutual TLS with the shipper's certificate, for its own stream (X-Regalia-Site)."""
        import ssl
        import urllib.request
        d = self.audit_dir
        context = ssl.create_default_context(cafile=str(d / "ca.pem"))
        context.load_cert_chain(str(d / "shipper.pem"), str(d / "shipper.key"))
        request = urllib.request.Request("https://127.0.0.1:%d/v1/receipt?sequence=%d" % (COLLECTOR_PORT, sequence),
                                         headers={"X-Regalia-Site": "e2e3-%s.%s" % (name, trail)})
        with urllib.request.urlopen(request, context=context, timeout=10) as answer:
            return json.loads(answer.read())

    def _receipt_problem(self, name, trail, lines, stream):
        """What is wrong at position len(lines) of the node's stream (the SNAPSHOT's end, audit_complete) as its receipt
        states it, or None: the signature (Ed25519 over internal/audit.ReceiptPreimage, with the receipt key) and what it
        names, the collector's event there, the snapshot's last line and the running line chain over the snapshot,
        recomputed here; and the shipper's head file, naming at least that many lines committed (it goes on shipping)."""
        import ssl
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        n = len(lines)
        try:
            got = self.receipt(name, trail, n)
        except OSError as failure:
            return "no receipt for the head (%s)" % failure
        chain = "0" * 64
        for line in lines:
            chain = hashlib.sha256(bytes.fromhex(chain) + hashlib.sha256(line).digest()).hexdigest()
        identity = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.audit_dir / "shipper.pem").read_text())).hexdigest()
        preimage = "\n".join(["regalia.collector.receipt/v1", identity, "e2e3-%s.%s" % (name, trail), str(got.get("sequence")),
                              got.get("event_hash", ""), got.get("line_sha256", ""), got.get("line_chain", "")]).encode()
        key = serialization.load_pem_public_key((self.audit_dir / "receipt.pub").read_bytes())
        try:
            key.verify(bytes.fromhex(got.get("signature", "")), preimage)
        except (InvalidSignature, ValueError):
            return "the head receipt's signature does not verify under the receipt key"
        want = (n, stream[n - 1].get("hash"), hashlib.sha256(lines[-1]).hexdigest(), chain)
        if (got.get("sequence"), got.get("event_hash"), got.get("line_sha256"), got.get("line_chain")) != want:
            return "the receipt at %d names %r, not %r" % (n, got, want)
        try:
            head = json.loads((self.audit_dir / "heads" / ("%s-%s.head.json" % (name, trail))).read_text())
        except (OSError, ValueError) as failure:
            return "the shipper's head file cannot be read (%s)" % failure
        if not isinstance(head.get("committed"), int) or not n <= head["committed"] <= len(stream):
            return "the shipper's head file says %r committed: not between the snapshot's %d and the collector's %d" % (
                head.get("committed"), n, len(stream))
        return None

    def audit_complete(self, timeout=180):
        """{(node, trail): what is wrong} for every node trail (sync, admission) the collector does not hold, line for
        line, UP TO A SNAPSHOT of the trail taken when this is called. The trails go on growing while it waits (the
        services run): judged against the trail as re-read at each look, a line written after the shipper's last pass
        failed it (regalia-kms#409, d9: 400 trail lines, 399 in the collector). So the snapshot, taken first, is the
        point of judgement, and the collector must hold AT LEAST it:
          - a trail must have been written (an empty one is not complete);
          - the trail as it is now still begins with the snapshot (append-only);
          - every event the collector holds (the snapshot's and any after it) is the trail's line at its position: event i
            at sequence i+1, the first chained to genesis and each to the one before, naming its line by its SHA-256
            (newline included), each DENY still a deny;
          - at the snapshot's end, the signed receipt and the shipper's head file say so.
        Empty when complete. Waits up to `timeout` for the shippers' passes. A node stopped by the scenario ships what its
        trail holds once it runs again: its shippers are started here."""
        for name in self.nodes:
            self._ship_start(name)

        def read(name, trail):
            path = self._trail_path(name, trail)
            return path.read_bytes().splitlines(keepends=True) if path.exists() else []
        snapshot = {(name, trail): read(name, trail) for name in self.nodes for trail, _, _ in AUDIT_TRAILS}

        def problems(receipts=False):
            wrong = {}
            for name in self.nodes:
                for trail, _, _ in AUDIT_TRAILS:
                    lines = snapshot[(name, trail)]
                    if not lines:
                        wrong[(name, trail)] = "the trail was never written"
                        continue
                    stream = self.audit_stream(name, trail)
                    now = read(name, trail)
                    if now[:len(lines)] != lines:
                        wrong[(name, trail)] = "the trail no longer begins with the %d lines it held: it was rewritten" % len(lines)
                        continue
                    if len(stream) < len(lines):
                        said = self.journal(name, "ship-" + trail, 3).strip().replace("\n", " | ")
                        wrong[(name, trail)] = "%d trail lines, %d in the collector (its shipper: %s)" % (len(lines), len(stream), said[-300:])
                        continue
                    if len(stream) > len(now):
                        wrong[(name, trail)] = "the collector holds %d events, the trail only %d lines" % (len(stream), len(now))
                        continue
                    for i, (line, event) in enumerate(zip(now, stream)):
                        detail = event.get("detail") or {}
                        if event.get("sequence") != i + 1:
                            wrong[(name, trail)] = "event %d carries sequence %r" % (i, event.get("sequence"))
                        elif event.get("previous_hash") != (stream[i - 1].get("hash") if i else self.GENESIS):
                            wrong[(name, trail)] = "event %d does not chain to %s" % (i, "the one before" if i else "genesis")
                        elif detail.get("line_sha256") != hashlib.sha256(line).hexdigest():
                            wrong[(name, trail)] = "line %d: the collector holds another line" % i
                        elif json.loads(line).get("outcome") == "DENY" and event.get("decision") != "deny":
                            wrong[(name, trail)] = "line %d is a DENY the collector holds as %r" % (i, event.get("decision"))
                        else:
                            continue
                        break
                    else:
                        if receipts:
                            problem = self._receipt_problem(name, trail, lines, stream)
                            if problem:
                                wrong[(name, trail)] = problem
            return wrong
        until(lambda: not problems(), timeout, 2)
        until(lambda: not problems(receipts=True), 30, 2)      # the shipper's head file follows its next pass
        return problems(receipts=True)

    def moved_by_sync(self, name, since, epoch):
        """The peer whose sync round moved `name` to `epoch`, from its collector stream since `since`; None if none did
        (regalia-kms-1e and 3e on #370 and #393; one copy for every scenario).

        A sync-apply event is filed under the manifest held when its round BEGAN (sync.Client.pull), and a pull goes round
        after round on ONE source until it has nothing more: the round that moved the node is the LAST sync-apply before
        the node's first pull event under `epoch` (that round's sync-heartbeat, or the next round's sync-apply), filed
        under the epoch before and from the same peer. Not merely the last ALLOW: every pull that received nothing is an
        ALLOW under the old epoch too, and must not stand in for the move. A round refused after it had moved the
        membership counts only when it says so ("had moved from epoch N-1 to N"), and the answer says it was refused."""
        events = self.audit_has(name, "sync", since=since)
        first = next((i for i, e in enumerate(events) if e.get("epoch") == epoch and e.get("event") in ("sync-heartbeat", "sync-apply")), None)
        if first is None:
            return None
        rounds = [e for e in events[:first] if e.get("event") == "sync-apply"]
        if not rounds or rounds[-1].get("epoch") != epoch - 1 or rounds[-1].get("peer") != events[first].get("peer"):
            return None
        moved = rounds[-1]
        if moved.get("outcome") == "ALLOW":
            return moved.get("peer")
        if "had moved from epoch %d to %d" % (epoch - 1, epoch) in (moved.get("reason") or ""):
            return "%s (refused after it moved)" % moved.get("peer")
        return None

    def audit_has(self, name, trail, since=0, **fields):
        """The node's trail lines that its COLLECTOR stream holds (line i taken from the trail only where it hashes to
        what event i names: what the collector committed is that line, nothing read from free text), whose fields include
        `fields` (a value that is a callable is a predicate), at or after `since` (their "at").

        A TRAIL'S "at" IS WHOLE SECONDS (node.Trail: int(now())), and `since` is usually a time.time(): a line written in
        the same second as `since` was taken has an "at" BELOW it. So `since` is taken to its second: never a line
        missed for that (rolling-threenode's step 9 failed so, now and then: regalia-kms-24, after #370)."""
        path = self._trail_path(name, trail)
        lines = path.read_bytes().splitlines(keepends=True) if path.exists() else []
        out = []
        for line, event in zip(lines, self.audit_stream(name, trail)):
            if (event.get("detail") or {}).get("line_sha256") != hashlib.sha256(line).hexdigest():
                break                                  # from here on the collector holds another line: nothing is taken
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if not isinstance(value, dict) or value.get("at", 0) < int(since):
                continue
            if all(v(value.get(k)) if callable(v) else value.get(k) == v for k, v in fields.items()):
                out.append(value)
        return out

    def close(self):
        self.stop_threads = True
        for n in self.members():
            self.stop(n.name, power=None)
        if self.audit:
            sh("systemctl", "stop", COLLECTOR_UNIT, check=False)
            sh("systemctl", "reset-failed", COLLECTOR_UNIT, check=False)
        for n in self.members():
            try:
                pid = int((n.dir / "tpm.pid").read_text())
                os.kill(pid, 15)
                until(lambda: not os.path.exists("/proc/%d" % pid), 10, 0.2)      # gone before its state is removed
            except (OSError, ValueError):
                pass
            sh("ip", "netns", "del", n.ns, check=False)
        sh("ip", "netns", "del", SWITCH, check=False)
        for loop in self.loops.values():
            sh("losetup", "-d", loop, check=False)
