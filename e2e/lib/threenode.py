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
  * heartbeats: signed by the test revocation key the chain names, written into each node's freshness
    state, as the revocation authority's pull would deliver them (into a running node's under its sync
    unit's own identity);
  * a new epoch (advance): the authority's publication, given to one seed node while its services are down;
    the running nodes pull it from there with their real sync;
  * the pre-root client's two systemd roles: the local half, unsealed by this fixture from the node's TPM,
    passed as a plain credential (on a host LoadCredentialEncrypted= unseals it under the TPM's policy), and
    the key socket (socket activation, systemd-cryptsetup's side played by this fixture);
  * regalia-wg-apply.path: the same trigger (PathChanged= on the published chain), a transient path unit.

Underlay: a bridge in a switch namespace, node i at 192.0.2.(10*i)/24. Each node's site configuration names
the others' underlay addresses, its boot mesh (wg-unlock) and its service mesh (wg-svc), as on a host.
Root only; it changes the machine (namespaces, interfaces, transient units), so its callers run only on a
throwaway machine (a GitHub-hosted runner)."""
import configparser
import grp
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.baremetal import attest, authtime, bootnet, heartbeat, measurements, membership, node, sitecfg, unlock, wgsvc   # noqa: E402
import tests.test_baremetal_heartbeat as hbt                                                        # noqa: E402  the test root and revocation keys

NAMES = ("a", "b", "c")
RECOVERY = b"cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"     # the TEST recovery key (as the unlock tests')
MARKER = b"regalia-kms root volume marker"
SWITCH = "e2e3-sw"
UNIT_PREFIX = "e2e3-"


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


class Cluster:
    def __init__(self, work, names=NAMES):
        self.work = pathlib.Path(work)
        self.nodes = {n: NodeHere(self.work, n, i + 1) for i, n in enumerate(names)}
        self.time = {n: True for n in names}          # authenticated time, per node (the stand-in's switch)
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

    # ---- building ----

    def build(self):
        # the services' users and groups, from the shipped file (regalia-sync, regalia-admission, their trails' groups)
        sh("systemd-sysusers", str(ROOT / "deploy" / "baremetal" / "units" / "regalia.sysusers.conf"))
        os.chmod(self.work, 0o711)                    # each node's directory is reached through it, read in it only
        # the checkout may sit where the services' users cannot go (a runner's home is 0750): they run a root-owned copy
        shutil.copytree(ROOT / "deploy", self.code / "deploy", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        sh("chown", "-R", "root:root", str(self.code))
        sh("chmod", "-R", "u=rwX,go=rX", str(self.code))
        self._network()
        for n in self.nodes.values():
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
        for n in self.nodes.values():
            self.beat(n.name, 1)
            # owned as the units' StateDirectory= would make them: the services are not root
            sh("chown", "-R", "regalia-sync:regalia-sync", str(n.state))
            os.chmod(n.state, 0o755)
            sh("chown", "-R", "regalia-admission:regalia-admission", str(n.admission))
            os.chmod(n.admission, 0o700)

    def _network(self):
        sh("ip", "netns", "add", SWITCH)
        sh("ip", "netns", "exec", SWITCH, "ip", "link", "add", "br0", "type", "bridge")
        sh("ip", "netns", "exec", SWITCH, "ip", "link", "set", "br0", "up")
        for n in self.nodes.values():
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

    def power_cycle(self, name, orderly=True):
        """The node's TPM through a power loss: (orderly) TPM2_Shutdown(CLEAR) first, then the process stopped and
        started again on the same state, which sends TPM2_Startup(CLEAR): resetCount one higher, the PCRs back to
        their reset values, every transient object and session gone, as on a host. Without `orderly`, a cut: no
        Shutdown, which a TPM counts against its dictionary-attack limit (#57)."""
        n = self.nodes[name]
        if orderly:
            sh("tpm2_shutdown", "-c", "-T", n.tcti, check=False)
        pid = int((n.dir / "tpm.pid").read_text())
        os.kill(pid, 15)
        if not until(lambda: not os.path.exists("/proc/%d" % pid), 10, 0.2):
            raise RuntimeError("%s's software TPM did not stop" % name)
        self._tpm(n)

    def reset_count(self, name):
        """The TPM's resetCount (TPM2_ReadClock): one higher after each power cycle."""
        out = sh("tpm2_readclock", "-T", self.nodes[name].tcti).stdout
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
        return attest.name_of(attest.public_area(ek, "the EK public area")).hex(), attest.ak_identity(ak)[0].hex(), ak.hex()

    def _reference(self, n, pcrs):
        """The node's accepted measurement set, read from its TPM, as pcr_survey.py records it on a host."""
        sh("tpm2_pcrread", "-T", n.tcti, "sha256:" + ",".join(str(i) for i in pcrs), "-o", str(n.dir / "pcrs.bin"))
        raw = (n.dir / "pcrs.bin").read_bytes()
        sh("tpm2_quote", "-T", n.tcti, "-c", attest.AK_HANDLE, "-g", "sha256", "-l", "sha256:%d" % pcrs[0], "-q", "00" * 32,
           "-m", str(n.dir / "ref.quote"), "-s", str(n.dir / "ref.sig"), "-f", "plain")
        sh("tpm2_flushcontext", "-T", n.tcti, "-t", check=False)
        return {"label": "e2e-" + n.name, "tpm_firmware_version": attest.parse_quote((n.dir / "ref.quote").read_bytes())["firmware_version"],
                "pcrs": {str(i): raw[32 * k:32 * (k + 1)].hex() for k, i in enumerate(pcrs)}}

    def _identities_and_chain(self):
        example = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
        self.ids = {n.name: self._identity(n) for n in self.nodes.values()}
        self.document = {"schema": measurements.SCHEMA, "name": "e2e3",
                         "nodes": {n.name: {"accepted": [self._reference(n, example["pcrs"])]} for n in self.nodes.values()}}
        self.manifest = {"schema": membership.SCHEMA, "epoch": 1, "prev_digest": "", "policy_version": measurements.version(self.document),
                         "issued_at": "2026-10-01T00:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)],
                         "nodes": [{"node_id": n.name, "state": "ACTIVE", "ek_name": self.ids[n.name][0], "ak_name": self.ids[n.name][1],
                                    "wg_boot_pub": self.keys[n.name]["boot"][1], "wg_service_pub": self.keys[n.name]["service"][1],
                                    "hsm_serials": ["E2E3%s" % n.name.upper()]} for n in self.nodes.values()]}
        self.chain = [self.signed(self.manifest)]

    @staticmethod
    def signed(manifest, key=None, signer="root"):
        key = key or (hbt.ROOT if signer == "root" else hbt.REVOKE)
        return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key), "sig": key.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}

    def _configure(self, n):
        example = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
        others = [o for o in self.nodes.values() if o is not n]
        site = {"schema": "regalia.baremetal-site/v1", "site": "e2e3-" + n.name, "host_ipv4": n.underlay, "kms_port": 8443, "ssh_port": 22,
                "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["203.0.113.128/32"], "admin_cidrs": ["203.0.113.0/28"],
                "outbound": [{"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514},
                             {"name": "ntp", "cidr": "203.0.113.193/32", "proto": "udp", "port": 123}],
                "boot_mesh": {"node_id": n.name, "interface": "wg-unlock", "listen_port": 51820, "address": n.boot_address, "unlock_port": 7443,
                              "nic_mac": "52:54:00:12:34:%02x" % (0x50 + n.index), "prefix": 24, "gateway": None,
                              "peers": [{"node_id": o.name, "underlay": o.underlay, "address": o.boot_address} for o in others]},
                "service_mesh": {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444, "authority": None}}
        (n.dir / "etc" / "site.json").write_text(json.dumps(site))
        (n.dir / "etc" / "measurements.json").write_text(json.dumps(self.document))
        cfg = dict(example, node_id=n.name, site=str(n.dir / "etc" / "site.json"), root_key=hbt.pub(hbt.ROOT), tcti=n.tcti,
                   state_dir=str(n.state), admission_dir=str(n.admission), run_dir=str(n.run),
                   wg_service_key=str(n.dir / "etc" / "wg-service.key"), measurements=str(n.dir / "etc" / "measurements.json"),
                   time_servers=["nts1.e2e3.invalid", "nts2.e2e3.invalid"], pull_interval=10)
        n.cfg_path.write_text(json.dumps(cfg))

    def node(self, name):
        """The node as its services see it (deploy/baremetal/node.Node), from its configuration."""
        return node.Node(node.load(str(self.nodes[name].cfg_path)))

    def _anchor_and_store(self, n):
        here = self.node(n.name)
        anchor = here.anchor()
        anchor.define()
        here.store().commit(self.chain[0])
        node.heartbeat_counter(here.cfg).define()

    # ---- the stand-ins ----

    def _authtime(self):
        """Authenticated time, per node: authtime's own Service and status file, with a reading that says chrony
        is synchronised to two NTS sources, or (cluster.time[n] False) that no source answers."""
        for n in self.nodes.values():
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

    def beat(self, name, sequence, manifest=None):
        """A heartbeat signed by the test revocation key, delivered into the node's freshness state."""
        manifest = manifest or self.manifest
        self.node(name).freshness().accept(hbt.beat(manifest, sequence, issued=int(time.time())), manifest)

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
        """systemd-run -p for one service of one node: its namespace, the installed unit's identity, and no view of
        the other nodes' directories."""
        n = self.nodes[name]
        props = ["NetworkNamespacePath=/run/netns/" + n.ns, "WorkingDirectory=" + str(self.code), "Environment=PYTHONDONTWRITEBYTECODE=1"]
        props += ["%s=%s" % (key, value) for key, value in self.identity(service).items()]
        props += ["InaccessiblePaths=" + str(o.dir) for o in self.nodes.values() if o is not n]
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
        if not self.time[name]:                       # booted again: its time is checked again (chrony, on a host)
            self.time[name] = True
            self.authtimes[name].step()
        for service in services:
            if service == "wg-apply" and not until(lambda: (n.state / node.PUBLISHED).exists(), 30, 0.5):
                raise RuntimeError("%s's sync published no chain" % name)
            if service == "admission":                # regalia-boot-session.service, Before= it: a session when the unlock client left none
                self._run(n, "boot-session", oneshot=True)
            self._run(n, service, oneshot=(service == "wg-apply"))
            if service == "wg-apply":                 # and again at every new chain, as regalia-wg-apply.path runs it
                self._run(n, "wg-apply", unit=self.unit(name, "wg-watch"),
                          extra=["--path-property=PathChanged=%s" % (n.state / node.PUBLISHED), "-p", "Type=oneshot"])
        self.services[name] = tuple(services)

    def _run(self, n, service, oneshot=False, unit=None, extra=()):
        argv = ["systemd-run", "--unit", unit or self.unit(n.name, service), "--collect"] + list(extra)
        for prop in self.properties(n.name, service):
            argv += ["-p", prop]
        if oneshot:
            argv += ["--wait", "-p", "Type=oneshot"]
        sh(*(argv + ["/usr/bin/python3", "-Es", "-m", "deploy.baremetal.node", "--config", str(n.cfg_path), service]))

    def running(self, name):
        return sh("systemctl", "is-active", self.unit(name, "sync"), check=False).stdout.strip() == "active"

    def _as_sync(self, name, code, data):
        """Python `code` run as the node's sync unit runs (its identity, its namespace, blind to the others), `data`
        (JSON) on its standard input: for a write into the state a running sync holds, with no root-owned window."""
        argv = ["systemd-run", "--unit", self.unit(name, "as-sync"), "--collect", "--wait", "--pipe", "--quiet"]
        for prop in self.properties(name, "sync"):
            argv += ["-p", prop]
        sh(*(argv + ["/usr/bin/python3", "-Es", "-c", code]), input=json.dumps(data))

    def stop(self, name, power="cycle"):
        """The node's services stopped. power="cycle" (an orderly power-off and on) or "cut" (power lost): its /run
        emptied (tmpfs on a host), its tunnels gone, its TPM through the power loss (power_cycle) and its time no
        longer authenticated until it starts again. power=None: the services only, as a crash."""
        n = self.nodes[name]
        for unit in [self.unit(name, s) for s in ("admission", "sync", "wg-apply")] + [self.unit(name, "wg-watch") + t for t in (".path", ".service")]:
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

    def enrol(self, name):
        """One peer path from each other node (enrolment, as unlock's tests and #190 do it): the local half sealed
        to the node's own TPM under PCR 7; each peer mints a contribution in its real contributions file and wraps
        it to the node's one-time key; a keyslot and token per peer. And the node's AK enrolled in each peer's
        verifier (the credential challenge, activated by the node's TPM). Run before the peers' services start."""
        n, loop = self.nodes[name], self.loops[name]
        local = os.urandom(32)
        sealed = unlock.seal_local(local, pcrs="7", tpm2_device=n.tcti)
        ek, ak = (n.dir / "ids" / "ek.pub").read_bytes(), (n.dir / "ids" / "ak.pub").read_bytes()
        for peer in [p for p in self.nodes if p != name]:
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
        credential (LoadCredentialEncrypted=), the key socket passed (socket activation), and the volume opened
        with the key that comes back (systemd-cryptsetup). Returns {rc, peer, marker, stderr}: `peer` the one
        whose keyslot opened it, `marker` whether the filesystem reads back."""
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
        path = str(n.dir / "key.sock")
        if os.path.exists(path):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        asker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        asker.connect(path)                                        # systemd-cryptsetup, waiting for its key

        fd = listener.fileno()
        # In its own mount namespace, the other nodes' directories covered (as InaccessiblePaths= does for the
        # units); the listener moved to descriptor 3 (sd_listen_fds) by the shell, no preexec_fn (two unlocks run
        # from two threads in 10.5); LISTEN_PID the client's own: the shell's, which execs ip, which execs the client.
        blind = "".join("mount -t tmpfs -o ro,size=4k e2e3-blind %s; " % shlex.quote(str(o.dir)) for o in self.nodes.values() if o is not n)
        script = blind + ("" if fd == 3 else "exec 3<&%d %d<&-; " % (fd, fd)) + 'LISTEN_PID=$$ exec "$@"'
        result = {"rc": None, "peer": None, "marker": False, "stderr": ""}
        mnt, mounted = n.dir / "mnt", False
        try:
            env = dict(os.environ, LISTEN_FDS="1", CREDENTIALS_DIRECTORY=str(creds))
            argv = ["unshare", "--mount", "--propagation", "private", "sh", "-c", script, "sh",
                    "ip", "netns", "exec", n.ns, self.client, "-once", "-config", str(config),
                    "-tpm", "unix:" + str(n.tpm_sock), "-session-dir", str(n.run), "-wait", "1s", "-rounds", str(rounds)]
            try:
                done = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, pass_fds=(fd,))
                result["rc"], result["stderr"] = done.returncode, done.stderr[-1500:]
            except subprocess.TimeoutExpired as late:            # still asking when the time ran out: no key
                result["rc"], result["stderr"] = "timeout", (late.stderr or b"")[-1500:].decode(errors="replace")
            listener.close()
            asker.settimeout(5)
            key = asker.recv(4096)
            if key:
                opened = subprocess.run(["cryptsetup", "open", "--key-file", "-", "-v", loop, mapped], input=key, capture_output=True)
                found = re.search(rb"Key slot (\d+) unlocked", opened.stdout)
                if opened.returncode == 0 and found:
                    result["peer"] = self.keyslot_peer(name, int(found.group(1)))
                    sh("mount", "-o", "ro", "/dev/mapper/" + mapped, str(mnt))
                    mounted = True
                    result["marker"] = (mnt / "marker").read_bytes() == MARKER
        finally:
            if mounted:
                sh("umount", str(mnt), check=False)
            if os.path.exists("/dev/mapper/" + mapped):
                sh("cryptsetup", "close", mapped, check=False)
            asker.close()
            listener.close()
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

    def wg_peers(self, name, interface):
        """The public keys `interface` in the node's namespace has as peers."""
        return set(self.nodes[name].in_ns("wg", "show", interface, "peers", check=False).stdout.split())

    BEAT = ("import json, sys\nfrom deploy.baremetal import node\nd = json.load(sys.stdin)\n"
            "node.Node(node.load(d['cfg'])).freshness().accept(d['beat'], d['manifest'])\n")

    def advance(self, seed, signer="root", **states):
        """A new epoch with nodes' states changed ({node: state}), signed by the root or the revocation key. The
        authority's publication, stood in for: `seed`, a running node, has its services stopped (a crash: the same
        boot), takes the epoch into its store with its heartbeat, and starts again. Nodes whose services are
        stopped take it into their stores as they are (they would pull it when they come back). The other running
        nodes are left to pull it from the seed with their real sync (their trails say from whom); each then gets
        the epoch's heartbeat, written under its sync unit's identity. Returns (the new manifest, when the seed
        started again)."""
        current = self.manifest
        nodes = [dict(n, state=states.get(n["node_id"], n["state"])) for n in current["nodes"]]
        manifest = dict(current, epoch=current["epoch"] + 1, prev_digest=membership.digest(current), nodes=nodes,
                        issued_at="2026-10-%02dT00:00:00Z" % (1 + current["epoch"]))
        envelope = self.signed(manifest, signer=signer)
        running = [name for name in self.nodes if name != seed and self.running(name)]
        services = self.services[seed]
        self.stop(seed, power=None)
        for name in self.nodes:
            if name in running:
                continue
            self.node(name).store().commit(envelope)
            self.beat(name, manifest["epoch"] + 1, manifest)
            sh("chown", "-R", "regalia-sync:regalia-sync", str(self.nodes[name].state))
        self.chain.append(envelope)
        self.manifest = manifest
        since = time.time()
        self.start(seed, services)
        for name in running:
            if not until(lambda: self.node(name).store().load()["epoch"] == manifest["epoch"], 120, 2):
                raise RuntimeError("%s did not take epoch %d from %s" % (name, manifest["epoch"], seed))
            self._as_sync(name, self.BEAT, {"cfg": str(self.nodes[name].cfg_path), "manifest": manifest,
                                            "beat": hbt.beat(manifest, manifest["epoch"] + 1, issued=int(time.time()))})
        return manifest, since

    def journal(self, name, service, lines=40):
        return sh("journalctl", "-u", self.unit(name, service), "-n", str(lines), "--no-pager", "-o", "cat", check=False).stdout

    def trail(self, name):
        """The node's sync trail, parsed."""
        path = self.nodes[name].state / "sync-audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]

    def close(self):
        self.stop_threads = True
        for name in self.nodes:
            self.stop(name, power=None)
        for n in self.nodes.values():
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
