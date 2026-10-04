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
    state, as the revocation authority's pull would deliver them.

Underlay: a bridge in a switch namespace, node i at 192.0.2.(10*i)/24. Each node's site configuration names
the others' underlay addresses, its boot mesh (wg-unlock) and its service mesh (wg-svc), as on a host.
Root only; it changes the machine (namespaces, interfaces, transient units), so its callers run only on a
throwaway machine (a GitHub-hosted runner)."""
import configparser
import grp
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.baremetal import attest, authtime, heartbeat, measurements, membership, node, wgsvc   # noqa: E402
import tests.test_baremetal_heartbeat as hbt                                                        # noqa: E402  the test root and revocation keys

NAMES = ("a", "b", "c")
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

    # ---- building ----

    def build(self):
        # the services' users and groups, from the shipped file (regalia-sync, regalia-admission, their trails' groups)
        sh("systemd-sysusers", str(ROOT / "deploy" / "baremetal" / "units" / "regalia.sysusers.conf"))
        os.chmod(self.work, 0o711)                    # each node's directory is reached through it, read in it only
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
        # the socket is the tss group's, 0660, as /dev/tpmrm0 is on a host: the services reach it through the group
        server = "type=unixio,path=%s,mode=0660,gid=%d" % (n.tpm_sock, grp.getgrnam("tss").gr_gid)
        done = sh("swtpm", "socket", "--tpm2", "--server", server, "--ctrl", "type=unixio,path=%s.ctrl" % n.tpm_sock,
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
        props = ["NetworkNamespacePath=/run/netns/" + n.ns, "WorkingDirectory=" + str(ROOT), "Environment=PYTHONDONTWRITEBYTECODE=1"]
        props += ["%s=%s" % (key, value) for key, value in self.identity(service).items()]
        props += ["InaccessiblePaths=" + str(o.dir) for o in self.nodes.values() if o is not n]
        return props

    def start(self, name, services=("sync", "wg-apply")):
        """The node's services, each a transient unit in its namespace, as a host runs them: sync first (it
        publishes the chain the others verify), wg-apply once the chain is published."""
        n = self.nodes[name]
        if not self.time[name]:                       # booted again: its time is checked again (chrony, on a host)
            self.time[name] = True
            self.authtimes[name].step()
        for service in services:
            if service == "wg-apply" and not until(lambda: (n.state / node.PUBLISHED).exists(), 30, 0.5):
                raise RuntimeError("%s's sync published no chain" % name)
            argv = ["systemd-run", "--unit", self.unit(name, service), "--collect"]
            for prop in self.properties(name, service):
                argv += ["-p", prop]
            if service == "wg-apply":
                argv += ["--wait", "-p", "Type=oneshot"]
            sh(*(argv + ["/usr/bin/python3", "-Es", "-m", "deploy.baremetal.node", "--config", str(n.cfg_path), service]))

    def stop(self, name, power="cycle"):
        """The node's services stopped. power="cycle" (an orderly power-off and on) or "cut" (power lost): its /run
        emptied (tmpfs on a host), its tunnels gone, its TPM through the power loss (power_cycle) and its time no
        longer authenticated until it starts again. power=None: the services only, as a crash."""
        n = self.nodes[name]
        for service in ("admission", "sync", "wg-apply"):
            sh("systemctl", "stop", self.unit(name, service), check=False)
            sh("systemctl", "reset-failed", self.unit(name, service), check=False)
        if power:
            self.time[name] = False
            for entry in n.run.iterdir():
                shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
            for interface in ("wg-svc", "wg-unlock", "wg-boot"):
                n.in_ns("ip", "link", "del", interface, check=False)
            self.power_cycle(name, orderly=(power == "cycle"))

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
