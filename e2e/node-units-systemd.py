#!/usr/bin/env python3
"""The node's four units under a real systemd (#80, step 3b): they start, reach what their sandboxes let
them reach, and do their jobs, up to a peer's lease, the KMS daemon serving on it, and a revocation ending it.

    REGALIA_E2E_BIN=<dir with regalia-kms (-tags piv), regalia-audit-collector> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_E2E_BIN python3 -Es e2e/node-units-systemd.py

IT CHANGES THE MACHINE, so it runs only on a GitHub-hosted runner (RUNNER_ENVIRONMENT=github-hosted: not
a self-hosted one, where GITHUB_ACTIONS is set too), or where REGALIA_NODE_HOST_OK equals the machine's
own /etc/machine-id; and never where a TPM, /etc/regalia, /usr/lib/regalia-kms or /var/lib/regalia-sync
already exists (a KMS host, or one being set up). It gives a software TPM the device name /dev/tpmrm0,
replaces the system chrony's configuration (the system clock follows two private NTS servers on the
loopback), creates the user regalia-sync, installs the units, and writes /etc/regalia and /var/lib/regalia-*.

THE TPM is swtpm. Where the kernel has the vTPM proxy it sits behind the kernel's resource manager, as on a
host; GitHub's Azure kernel has none, and there it is swtpm's CUSE device, which has NO resource manager:
one command buffer, no per-connection context, so two processes using it at once could receive each
other's responses, and sessions survive between processes (on a host the kernel flushes them when a
connection closes). Part 1 therefore lets one unit at a time use the TPM after the first one. Part 2 needs
several at once (regalia-sync writes the TPM while the path unit's regalia-wg-apply reads it), and a first
run without a resource manager showed exactly that collision: so part 2 puts tpm2-abrmd, a resource
manager, in front of the device and gives the units its TCTI (below: what that changes). The test rests
nothing on a session kept across processes (attest.activate does that: #190; a's AK is enrolled at b by
hand, as the rest of the provisioning is).

What part 1 shows, on the units as shipped (deploy/baremetal/units):

  0  controls: the TPM device is the tss group's 0660, and root without capabilities is held to that
  1  regalia-authtime: as root in the _chrony group, with one capability and an empty /etc, /var and /run
     around it, it reaches chronyd and publishes "authenticated" while two NTS servers agree, and "not
     authenticated" when one stops
  2  provisioning by hand (#190 is not built): the first manifest committed under the TPM anchor
  3  regalia-sync, as its own user with no capability, opens the TPM through the tss group, keeps the
     store and publishes the chain; regalia-wg-apply, root with CAP_NET_ADMIN only, reads that chain,
     verifies it against the TPM anchor, and brings wg-svc and wg-unlock up, read back; sync then binds
     both listeners
  4  the recovery-key boot path (#191): with no unlock client this boot, the lease service, run by hand as
     its own user, refuses for want of a session and writes nothing, and cannot write /run/regalia;
     started as a unit, it pulls in regalia-boot-session (root, no capability), which makes the pair, root's
     0644; then regalia-admission, as regalia-admission with no capability, verifies the chain against the
     TPM anchor and writes the admission file in its own directory: "not admitted" because no peer answers
     (b and c are not running: that is part 2). The kernel reports the service's uids as that user's, and
     the host probe agrees
  5  each unit's sandbox as systemd applied it (systemctl show), what regalia-authtime's process really
     sees, and what chrony does with a group-writable /run/chrony (observed, not asserted)

Part 2: peer b, in a network namespace, on its own software TPM (a socket: it is the fixture, not what is
tested), running the product's sync.Server with a real attestation verifier and lease signer, reached
over real WireGuard. No revocation authority is configured: b receives what the root and the revocation
key sign, by hand.

HOW PART 2 DIFFERS FROM PRODUCTION, stated so nothing is read into it:
  * a's TPM is behind tpm2-abrmd (D-Bus), not the kernel's /dev/tpmrm0: the units' DevicePolicy is not
    exercised here (part 1 does that), and tabrmd keeps a disconnected client's sessions reclaimable where
    the kernel flushes them, so nothing that uses a session across processes is proven by it (#65).
  * the KMS daemon runs as the invoking user through systemd-run, not as the shipped regalia-kms.service
    (its user, sandbox, AppArmor profile and credentials): what is proven is the admission contract
    between the units and the daemon, not the daemon's own confinement (that is e2e/kms-hardened-serve.sh).

  6  b's tunnel to node a comes up from the same manifest
  7  catch-up: b holds epoch 2 and its heartbeat; regalia-sync pulls both over the tunnel, publishes, and
     the path unit runs regalia-wg-apply for the new chain
  8  the KMS daemon (SoftHSM, as a unit named regalia-kms.service) is up and NOT ready; regalia-admission
     re-attests to b with a's TPM, b's TPM signs a lease, the admission file admits, and the daemon signs
  9  b receives the manifest that revokes a: it refuses to renew, by name, and the daemon stops serving at
     the end of the lease it holds, with nobody touching it. (A revoked node is told nothing by its peers,
     so a's own chain never shows the revocation: the lease running out is what stops it.)
"""
import base64
import datetime
import grp
import hashlib
import http.client
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deploy.baremetal import admission, attest, authtime, enrol, heartbeat, lease, measurements, membership, metrics, node, os_probe, sync, wgsvc   # noqa: E402
import tests.test_baremetal_heartbeat as hbt                                    # noqa: E402  the root and revocation keys, and beat()

PREFIX = "/usr/lib/regalia-kms"
UNITS = ("regalia-authtime.service", "regalia-wg-apply.service", "regalia-wg-apply.path", "regalia-boot-session.service",
         "regalia-admission.service", "regalia-sync.service", "regalia-authority-authtime.service")
ADMISSION_FILE = "/run/regalia/admission/admission.json"
DAEMON_UNITS = ("regalia-kms.service", "regalia-audit-collector.service")
NS, A_TCTI = "regalia-e2e-b", "device:/dev/tpmrm0"
SITE, DEVICE, OBJECT, PRINCIPAL = "e2e-site", "softhsm-e2e", "e2e-signing-key", "spiffe://regalia/workload/e2e"
passed, failed = 0, 0


def ok(condition, text, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  \033[32mPASS\033[0m %s" % text)
    else:
        failed += 1
        print("  \033[31mFAIL\033[0m %s%s" % (text, (": %s" % (detail,)) if detail != "" else ""))
    sys.stdout.flush()


def header(text):
    print("\n\033[1m### %s\033[0m" % text)
    sys.stdout.flush()


def sh(*argv, check=True, **kw):
    done = subprocess.run(list(argv), capture_output=True, text=True, **kw)
    if check and done.returncode != 0:
        raise SystemExit("node-units-systemd: %s failed (%d): %s %s" % (" ".join(argv[:3]), done.returncode, done.stdout.strip()[-800:], done.stderr.strip()[-800:]))
    return done


def until(what, seconds, interval=1.0):
    deadline, last = time.monotonic() + seconds, None
    while time.monotonic() < deadline:
        try:
            last = what()
            if last:
                return last
        except Exception as failure:      # noqa: BLE001 - keep trying until the deadline, then say what it was
            last = failure
        time.sleep(interval)
    return last


def journal(unit, lines=30):
    return sh("journalctl", "-u", unit, "-n", str(lines), "--no-pager", check=False).stdout


def show(unit, *properties):
    out = sh("systemctl", "show", unit, "-p", ",".join(properties), check=False).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


STOP = []


def inside(fn):
    """fn() in a thread that has entered b's network namespace: sockets it makes, threads it starts and
    commands it runs live there."""
    out = {}

    def enter():
        try:
            fd = os.open("/run/netns/" + NS, os.O_RDONLY)
            try:
                os.setns(fd, os.CLONE_NEWNET)
            finally:
                os.close(fd)
            out["value"] = fn()
        except BaseException as failure:                                   # noqa: BLE001 - handed to the caller
            out["error"] = failure
    thread = threading.Thread(target=enter)
    thread.start()
    thread.join()
    if "error" in out:
        raise out["error"]
    return out["value"]


def in_ns(argv, **kw):
    return subprocess.run(["ip", "netns", "exec", NS] + list(argv), **kw)


def signed(manifest, key=None, signer="root"):
    key = key or hbt.ROOT
    return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key),
                                                "sig": key.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}


def identity(tcti, out):
    """An EK and a persistent AK, as attest.node_init makes them: (EK name, AK name, AK public area hex)."""
    out.mkdir()
    before = os.environ.get("TPM2TOOLS_TCTI")
    os.environ["TPM2TOOLS_TCTI"] = tcti
    try:
        attest.node_init(str(out))
        sh("tpm2_flushcontext", "-t", check=False)        # a TPM with no resource manager keeps what each call loaded
    finally:
        os.environ.pop("TPM2TOOLS_TCTI") if before is None else os.environ.__setitem__("TPM2TOOLS_TCTI", before)
    ek, ak = (out / "ek.pub").read_bytes(), (out / "ak.pub").read_bytes()
    return attest.name_of(attest.public_area(ek, "the EK public area")).hex(), attest.ak_identity(ak)[0].hex(), ak.hex()


def reference(work, tcti, pcrs):
    """a's accepted measurement set, read from a's TPM: what pcr_survey.py would record on a host."""
    sh("tpm2_pcrread", "-T", tcti, "sha256:" + ",".join(str(i) for i in pcrs), "-o", str(work / "pcrs.bin"))
    raw = (work / "pcrs.bin").read_bytes()
    sh("tpm2_quote", "-T", tcti, "-c", attest.AK_HANDLE, "-g", "sha256", "-l", "sha256:%d" % pcrs[0], "-q", "00" * 32,
       "-m", str(work / "ref.quote"), "-s", str(work / "ref.sig"), "-f", "plain")
    sh("tpm2_flushcontext", "-T", tcti, "-t", check=False)
    return {"label": "e2e-a", "tpm_firmware_version": attest.parse_quote((work / "ref.quote").read_bytes())["firmware_version"],
            "pcrs": {str(i): raw[32 * n:32 * (n + 1)].hex() for n, i in enumerate(pcrs)}}


def peer_tpm(work):
    """b's TPM: swtpm on a socket of the test's own (b is the fixture here, not what is tested)."""
    (work / "b-tpm").mkdir()
    sh("swtpm", "socket", "--tpm2", "--server", "type=unixio,path=%s" % (work / "b-tpm.sock"), "--ctrl", "type=unixio,path=%s.ctrl" % (work / "b-tpm.sock"),
       "--tpmstate", "dir=%s" % (work / "b-tpm"), "--flags", "not-need-init,startup-clear", "--daemon")
    until(lambda: (work / "b-tpm.sock").exists(), 10, 0.2)
    return "swtpm:path=%s" % (work / "b-tpm.sock")


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_NODE_HOST_OK") != machine):
        print("node-units-systemd: refused: this changes the machine (a TPM device, the system chrony and clock, a user, units, "
              "/etc/regalia). It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/dev/tpm0", "/dev/tpmrm0", "/etc/regalia", PREFIX, "/var/lib/regalia-sync") if os.path.exists(p)]
    if present:
        print("node-units-systemd: refused: %s exists: this looks like a KMS host or one being set up" % ", ".join(present))
        return 2
    if os.geteuid() != 0:
        print("node-units-systemd: run as root")
        return 2
    binaries = pathlib.Path(os.environ.get("REGALIA_E2E_BIN", "/nonexistent"))
    if not all((binaries / name).is_file() for name in ("regalia-kms", "regalia-audit-collector")) or not os.environ.get("SUDO_USER"):
        print("node-units-systemd: REGALIA_E2E_BIN must name a directory with regalia-kms (built with -tags piv) and regalia-audit-collector built, "
              "and it must run under sudo (the daemon runs as the invoking user)")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="node-units-"))
    os.chmod(work, 0o711)                  # the software TPM runs as tss, under it
    try:
        return scenario(work, binaries, os.environ["SUDO_USER"])
    finally:
        STOP.append(True)
        for name in DAEMON_UNITS + tuple(reversed(UNITS)) + ("tpm2-abrmd.service",):
            sh("systemctl", "stop", name, check=False)
        sh("ip", "netns", "del", NS, check=False)
        dropin = pathlib.Path("/etc/systemd/system/tpm2-abrmd.service.d/e2e.conf")
        if dropin.exists():
            dropin.unlink()
            sh("systemctl", "daemon-reload", check=False)
        sh("ip", "link", "del", "e2e-b0", check=False)
        print("\nnode-units-systemd: %d passed, %d failed" % (passed, failed))


def tpm(work):
    """A software TPM as a character device the units open as a host's: /dev/tpmrm0, the tss group's, 0660.
    The kernel's vTPM proxy where the kernel has it; else (GitHub's Azure kernel is built without it)
    swtpm's CUSE device under that name, which needs no kernel module but FUSE's CUSE, and is a TPM
    without the kernel's resource manager (see the module's docstring). Returns (how, whether the test
    set the device's group and mode itself)."""
    state = work / "tpm"
    state.mkdir()
    shutil.chown(state, "tss", "tss")
    if sh("modprobe", "tpm_vtpm_proxy", check=False).returncode == 0:
        done = sh("swtpm", "chardev", "--vtpm-proxy", "--tpm2", "--tpmstate", "dir=%s" % state, "--flags", "not-need-init,startup-clear",
                  "--daemon", "--log", "file=%s" % (work / "swtpm.log"))
        how = "the kernel's vTPM proxy (%s)" % (done.stdout + done.stderr).strip()
    else:
        sh("modprobe", "cuse", check=False)
        (work / "swtpm.log").touch()
        shutil.chown(work / "swtpm.log", "tss", "tss")
        sh("swtpm", "cuse", "-n", "tpmrm0", "--tpm2", "--tpmstate", "dir=%s" % state, "--log", "file=%s" % (work / "swtpm.log"),
           "--runas", "tss")
        until(lambda: os.path.exists("/dev/tpmrm0"), 10, 0.2)
        sh("swtpm_ioctl", "-i", "/dev/tpmrm0")
        sh("tpm2_startup", "-c", "-T", "device:/dev/tpmrm0")
        how = "swtpm's CUSE device"
    sh("udevadm", "settle", check=False)
    # the distribution's rule (tpm-udev: KERNEL=="tpmrm[0-9]*", group tss, 0660) where udev applied it
    by_test = sh("stat", "-c", "%G %a", "/dev/tpmrm0", check=False).stdout.strip() != "tss 660"
    if by_test:
        shutil.chown("/dev/tpmrm0", "root", "tss")
        os.chmod("/dev/tpmrm0", 0o660)
    return how, by_test


def nts_server(work, n):
    """One NTS server on 127.0.0.<n+1>, from a copy of chronyd (unconfined by the distribution's profile)."""
    copy = work / "chronyd-server"
    if not copy.exists():
        shutil.copy(shutil.which("chronyd") or "/usr/sbin/chronyd", copy)
    address = "127.0.0.%d" % (n + 1)
    if not (work / ("s%d.crt" % n)).exists():
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
           "-keyout", str(work / ("s%d.key" % n)), "-out", str(work / ("s%d.crt" % n)), "-subj", "/CN=" + address,
           "-addext", "subjectAltName=IP:" + address)
    conf = work / ("s%d.conf" % n)
    conf.write_text("local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s\nntsservercert %s\nallow 127.0.0.0/8\n"
                    "cmdport 0\nbindcmdaddress %s\npidfile %s\nntsdumpdir %s\n"
                    % (21120 + n, 21460 + n, address, work / ("s%d.key" % n), work / ("s%d.crt" % n), work / ("s%d.sock" % n),
                       work / ("s%d.pid" % n), work))
    return subprocess.Popen([str(copy), "-x", "-U", "-u", "root", "-n", "-f", str(conf)], stdout=open(work / ("s%d.log" % n), "a"), stderr=subprocess.STDOUT)


def chrony(work):
    """Two NTS servers on the loopback (each with its own certificate), and the system chrony configured as
    authtime.conf() renders it, pointed at them, through the shipped drop-in (#303): /etc/chrony/regalia.conf,
    under the distribution's AppArmor profile, the package's own chrony.conf untouched."""
    servers = [nts_server(work, n) for n in (1, 2)]
    package_conf = hashlib.sha256(pathlib.Path("/etc/chrony/chrony.conf").read_bytes()).hexdigest()
    text = authtime.conf(["127.0.0.2", "127.0.0.3"])
    for n, address in enumerate(("127.0.0.2", "127.0.0.3"), 1):
        text = text.replace("server %s nts iburst\n" % address, "server %s port %d nts ntsport %d iburst minpoll 0 maxpoll 1\n" % (address, 21120 + n, 21460 + n))
    for n in (1, 2):                       # where the distribution's AppArmor profile lets chronyd read
        shutil.copy(work / ("s%d.crt" % n), "/etc/chrony/e2e-s%d.crt" % n)
    text += "".join("ntstrustedcerts /etc/chrony/e2e-s%d.crt\n" % n for n in (1, 2))
    pathlib.Path(enrol.CHRONY_CONF).write_text(text)
    # the package's other ways to run chronyd, from its own configuration or with sources added at run time (#303)
    sh("systemctl", "mask", "chronyd-restricted.service", "chrony-dnssrv@.timer")
    os.makedirs("/etc/systemd/system/chrony.service.d", exist_ok=True)
    shutil.copy(ROOT / "deploy" / "baremetal" / "units" / "chrony.service.d" / "regalia.conf", "/etc/systemd/system/chrony.service.d/regalia.conf")
    sh("systemctl", "daemon-reload")
    sh("systemctl", "restart", "chrony")
    started = show("chrony.service", "ExecStart", "Conflicts", "ActiveState")
    ok("-f %s" % enrol.CHRONY_CONF in started["ExecStart"] and started["ActiveState"] == "active",
       "chronyd runs from %s through the shipped drop-in, under the distribution's AppArmor profile" % enrol.CHRONY_CONF, started)
    ok("systemd-timesyncd.service" in started["Conflicts"], "systemd-timesyncd conflicts with it: one thing sets the clock", started["Conflicts"])
    ok(hashlib.sha256(pathlib.Path("/etc/chrony/chrony.conf").read_bytes()).hexdigest() == package_conf,
       "the package's /etc/chrony/chrony.conf is untouched")
    # a template (chrony-dnssrv@.timer) has no UnitFileState to show: a mask is the link to /dev/null
    masked = [os.path.realpath("/etc/systemd/system/" + name) for name in ("chronyd-restricted.service", "chrony-dnssrv@.timer")]
    ok(masked == ["/dev/null", "/dev/null"], "the package's chronyd-restricted and chrony-dnssrv timer are masked", masked)
    leap = until(lambda: "Using right/UTC timezone to obtain leap second data" in journal("chrony.service"), 20)
    ok(leap, "chronyd reads leap seconds from right/UTC under the distribution's AppArmor profile", journal("chrony.service")[-400:])
    state = os.stat("/var/lib/chrony")
    ok(stat.S_IMODE(state.st_mode) & 0o007 == 0 and pwd.getpwuid(state.st_uid).pw_name == "_chrony",
       "the NTS cookies' directory (ntsdumpdir /var/lib/chrony) is chrony's user's, and others cannot read it (%s %s)"
       % (oct(stat.S_IMODE(state.st_mode)), pwd.getpwuid(state.st_uid).pw_name))
    return servers


def install():
    """The package, the units, the user and /run/regalia, as a host would have them."""
    os.makedirs(PREFIX)
    shutil.copytree(ROOT / "deploy", pathlib.Path(PREFIX) / "deploy", ignore=shutil.ignore_patterns("__pycache__"))
    units = ROOT / "deploy" / "baremetal" / "units"
    for name in UNITS:
        shutil.copy(units / name, "/etc/systemd/system/" + name)
    for directory in ("/etc/sysusers.d", "/etc/tmpfiles.d"):
        os.makedirs(directory, exist_ok=True)
    shutil.copy(units / "regalia.sysusers.conf", "/etc/sysusers.d/regalia.conf")
    shutil.copy(units / "regalia.tmpfiles.conf", "/etc/tmpfiles.d/regalia.conf")
    sh("systemd-sysusers")
    sh("systemd-tmpfiles", "--create", "/etc/tmpfiles.d/regalia.conf")
    sh("systemctl", "daemon-reload")


def provision(work):
    """What enrolment (#190) will do, by hand: a's and b's TPM identities, keys, the site configuration, the
    measurements document (a's set read from a's TPM), the first manifest committed under the TPM anchor
    (as the regalia-sync user owns its store)."""
    os.makedirs("/etc/regalia")
    keys = {}
    for name in ("a", "b", "c"):
        private = sh("wg", "genkey").stdout.strip()
        keys[name] = (private, wgsvc.hex_key(sh("wg", "pubkey", input=private + "\n").stdout.strip()))
    pathlib.Path("/etc/regalia/wg-service.key").write_text(keys["a"][0] + "\n")
    os.chmod("/etc/regalia/wg-service.key", 0o600)
    cfg = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
    cfg.update(node_id="a", root_key=hbt.pub(hbt.ROOT), time_servers=["127.0.0.2", "127.0.0.3"], pull_interval=10)
    b_tcti = peer_tpm(work)
    ids = {"a": identity(cfg["tcti"], work / "a-ids"), "b": identity(b_tcti, work / "b-ids"),
           "c": ("000b" + "42" * 32, "000b" + "43" * 32, None)}
    mine = reference(work, cfg["tcti"], cfg["pcrs"])
    other = {"label": "e2e", "tpm_firmware_version": "0" * 16, "pcrs": {str(i): "00" * 32 for i in cfg["pcrs"]}}
    document = {"schema": measurements.SCHEMA, "name": "e2e", "nodes": {"a": {"accepted": [mine]}, "b": {"accepted": [dict(other)]},
                                                                       "c": {"accepted": [dict(other)]}}}
    pathlib.Path("/etc/regalia/measurements.json").write_text(json.dumps(document))
    manifest = {"schema": membership.SCHEMA, "epoch": 1, "prev_digest": "", "policy_version": measurements.version(document),
                "issued_at": "2026-10-01T00:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)],
                "nodes": [{"node_id": n, "state": "ACTIVE", "ek_name": ids[n][0], "ak_name": ids[n][1],
                           "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": keys[n][1], "hsm_serials": ["E2E%d" % i]}
                          for i, n in enumerate(("a", "b", "c"))]}
    envelope = signed(manifest)
    site = {"schema": "regalia.baremetal-site/v1", "site": "e2e", "host_ipv4": "192.0.2.10", "kms_port": 8443, "ssh_port": 22,
            "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["203.0.113.128/32"], "admin_cidrs": ["203.0.113.0/28"],
            "outbound": [{"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514}],
            "time": {"nts": [{"name": "127.0.0.2", "cidrs": ["127.0.0.2/32"]}, {"name": "127.0.0.3", "cidrs": ["127.0.0.3/32"]}]},
            "boot_mesh": {"node_id": "a", "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443, "nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": None,
                          "peers": [{"node_id": "b", "underlay": "192.0.2.20", "address": "10.89.0.2"},
                                    {"node_id": "c", "underlay": "192.0.2.30", "address": "10.89.0.3"}]},
            "service_mesh": {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444, "authority": None}}
    pathlib.Path("/etc/regalia/site.json").write_text(json.dumps(site))
    pathlib.Path("/etc/regalia/node.json").write_text(json.dumps(cfg))
    # the modes the units' StateDirectoryMode gives them; the store must be regalia-sync's (#190: an
    # enrolment run as root would leave files sync cannot open)
    for directory, owner, mode in (("/var/lib/regalia-sync", "regalia-sync", 0o755), ("/var/lib/regalia-admission", "regalia-admission", 0o700)):
        os.makedirs(directory)
        shutil.chown(directory, owner, owner)
        os.chmod(directory, mode)
    # the anchor and the first manifest, written by the user that owns the store; the TPM through its group
    program = ("import json, sys\nsys.path.insert(0, %r)\nfrom deploy.baremetal import membership as m\n"
               "a = m.HighWater(%r, %r, lock_path='/var/lib/regalia-sync/highwater.lock')\na.define()\n"
               "s = m.Store('/var/lib/regalia-sync/membership.json', %r, a)\ns.commit(json.load(sys.stdin))\nprint(s.load()['epoch'])\n"
               % (PREFIX, cfg["nv_epoch"], cfg["tcti"], cfg["root_key"]))
    epoch = sh("runuser", "-u", "regalia-sync", "-g", "regalia-sync", "-G", "tss", "--", "python3", "-I", "-c", program, input=json.dumps(envelope)).stdout.strip()
    counter = ("import sys\nsys.path.insert(0, %r)\nfrom deploy.baremetal import heartbeat\n"
               "heartbeat.Counter(%r, %r, lock_path='/var/lib/regalia-sync/heartbeat-counter.lock').define()\n" % (PREFIX, cfg["nv_heartbeat"], cfg["tcti"]))
    sh("runuser", "-u", "regalia-sync", "-g", "regalia-sync", "-G", "tss", "--", "python3", "-I", "-c", counter)
    return {"cfg": cfg, "epoch": epoch, "public": {n: keys[n][1] for n in keys}, "private": {n: keys[n][0] for n in keys},
            "manifest": manifest, "envelope": envelope, "document": document, "b_tcti": b_tcti, "ids": ids}


def scenario(work, binaries, user):
    header("0  the TPM, as a device, and the controls")
    how, by_test = tpm(work)
    rm = "/dev/tpmrm0"
    ok(os.path.exists(rm) and sh("tpm2_getrandom", "--hex", "-T", "device:" + rm, "8", check=False).returncode == 0,
       "a software TPM answers at /dev/tpmrm0, the device the units allow: %s" % how)
    info = os.stat(rm) if os.path.exists(rm) else None
    ok(info is not None and oct(info.st_mode & 0o777) == "0o660" and sh("stat", "-c", "%G", rm).stdout.strip() == "tss",
       "the device is the tss group's, 0660, as on a host (%s)" % ("SET BY THE TEST: udev did not apply the rule to this device" if by_test
                                                                  else "by the distribution's udev rule"), sh("ls", "-l", rm, check=False).stdout.strip())

    def probe(*extra):
        return sh("systemd-run", "--wait", "--pipe", "--collect", "-p", "User=root", "-p", "CapabilityBoundingSet=", "-p", "DevicePolicy=closed",
                  "-p", "DeviceAllow=/dev/tpmrm0 rw", *extra, "-E", "TPM2TOOLS_TCTI=device:/dev/tpmrm0", "--", "tpm2_getrandom", "--hex", "8", check=False)
    without, with_group = probe(), probe("-p", "SupplementaryGroups=tss")
    ok(without.returncode != 0 and "ermission denied" in without.stdout + without.stderr and with_group.returncode == 0,
       "control: root with no capability is denied by the file's mode, and the same probe with the tss group succeeds",
       (without.returncode, (without.stdout + without.stderr).strip()[-200:], with_group.returncode, with_group.stderr.strip()[-200:]))

    header("1  regalia-authtime: chrony with two NTS servers")
    install()                        # first: the latch's directory (regalia.tmpfiles.conf) must exist before chronyd starts
    servers = chrony(work)
    ctx = provision(work)
    cfg, epoch, public = ctx["cfg"], ctx["epoch"], ctx["public"]
    sh("systemctl", "start", "regalia-authtime.service")
    status = pathlib.Path("/run/regalia/authtime.json")
    got = until(lambda: json.loads(status.read_text())["authenticated"] and json.loads(status.read_text()), 120, 2)
    ok(isinstance(got, dict) and got.get("authenticated") is True, "regalia-authtime publishes: authenticated", got if not isinstance(got, dict) else "")
    if not isinstance(got, dict):
        print(journal("regalia-authtime.service"))
        print(sh("chronyc", "-N", "sources", check=False).stdout)
        print(sh("chronyc", "-N", "authdata", check=False).stdout)
        for n in (1, 2):
            print((work / ("s%d.log" % n)).read_text()[-600:])
    ok(os.stat(status).st_uid == 0 and oct(os.stat(status).st_mode & 0o777) == "0o644", "root's, 0644, in root's /run/regalia")
    # #305: and its node_exporter textfile, in its own directory, read through the group
    prom = pathlib.Path(metrics.path("authtime"))
    said = until(lambda: prom.exists() and 'regalia_time_authenticated{cause="ok"} 1' in prom.read_text() and prom.read_text(), 30, 2)
    ok(isinstance(said, str) and "regalia_chrony_latch_set 0" in said and stat.S_IMODE(prom.stat().st_mode) == 0o640
       and grp.getgrgid(prom.stat().st_gid).gr_name == metrics.GROUP,
       "regalia-authtime writes its metrics, 0640, group %s, from its sandbox" % metrics.GROUP, said if isinstance(said, str) else "absent")
    # #71: the authority host's unit, the same service from authority.json (run_dir and time_servers alone), in its
    # own sandbox: it publishes the same root-owned status the authority believes
    sh("systemctl", "stop", "regalia-authtime.service")
    status.unlink()
    pathlib.Path("/etc/regalia/authority.json").write_text(json.dumps({"schema": "regalia.authority/v1", "run_dir": "/run/regalia",
                                                                      "time_servers": ["127.0.0.2", "127.0.0.3"]}))
    sh("systemctl", "start", "regalia-authority-authtime.service")
    from_authority = until(lambda: json.loads(status.read_text())["authenticated"] and json.loads(status.read_text()), 120, 2)
    ok(isinstance(from_authority, dict) and os.stat(status).st_uid == 0 and oct(os.stat(status).st_mode & 0o777) == "0o644",
       "regalia-authority-authtime (authority.json) publishes authenticated, root's 0644 in /run/regalia",
       from_authority if isinstance(from_authority, dict) else journal("regalia-authority-authtime.service"))
    sh("systemctl", "stop", "regalia-authority-authtime.service")
    os.unlink("/etc/regalia/authority.json")
    sh("systemctl", "start", "regalia-authtime.service")
    until(lambda: json.loads(status.read_text())["authenticated"], 120, 2)
    servers[1].terminate()
    servers[1].wait(10)
    gone = until(lambda: not json.loads(status.read_text())["authenticated"] and json.loads(status.read_text()), 150, 3)
    reason = gone.get("reason", "") if isinstance(gone, dict) else ""
    ok(gone.get("authenticated") is False and reason and not reason.startswith(("chrony could not be asked", "the check failed")) if isinstance(gone, dict) else False,
       "one server stops: not authenticated, judged from chrony's answer (%s)" % reason[:70], gone)
    # #303, THE LATCH: chronyd that stopped abnormally (maxchange: two sources agreeing on a jump) stays down
    # until an operator clears it, because a fresh chronyd steps during its first updates. Nothing may start
    # it again: not regalia-authtime (After=, never Wants=), not a package upgrade's restart, not a boot.
    trail = pathlib.Path("/var/log/regalia-time/time.jsonl")
    # SIGKILL stands in for the real trigger, which a host under test cannot be made to see: on maxchange, Debian 13's
    # chronyd 4.6.1 exits with status 1 after "exceeds the allowed maximum" (measured by regalia-kms-d9 in
    # authtime-chrony-nts.py's scenario 8), SERVICE_RESULT=exit-code, which latches the same way as this signal
    sh("systemctl", "kill", "-s", "KILL", "chrony.service", check=False)
    latch = pathlib.Path(authtime.LATCH)
    ok(until(lambda: show("chrony.service", "ActiveState")["ActiveState"] in ("failed", "inactive") and latch.exists(), 20) and
       json.loads(latch.read_text())["result"] == "signal",
       "an unclean stop leaves the latch in root's %s (%s)" % (authtime.LATCH_DIR, latch.read_text().strip() if latch.exists() else "none"))
    ok(until(lambda: "regalia_chrony_latch_set 1" in prom.read_text(), 60, 3),
       "and regalia-authtime sees it, read only from its sandbox: regalia_chrony_latch_set 1 (#305)", prom.read_text()[-300:])
    sh("systemctl", "restart", "regalia-authtime.service")
    time.sleep(20)
    refused = until(lambda: json.loads(status.read_text())["authenticated"] is False and json.loads(status.read_text()), 60, 3)
    ok(show("chrony.service", "ActiveState")["ActiveState"] in ("failed", "inactive") and isinstance(refused, dict),
       "regalia-authtime restarting does not start chronyd, and time is not authenticated (%s)"
       % (refused.get("reason", "")[:50] if isinstance(refused, dict) else refused))
    upgrade = sh("systemctl", "restart", "chrony.service", check=False)        # what the package's postinst does
    ok(upgrade.returncode != 0 and show("chrony.service", "ActiveState")["ActiveState"] != "active"
       and "stopped abnormally before" in journal("chrony.service"),
       "a package upgrade's restart is refused while the latch is there", journal("chrony.service")[-400:])
    sh("systemctl", "reset-failed", "chrony.service", check=False)
    boot = sh("systemctl", "start", "chrony.service", check=False)             # what a boot does
    ok(boot.returncode != 0 and show("chrony.service", "ActiveState")["ActiveState"] != "active",
       "and so is a start, as at boot")
    events = [json.loads(line) for line in trail.read_text().splitlines()] if trail.exists() else []
    kinds = [e["event"] for e in events]
    ok("time-authenticated" in kinds and kinds[-1] == "time-unauthenticated" and events[-1]["reason"],
       "the time trail records the transitions, the last one not authenticated, with the reason (%s)"
       % (events[-1]["reason"][:50] if events else "no trail"), events[-3:])
    cleared = sh("python3", "-Es", "-m", "deploy.baremetal.node", "--config", "/etc/regalia/node.json", "time-clear", "--reason",
                 "the e2e compared the lab servers with the runner's clock", check=False, cwd=PREFIX)
    events = [json.loads(line) for line in trail.read_text().splitlines()]
    ok(cleared.returncode == 0 and not latch.exists() and events[-1]["event"] == "time-latch-cleared" and "signal" in events[-1]["latch"],
       "regalia-node time-clear removes the latch, recorded first with the reason and what the latch held",
       (cleared.returncode, cleared.stderr[-300:], events[-1:]))
    sh("systemctl", "reset-failed", "chrony.service", check=False)
    ok(sh("systemctl", "start", "chrony.service", check=False).returncode == 0 and show("chrony.service", "ActiveState")["ActiveState"] == "active",
       "then chronyd starts")

    header("2  provisioning, by hand (#190 is not built)")
    ok(epoch == "1", "the first manifest is committed under the TPM anchor, by regalia-sync's user through the tss group", epoch)

    header("3  regalia-sync and regalia-wg-apply")
    sh("systemctl", "start", "regalia-wg-apply.path")
    sh("systemctl", "start", "regalia-sync.service")
    chain = pathlib.Path("/var/lib/regalia-sync/chain.json")
    ok(until(lambda: chain.exists(), 30), "regalia-sync publishes the chain", journal("regalia-sync.service")[-600:])
    ok(oct(os.stat(chain).st_mode & 0o777) == "0o644" and pathlib.Path(chain).owner() == "regalia-sync", "0644, regalia-sync's")
    up = until(lambda: sh("ip", "link", "show", "wg-svc", check=False).returncode == 0 and ":7444" in sh("ss", "-ltn", check=False).stdout
               and "10.89.0.1:7443" in sh("ss", "-ltn", check=False).stdout, 90, 2)
    ok(up, "the path unit runs regalia-wg-apply on the published chain; regalia-sync then binds wg-svc (7444) and wg-unlock (7443)",
       journal("regalia-wg-apply.service")[-800:] + journal("regalia-sync.service")[-600:])
    for name in ("wg-svc", "wg-unlock"):
        state = sh("ip", "-o", "link", "show", name, check=False).stdout
        flags = state.split("<", 1)[1].split(">", 1)[0].split(",") if "<" in state else []
        ok("UP" in flags, "%s is up" % name, state.strip())
    peers = {line.split("\t")[0]: line.split("\t")[1] for line in sh("wg", "show", "wg-svc", "allowed-ips", check=False).stdout.splitlines() if "\t" in line}
    want = {wgsvc.wg_key(public[n]): "%s/128" % wgsvc.address(public[n]) for n in ("b", "c")}
    ok(peers == want, "wg-svc's peers are b's and c's keys, each with the one /128 its key derives", peers)
    # the path unit, on its own: a new chain.json (written as regalia-sync writes it) and nothing else
    sync_before = show("regalia-sync.service", "NRestarts", "InvocationID")
    ok(sync_before.get("NRestarts") == "0", "regalia-sync did not restart on its first start (it waits for its tunnel address)",
       sync_before)
    before = show("regalia-wg-apply.service", "InvocationID")["InvocationID"]
    temporary = chain.with_name(".chain.e2e")
    temporary.write_bytes(chain.read_bytes())
    shutil.chown(temporary, "regalia-sync", "regalia-sync")
    os.chmod(temporary, 0o644)
    written = time.clock_gettime(time.CLOCK_MONOTONIC)
    os.rename(temporary, chain)
    rerun = until(lambda: (lambda now: now["InvocationID"] != before and now["ExecMainStatus"] == "0" and now["ActiveState"] == "inactive"
                                        and int(now["ExecMainStartTimestampMonotonic"]) / 1e6 >= written and now)(
                  show("regalia-wg-apply.service", "InvocationID", "ExecMainStatus", "ActiveState", "ExecMainStartTimestampMonotonic")), 30, 1)
    ok(bool(rerun), "chain.json replaced: the path unit starts a NEW regalia-wg-apply run after the write, and it succeeds",
       journal("regalia-wg-apply.service")[-600:])
    time.sleep(10)
    sync_after = show("regalia-sync.service", "NRestarts", "InvocationID", "ActiveState")
    ok(sync_after["ActiveState"] == "active" and (sync_after["NRestarts"], sync_after["InvocationID"]) == (sync_before["NRestarts"], sync_before["InvocationID"]),
       "regalia-sync stays up, the same process, through that and ten seconds more", (sync_before, sync_after))

    header("4  regalia-admission")
    # the CUSE TPM has no resource manager: one unit at a time from here (see the docstring)
    sh("systemctl", "stop", "regalia-wg-apply.path", "regalia-sync.service")
    # the recovery-key boot: no unlock client ran, so no session yet. The lease service alone, as its own
    # user, must refuse rather than make one (it cannot, and the daemon would not trust it), and write nothing
    ok(not os.path.exists("/run/regalia/boot-session") and not os.path.exists("/run/regalia/boot-session.pub"),
       "no boot session yet: no unlock client ran this boot")
    alone = sh("runuser", "-u", "regalia-admission", "-g", "regalia-admission", "-G", "tss", "--", "timeout", "60",
               "python3", "-Es", "-m", "deploy.baremetal.node", "--config", "/etc/regalia/node.json", "admission", check=False, cwd=PREFIX)
    ok(alone.returncode == 2 and "regalia-boot-session.service makes one" in alone.stderr and not os.listdir("/run/regalia/admission")
       and not os.path.exists("/run/regalia/boot-session"),
       "the lease service alone refuses: this boot has no session, and it writes nothing", (alone.returncode, alone.stderr[-300:]))
    denied = sh("runuser", "-u", "regalia-admission", "--", "touch", "/run/regalia/boot-session", check=False)
    ok(denied.returncode != 0 and not os.path.exists("/run/regalia/boot-session"),
       "and as its user it cannot write root's /run/regalia (where the boot session lives)", denied.stderr[-200:])
    sh("systemctl", "start", "regalia-admission.service")
    pair = [os.stat("/run/regalia/" + n) if os.path.exists("/run/regalia/" + n) else None for n in ("boot-session", "boot-session.pub")]
    ok(show("regalia-boot-session.service", "ActiveState", "Result") == {"ActiveState": "active", "Result": "success"}
       and all(st is not None and st.st_uid == 0 and st.st_mode & 0o777 == 0o644 for st in pair),
       "regalia-admission pulled in regalia-boot-session, which made the pair: root's, 0644",
       journal("regalia-boot-session.service")[-400:])
    admission = pathlib.Path(ADMISSION_FILE)
    doc = until(lambda: json.loads(admission.read_text()), 60, 2)
    doc = doc if isinstance(doc, dict) else {}
    ok(doc.get("serve_until_boottime_ms") == 0 and doc.get("epoch") == 1 and doc.get("manifest_digest", "00" * 32) != "00" * 32
       and doc.get("reason", "").startswith("renewal failed: no peer gave a lease"),
       "not admitted, under epoch 1 verified against the TPM anchor, because no peer answered (%s)" % doc.get("reason", "")[:90],
       doc or journal("regalia-admission.service")[-600:])
    served = pathlib.Path(metrics.path("admission"))
    ok(until(lambda: served.exists() and "regalia_admission_serving 0" in served.read_text(), 30, 2),
       "regalia-admission writes its metrics as its user: regalia_admission_serving 0 (#305)", served.read_text() if served.exists() else "absent")
    uid = pwd.getpwnam("regalia-admission").pw_uid
    written, directory = os.stat(ADMISSION_FILE), os.stat(os.path.dirname(ADMISSION_FILE))
    ok(uid != 0 and written.st_uid == uid and written.st_mode & 0o022 == 0 and directory.st_uid == uid and directory.st_mode & 0o777 == 0o755,
       "the admission file is regalia-admission's (uid %d), in its own 0755 directory, written by nobody else" % uid,
       (written.st_uid, oct(written.st_mode), directory.st_uid, oct(directory.st_mode)))
    pid = show("regalia-admission.service", "MainPID")["MainPID"]
    uids = re.search(r"^Uid:\s+(.*)$", pathlib.Path("/proc/%s/status" % pid).read_text(), re.M).group(1).split()
    ok(set(uids) == {str(uid)}, "the kernel reports the running lease service's real, effective, saved and filesystem uids as %d" % uid, uids)
    verdict = os_probe.lease_service_unprivileged(os_probe.Host(), "regalia-admission")
    ok(verdict[0] is True, "the host probe measures it: %s" % verdict[1], verdict)

    header("5  the sandboxes as systemd applied them")
    for unit, want in (("regalia-sync.service", {"User": "regalia-sync", "CapabilityBoundingSet": "", "NoNewPrivileges": "yes"}),
                       ("regalia-admission.service", {"User": "regalia-admission", "CapabilityBoundingSet": "", "NoNewPrivileges": "yes"}),
                       ("regalia-boot-session.service", {"User": "root", "CapabilityBoundingSet": "", "PrivateNetwork": "yes"}),
                       ("regalia-authtime.service", {"CapabilityBoundingSet": "cap_dac_override", "ProtectProc": "invisible"}),
                       ("regalia-wg-apply.service", {"CapabilityBoundingSet": "cap_net_admin"})):
        have = show(unit, *want)
        ok(all(have.get(k) == v for k, v in want.items()), "%s: %s" % (unit, ", ".join("%s=%s" % kv for kv in want.items())), have)
    main_pid = show("regalia-authtime.service", "MainPID")["MainPID"]
    seen = {p: sh("nsenter", "-t", main_pid, "-m", "--", "test", "-e", p, check=False).returncode == 0
            for p in ("/etc/regalia/node.json", "/etc/regalia/site.json", "/etc/regalia/wg-service.key", "/var/lib/regalia-sync", "/run/credentials",
                      "/run/regalia", "/run/chrony")}
    ok(seen == {"/etc/regalia/node.json": True, "/etc/regalia/site.json": False, "/etc/regalia/wg-service.key": False, "/var/lib/regalia-sync": False,
                "/run/credentials": False, "/run/regalia": True, "/run/chrony": True},
       "regalia-authtime's running process sees its configuration, /run/regalia and /run/chrony, and not the keys, the site, the store or credentials", seen)
    # observed, not asserted: what chrony does with a group-writable /run/chrony
    os.chmod("/run/chrony", 0o770)
    sh("systemctl", "restart", "chrony", check=False)
    accepted = until(lambda: show("chrony.service", "ActiveState")["ActiveState"] == "active" and os.path.exists("/run/chrony/chronyd.sock"), 20)
    print("  OBSERVED (%s): chronyd with /run/chrony made 0770 -> %s; mode after the restart %s"
          % (sh("chronyd", "-v", check=False).stdout.strip(), "starts" if accepted else "does not start", oct(os.stat("/run/chrony").st_mode & 0o777) if os.path.exists("/run/chrony") else "absent"))
    print(journal("chrony.service", 8))
    print(sh("systemctl", "cat", "chrony.service", check=False).stdout)
    if failed:
        print("node-units-systemd: part 1 failed; part 2 not run")
        return 1
    part2(work, binaries, user, ctx, servers, status)
    return 1 if failed else 0


class Daemon:
    """The KMS daemon on SoftHSM, as e2e/runtime-admission.py runs it, but as a systemd unit named
    regalia-kms.service (so regalia-admission sees when it started), as the invoking user, reading the
    admission file regalia-admission writes in /run/regalia."""

    def __init__(self, work, binaries, user):
        """The token, its key and the daemon's files: nothing runs yet (start). Prepared before epoch 2 is signed,
        so that the manifest can list the token's serial for node a (#72 G1: a token the manifest does not list is
        not served)."""
        self.binaries, self.user = binaries, user
        self.w = w = work / "kms"
        w.mkdir(mode=0o700)
        etc, state = w / "etc", w / "state"
        for d in (etc, state, state / "tokens", w / "collector"):
            d.mkdir(mode=0o700)
        module = next(c for c in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if os.path.exists(c))
        self.env = dict(os.environ, SOFTHSM2_CONF=str(etc / "softhsm2.conf"))
        (etc / "softhsm2.conf").write_text("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n" % (state / "tokens"))
        pin = os.urandom(8).hex()
        sh("softhsm2-util", "--init-token", "--free", "--label", "regalia-e2e", "--so-pin", os.urandom(8).hex(), "--pin", pin, env=self.env)
        token = ["pkcs11-tool", "--module", module, "--token-label", "regalia-e2e"]
        sh(*token, "--login", "--pin", "env:P", "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", "regalia-e2e", "--id", "01",
           env=dict(self.env, P=pin))
        sh(*token, "--read-object", "--type", "pubkey", "--id", "01", "--output-file", str(w / "pub.der"), env=self.env)
        sh("openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(w / "pub.der"), "-out", str(w / "pub.pem"))
        self.serial = serial = next(line.split(":", 1)[1].strip() for line in sh(*token, "--list-slots", env=self.env).stdout.splitlines() if "serial num" in line)
        keypin = "sha256:" + hashlib.sha256((w / "pub.der").read_bytes()).hexdigest()
        (etc / "card.pin").write_text(pin)
        sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(etc / "ca.key"))
        sh("openssl", "req", "-new", "-x509", "-key", str(etc / "ca.key"), "-subj", "/CN=regalia e2e CA", "-days", "2", "-out", str(etc / "ca.pem"),
           "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
        for name, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature"),
                          ("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"),
                          ("client", "subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature" % PRINCIPAL)):
            sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(etc / (name + ".key")))
            sh("openssl", "req", "-new", "-key", str(etc / (name + ".key")), "-subj", "/CN=regalia e2e " + name, "-out", str(etc / (name + ".csr")))
            (etc / (name + ".ext")).write_text(ext + "\n")
            sh("openssl", "x509", "-req", "-in", str(etc / (name + ".csr")), "-CA", str(etc / "ca.pem"), "-CAkey", str(etc / "ca.key"), "-set_serial",
               str(int.from_bytes(os.urandom(8), "big")), "-days", "2", "-extfile", str(etc / (name + ".ext")), "-out", str(etc / (name + ".pem")))
        now = datetime.datetime.now(datetime.timezone.utc)
        self.stamp, tomorrow = now.strftime("%Y-%m-%dT%H:%M:%SZ"), (now + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.port, sink = 18453, 18454
        documents = {
            "secure-channel.json": {"schema_version": 1, "devices": [{"device_serial": serial, "verified_by": "e2e", "verified_at": self.stamp,
                                                                       "expires_at": tomorrow, "firmware": "softhsm", "secure_messaging_established": True}]},
            "manifest.json": {"schema_version": 1, "manifest_id": "node-units-e2e", "generated_at": self.stamp, "objects": [{
                "id": OBJECT, "name": "E2E P-256 signing key", "kind": "asymmetric-key", "classification": "restricted",
                "environment": "staging", "owner": "security", "purpose": "e2e-signing", "custody": "direct-hardware",
                "algorithm": "p256", "operations": ["sign"], "policy_id": "e2e-sign",
                "bindings": [{"site": SITE, "backend": "nitrokey-pkcs11", "device_id": DEVICE, "device_serial": serial, "object_id": "01",
                              "public_key_sha256": keypin, "public_fingerprint": keypin, "state": "active"}],
                "recovery": {"mode": "shamir-4-of-6", "authority_id": "e2e", "minimum_replicas": 2, "status": "tested"},
                "rotation": {"maximum_age_days": 90, "last_rotated": None}, "migration": {"status": "migrated", "source": "e2e"},
                "verification": {"status": "verified", "last_verified": self.stamp[:10], "evidence": "e2e"}}]},
            "policy.json": {"schema_version": 1, "policies": [{"id": "e2e-sign", "object_id": OBJECT, "purpose": "e2e-signing", "environment": "staging",
                                                               "operation": "sign", "algorithm": "p256", "content_types": ["application/vnd.regalia.digest"],
                                                               "max_payload_bytes": 32, "max_future_seconds": 300, "required_approvals": 0,
                                                               "approvers": ["spiffe://regalia/approver/e2e"]}]},
            "rbac.json": {"schema_version": 1, "principals": [{"uri": PRINCIPAL, "grants": [
                {"objects": [OBJECT], "operations": ["sign"], "environments": ["staging"]}]}]},
            "config.json": {
                "listen_address": "127.0.0.1:%d" % self.port, "site": SITE,
                "registry_path": str(etc / "manifest.json"), "rbac_policy_path": str(etc / "rbac.json"),
                "policy_path": str(etc / "policy.json"), "policy_state_path": str(state / "policy-state.jsonl"),
                "tls_certificate_path": str(etc / "server.pem"), "tls_private_key_path": str(etc / "server.key"), "tls_client_ca_path": str(etc / "ca.pem"),
                "pkcs11_module_path": module, "secure_channel_evidence_path": str(etc / "secure-channel.json"),
                "pin_paths": {DEVICE: str(etc / "card.pin")},
                "audit_journal_path": str(state / "audit.jsonl"), "audit_sink_url": "https://127.0.0.1:%d" % sink,
                # what this test is about: the files regalia-admission writes, as the daemon finds them on a host
                "runtime_admission": "required", "runtime_admission_path": ADMISSION_FILE, "runtime_admission_owner": "regalia-admission",
                "node_id": "a", "boot_session_path": "/run/regalia/boot-session"}}
        for name, document in documents.items():
            (etc / name).write_text(json.dumps(document, indent=1) + "\n")
        for path in etc.iterdir():
            path.chmod(0o600)
        sh("chown", "-R", "%s:" % user, str(w))
        self.etc, self.sink = etc, sink

    def start(self):
        """The audit collector, then the daemon, as units."""
        w, etc, sink, binaries = self.w, self.etc, self.sink, self.binaries
        common = ["systemd-run", "--collect", "-p", "User=" + self.user, "-p", "WorkingDirectory=" + str(w)]
        sh(*common, "--unit=regalia-audit-collector", "--", str(binaries / "regalia-audit-collector"), "-state", str(w / "collector"),
           "-listen", "127.0.0.1:%d" % sink, "-tls-cert", str(etc / "collector.pem"), "-tls-key", str(etc / "collector.key"), "-client-ca", str(etc / "ca.pem"))
        time.sleep(2)
        sh(*common, "--unit=regalia-kms", "-E", "SOFTHSM2_CONF=" + self.env["SOFTHSM2_CONF"], "--", str(binaries / "regalia-kms"), "-config", str(etc / "config.json"))
        self.context = ssl.create_default_context(cafile=str(etc / "ca.pem"))
        self.context.load_cert_chain(str(etc / "client.pem"), str(etc / "client.key"))

    def call(self, method, path, body=None, nonce=None):
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.context, timeout=60)
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

    def ready(self):
        try:
            return self.call("GET", "/v1/health/ready")[0]
        except OSError:
            return None

    def sign(self, message):
        nonce = "e2e-nonce-" + os.urandom(12).hex()
        expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.call("POST", "/v1/operations/sign", {
            "object_id": OBJECT, "context": {"environment": "staging", "purpose": "e2e-signing", "expires_at": expires, "nonce": nonce},
            "content_type": "application/vnd.regalia.digest", "payload_base64": base64.b64encode(hashlib.sha256(message).digest()).decode()}, nonce)

    def verifies(self, message, result):
        raw = base64.b64decode(result["result_base64"], validate=True)

        def integer(value):
            value = value.lstrip(b"\x00") or b"\x00"
            value = (b"\x00" + value) if value[0] & 0x80 else value
            return b"\x02" + bytes([len(value)]) + value
        body = integer(raw[:32]) + integer(raw[32:])
        (self.w / "sig.der").write_bytes(b"\x30" + bytes([len(body)]) + body)
        (self.w / "message").write_bytes(message)
        return len(raw) == 64 and subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(self.w / "pub.pem"), "-signature", str(self.w / "sig.der"),
                                                  str(self.w / "message")], capture_output=True).returncode == 0

    def wait_for(self, want, seconds):
        got = until(lambda: self.ready() == want, seconds, 0.5)
        return want if got is True else self.ready()

    def log(self):
        return journal("regalia-kms.service", 40)


def chain_epoch():
    raw = pathlib.Path("/var/lib/regalia-sync/chain.json").read_bytes()
    return membership.load(raw, membership.MAX_CHAIN_BYTES)[-1]["manifest"]["epoch"]


def part2(work, binaries, user, ctx, servers, status):
    cfg, public, document = ctx["cfg"], ctx["public"], ctx["document"]
    m1 = ctx["manifest"]
    address = {n: wgsvc.address(public[n]) for n in public}

    header("6  peer b: its own namespace and TPM, its tunnel to a from the same manifest")
    sh("systemctl", "stop", "regalia-admission.service")
    # a resource manager in front of the CUSE device, as the kernel's is on a host (see the docstring)
    # the distribution's unit (D-Bus activated, as the tss user), pointed at this device instead of /dev/tpm0
    os.makedirs("/etc/systemd/system/tpm2-abrmd.service.d", exist_ok=True)
    pathlib.Path("/etc/systemd/system/tpm2-abrmd.service.d/e2e.conf").write_text(
        "[Service]\nExecStart=\nExecStart=/usr/sbin/tpm2-abrmd --tcti=device:/dev/tpmrm0\n")
    sh("systemctl", "daemon-reload")
    sh("systemctl", "restart", "tpm2-abrmd.service", check=False)
    probe = lambda: sh("tpm2_getrandom", "-T", "tabrmd:bus_type=system", "--hex", "8", check=False)     # noqa: E731
    managed = until(lambda: probe().returncode == 0, 30, 1)
    ok(managed is True, "tpm2-abrmd serves a's TPM; the units use it from here",
       "%s\n%s" % (probe().stderr[-600:], journal("tpm2-abrmd.service")[-1200:]))
    cfg = dict(cfg, tcti="tabrmd:bus_type=system")
    pathlib.Path("/etc/regalia/node.json").write_text(json.dumps(cfg))
    servers[1] = nts_server(work, 2)                     # both time sources again
    again = until(lambda: json.loads(status.read_text())["authenticated"], 120, 2)
    ok(again is True, "the stopped NTS server is back: authenticated again", status.read_text() if status.exists() else "")
    sh("ip", "netns", "add", NS)
    sh("ip", "link", "add", "e2e-b0", "type", "veth", "peer", "name", "eth0", "netns", NS)
    sh("ip", "address", "add", "192.0.2.10/24", "dev", "e2e-b0")
    sh("ip", "link", "set", "e2e-b0", "up")
    for argv in (["ip", "link", "set", "lo", "up"], ["ip", "address", "add", "192.0.2.20/24", "dev", "eth0"], ["ip", "link", "set", "eth0", "up"]):
        in_ns(argv, check=True, capture_output=True)
    own = wgsvc.reconcile(m1, "b", {"a": "192.0.2.10", "c": "192.0.2.30"}, ctx["private"]["b"], None, run=in_ns)
    ok(own == address["b"], "b's wg-svc is up at its key's address, with a and c as its peers, read back", own)
    # b's side, as a node holds it: the store under its TPM anchor, a heartbeat, the verifier, the signer
    b_tcti = ctx["b_tcti"]
    anchor = membership.HighWater(cfg["nv_epoch"], b_tcti, lock_path=str(work / "b-highwater.lock"))
    anchor.define()
    store = membership.Store(str(work / "b-membership.json"), cfg["root_key"], anchor)
    store.commit(ctx["envelope"])
    counter = heartbeat.Counter(cfg["nv_heartbeat"], b_tcti, lock_path=str(work / "b-counter.lock"))
    counter.define()
    freshness = heartbeat.Freshness(counter, authtime.clock(str(status)), heartbeat.TpmClock(b_tcti), str(work / "b-freshness.json"))
    freshness.accept(hbt.beat(m1, 1, issued=int(time.time())), m1)
    verifier = attest.Verifier(measurements.attest_policy(m1, document, "b"), str(work / "b-attest.json"))
    with attest.locked_state(str(work / "b-attest.json")) as (state, save):       # a's AK, enrolled by hand (#190)
        state["nodes"].setdefault("a", {})["ak_public"] = ctx["ids"]["a"][2]
        save()
    events = []
    server = sync.Server("b", store, freshness, verifier, lease.TpmSigner(b_tcti), wgsvc.key_at, events.append)
    # b's trail names a refused caller before it parses the request ("event": "sync"), so the test also
    # notes each request's operation and b's answer, to tell a's renewals from its pulls
    requests, b_handle = [], server.handle          # (not "answer": section 8 reuses that name for the daemon's reply)

    started, raised = [], []

    def handle(raw, address):
        try:
            op = json.loads(raw).get("op")
        except (ValueError, AttributeError):
            op = None
        who = address[0] if isinstance(address, tuple) else address
        started.append((time.monotonic(), op, who))          # a request that never answers shows here only
        try:
            out = b_handle(raw, address)
        except BaseException:
            import traceback
            raised.append((op, traceback.format_exc()[-1500:]))
            raise
        requests.append((op, who, out))
        return out
    server.handle = handle
    listener = inside(lambda: socket.create_server((address["b"], cfg_port(ctx)), family=socket.AF_INET6))
    listener.settimeout(0.5)
    inside(lambda: threading.Thread(target=sync.serve, args=(server, listener, lambda: bool(STOP)), daemon=True).start())
    reached = until(lambda: sh("ping", "-6", "-c", "1", "-W", "2", address["b"], check=False).returncode == 0, 30, 1)
    ok(reached is True, "a reaches b's tunnel address through a's wg-svc (a WireGuard handshake on the underlay)",
       sh("wg", "show", "wg-svc", check=False).stdout)

    header("7  catch-up: b holds epoch 2; regalia-sync pulls it over the tunnel, and wg-apply runs for it")
    # the daemon's token first, so that epoch 2 (root-signed) lists its serial as a's: the daemon serves only from a
    # token the manifest lists for this node (#72 G1)
    daemon = Daemon(work, binaries, user)
    m2 = dict(m1, epoch=2, prev_digest=membership.digest(m1), issued_at="2026-10-02T00:00:00Z",
              nodes=[dict(n, state="DRAINING") if n["node_id"] == "c" else dict(n, hsm_serials=[daemon.serial]) if n["node_id"] == "a" else n
                     for n in m1["nodes"]])
    store.commit(signed(m2))
    freshness.accept(hbt.beat(m2, 2, issued=int(time.time())), m2)
    before = show("regalia-wg-apply.service", "InvocationID")["InvocationID"]
    sh("systemctl", "start", "regalia-wg-apply.path", "regalia-sync.service")
    caught = until(lambda: chain_epoch() == 2, 90, 2)
    ok(caught is True, "regalia-sync pulled epoch 2 from b and published it", journal("regalia-sync.service")[-800:])
    pulled = [e for e in events if e.get("event") == "sync-pull" and e.get("subject") == "a"]
    ok(pulled and pulled[-1].get("outcome") == "ALLOW", "b recorded the caller as node a, by the tunnel address its key derives", pulled[-1:] or events[-3:])
    held = until(lambda: json.loads(pathlib.Path("/var/lib/regalia-sync/freshness.json").read_text())["envelope"]["heartbeat"]["epoch"] == 2, 60, 2)
    ok(held is True, "and a holds b's heartbeat for epoch 2 (regalia-sync's freshness state)")
    def applied_epoch_2():
        now = show("regalia-wg-apply.service", "InvocationID", "ExecMainStatus", "ActiveState", "NRestarts")
        if now["InvocationID"] == before or now["ExecMainStatus"] != "0" or now["ActiveState"] != "inactive":
            return False
        said = sh("journalctl", "_SYSTEMD_INVOCATION_ID=" + now["InvocationID"], "-o", "cat", "--no-pager", check=False).stdout
        return "applied under epoch 2" in said and now
    rerun = until(applied_epoch_2, 90, 1)
    ok(bool(rerun), "regalia-wg-apply ran again and applied epoch 2, by its own run's journal (restarts: %s)"
       % (rerun.get("NRestarts") if isinstance(rerun, dict) else "?"), journal("regalia-wg-apply.service")[-600:])
    # regalia-sync and the path unit keep running from here, beside regalia-admission, as on a host

    header("8  the KMS daemon, and a lease from b over the tunnel")
    daemon.start()
    ok(daemon.wait_for(503, 90) == 503, "regalia-kms.service is up and NOT ready (503): no admission yet", daemon.log()[-900:])
    sh("systemctl", "start", "regalia-admission.service")
    admitted_doc = until(lambda: (lambda d: d["serve_until_boottime_ms"] > admission.boottime_ms() and d)(
        json.loads(pathlib.Path(ADMISSION_FILE).read_text())), 120, 2)
    admitted_doc = admitted_doc if isinstance(admitted_doc, dict) else {}
    left = (admitted_doc.get("serve_until_boottime_ms", 0) - admission.boottime_ms()) / 1000
    ok(admitted_doc.get("epoch") == 2 and 200 < left <= lease.MAX_LIFETIME,
       "regalia-admission re-attested to b with a's TPM; b's TPM signed a lease; admitted for %.0f s under epoch 2" % left,
       admitted_doc or json.loads(pathlib.Path(ADMISSION_FILE).read_text()))
    issued = [e for e in events if e.get("event") == "sync-lease" and e.get("subject") == "a"]
    ok(issued and issued[-1].get("outcome") == "ALLOW", "b's trail: a lease for a", issued[-1:] or events[-3:])
    ok(daemon.wait_for(200, 30) == 200, "the daemon is ready (200)", daemon.log()[-900:])
    message = b"regalia-kms node units e2e " + daemon.stamp.encode()
    code, answer = daemon.sign(message)
    ok(code == 200 and daemon.verifies(message, answer), "it signs, and openssl verifies the signature against the token's key", (code, answer))

    header("9  b revokes a: no renewal, and the daemon stops at the end of the lease it holds, on its own clock")
    m3 = dict(m2, epoch=3, prev_digest=membership.digest(m2), issued_at="2026-10-02T01:00:00Z",
              nodes=[dict(n, state="REVOKED_STOLEN") if n["node_id"] == "a" else n for n in m2["nodes"]])
    store.commit(signed(m3, hbt.REVOKE, "revocation"))
    freshness.accept(hbt.beat(m3, 3, issued=int(time.time())), m3)
    mark, marked = len(events), len(requests)   # from here b refuses; a lease it granted just before may still be landing

    def from_a(ops):
        return [r for r in requests[marked:] if r[0] in ops and r[1] == address["a"]]
    renewals = until(lambda: from_a(("lease-nonce", "lease")), lease.MAX_LIFETIME, 2)
    if not renewals:                     # diagnostics: what b was doing instead
        import faulthandler
        print("  b: %d requests started, %d answered; last started: %s" % (len(started), len(requests), started[-4:]))
        print("  b raised %d times; the last: %s" % (len(raised), raised[-1] if raised else None))
        print("  b's trail since the revocation: %s" % [(e.get("event"), e.get("subject"), e.get("outcome"), e.get("reason", "")[:80]) for e in events[mark:]][-8:])
        print("  a's lease service: %s" % journal("regalia-admission.service", 15)[-1500:])
        faulthandler.dump_traceback(all_threads=True)
    denied = [e for e in events[mark:] if e.get("subject") == "a" and e.get("outcome") == "DENY"]
    # b refuses a when it identifies the caller (sync.py, peer_of), before any lease policy runs: the
    # transport's refusal. The lease policy's own refusal of a revoked subject is #199's revoke e2e.
    ok(bool(renewals) and all(b'"refused"' in r[2] for r in renewals) and any("REVOKED_STOLEN under epoch 3" in e.get("reason", "") for e in denied),
       "a asks b to renew (%s); b refuses the caller by name, as REVOKED_STOLEN under epoch 3 (the transport, before the lease code)"
       % (renewals[0][0] if renewals else "no request"), (renewals[-1:] if renewals else requests[-3:], denied[-1:]))
    pulls = from_a(("pull",))
    ok(bool(pulls) and all(b'"refused"' in r[2] for r in pulls), "a's own pulls are refused too: it is told nothing of its revocation", pulls[-2:] or requests[-3:])
    # from here nothing writes the admission file: the daemon must stop on its own CLOCK_BOOTTIME
    sh("systemctl", "stop", "regalia-admission.service")
    frozen = pathlib.Path(ADMISSION_FILE).read_bytes()
    end = json.loads(frozen)["serve_until_boottime_ms"]
    granted = [e for e in events[mark:] if e.get("event") == "sync-lease" and e.get("subject") == "a" and e.get("outcome") == "ALLOW"]
    ok(not granted and end - admission.boottime_ms() > 15000,
       "b granted no lease after the revocation; regalia-admission is stopped with %.0f s of the last lease left"
       % ((end - admission.boottime_ms()) / 1000), (granted, end, admission.boottime_ms()))
    time.sleep(max(0, (end - 5000 - admission.boottime_ms()) / 1000))
    code, answer = daemon.sign(b"five seconds before the end")
    ok(code == 200 and daemon.ready() == 200, "5 s before the end of the lease the daemon still signs and is ready", (code, answer))
    time.sleep(max(0, (end + 2000 - admission.boottime_ms()) / 1000))
    code, answer = daemon.sign(b"two seconds after the end")
    ok(code == 503 and daemon.ready() == 503 and pathlib.Path(ADMISSION_FILE).read_bytes() == frozen,
       "2 s after the end it refuses (503) and is not ready, with the admission file untouched since the lease service stopped",
       (code, answer, daemon.log()[-600:]))
    # b's handler never failed (a failure there is swallowed by sync.serve and would look like silence)
    ok(not raised, "b's handler answered every request it received without raising (%d requests)" % len(started), raised[-1:])


def cfg_port(ctx):
    return json.loads(pathlib.Path("/etc/regalia/site.json").read_text())["service_mesh"]["sync_port"]


if __name__ == "__main__":
    sys.exit(main())
