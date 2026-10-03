#!/usr/bin/env python3
"""The node's four units under a real systemd, part 1 (#80, step 3b): they start, reach what their sandboxes
let them reach, and do their first job.

    sudo --preserve-env=GITHUB_ACTIONS python3 -Es e2e/node-units-systemd.py   (CI only; elsewhere REGALIA_NODE_HOST_OK=1)

IT CHANGES THE MACHINE, which is why it refuses to run anywhere but a throwaway CI runner: it loads the
kernel's tpm_vtpm_proxy module and gives a software TPM a /dev/tpmrm device, replaces the system chrony's
configuration (so the system clock follows two private NTS servers on the loopback), creates the user
regalia-sync, installs the units under /etc/systemd/system, and writes /etc/regalia and /var/lib/regalia-*.

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
  4  regalia-admission, root with no capability, opens the TPM, makes this boot's session, and writes
     the admission file: "not admitted", with no peer to ask (that is part 2)
  5  each unit's sandbox as systemd applied it (systemctl show), and chronyd and a group-writable
     /run/chrony (the measurement that could take regalia-authtime's capability away)

Part 2 adds the peers, the authority and the KMS daemon: a lease from a peer, the daemon ready, and a
revocation reaching the daemon.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deploy.baremetal import authtime, measurements, membership, node, wgsvc        # noqa: E402

PREFIX = "/usr/lib/regalia-kms"
UNITS = ("regalia-authtime.service", "regalia-wg-apply.service", "regalia-wg-apply.path", "regalia-admission.service", "regalia-sync.service")
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
    return subprocess.run(list(argv), capture_output=True, text=True, check=check, **kw)


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


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" and os.environ.get("REGALIA_NODE_HOST_OK") != "1":
        print("node-units-systemd: refused: this changes the machine (a kernel module, the system chrony and clock, a user, "
              "units). It runs in CI; set REGALIA_NODE_HOST_OK=1 only on a throwaway host.")
        return 2
    if os.geteuid() != 0:
        print("node-units-systemd: run as root")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="node-units-"))
    try:
        return scenario(work)
    finally:
        for name in reversed(UNITS):
            sh("systemctl", "stop", name, check=False)
        print("\nnode-units-systemd: %d passed, %d failed" % (passed, failed))


def tpm(work):
    """A software TPM behind the kernel's vTPM proxy: a real /dev/tpmrm device, a real udev rule."""
    loaded = sh("modprobe", "tpm_vtpm_proxy", check=False)
    if loaded.returncode != 0:
        raise SystemExit("node-units-systemd: the kernel's vTPM proxy cannot be loaded: %s" % loaded.stderr.strip())
    state = work / "tpm"
    state.mkdir()
    done = sh("swtpm", "chardev", "--vtpm-proxy", "--tpm2", "--tpmstate", "dir=%s" % state, "--flags", "not-need-init,startup-clear",
              "--daemon", "--pid", "file=%s" % (work / "swtpm.pid"), "--log", "file=%s" % (work / "swtpm.log"))
    device = next((w for w in (done.stdout + done.stderr).split() if w.startswith("/dev/tpm")), None)
    sh("udevadm", "settle")
    return device


def chrony(work):
    """Two NTS servers on the loopback (each with its own certificate), and the system chrony configured as
    authtime.conf() renders it, pointed at them."""
    servers = []
    for n, address in enumerate(("127.0.0.2", "127.0.0.3"), 1):
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
           "-keyout", str(work / ("s%d.key" % n)), "-out", str(work / ("s%d.crt" % n)), "-subj", "/CN=" + address,
           "-addext", "subjectAltName=IP:" + address)
        conf = work / ("s%d.conf" % n)
        conf.write_text("local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s\nntsservercert %s\nallow 127.0.0.0/8\n"
                        "cmdport 0\nbindcmdaddress %s\npidfile %s\nntsdumpdir %s\n"
                        % (21120 + n, 21460 + n, address, work / ("s%d.key" % n), work / ("s%d.crt" % n), work / ("s%d.sock" % n),
                           work / ("s%d.pid" % n), work))
        copy = work / "chronyd-server"
        shutil.copy(shutil.which("chronyd") or "/usr/sbin/chronyd", copy)       # unconfined by the distribution's profile
        servers.append(subprocess.Popen([str(copy), "-x", "-n", "-f", str(conf)], stdout=open(work / ("s%d.log" % n), "w"), stderr=subprocess.STDOUT))
    text = authtime.conf(["127.0.0.2", "127.0.0.3"])
    for n, address in enumerate(("127.0.0.2", "127.0.0.3"), 1):
        text = text.replace("server %s nts iburst\n" % address, "server %s port %d nts ntsport %d iburst minpoll 0 maxpoll 1\n" % (address, 21120 + n, 21460 + n))
    for n in (1, 2):                       # where the distribution's AppArmor profile lets chronyd read
        shutil.copy(work / ("s%d.crt" % n), "/etc/chrony/e2e-s%d.crt" % n)
    text += "".join("ntstrustedcerts /etc/chrony/e2e-s%d.crt\n" % n for n in (1, 2))
    pathlib.Path("/etc/chrony/chrony.conf").write_text(text)
    sh("systemctl", "restart", "chrony")
    return servers


def install():
    """The package, the units, the user and /run/regalia, as a host would have them."""
    if os.path.exists(PREFIX):
        shutil.rmtree(PREFIX)
    os.makedirs(PREFIX)
    shutil.copytree(ROOT / "deploy", pathlib.Path(PREFIX) / "deploy", ignore=shutil.ignore_patterns("__pycache__"))
    units = ROOT / "deploy" / "baremetal" / "units"
    for name in UNITS:
        shutil.copy(units / name, "/etc/systemd/system/" + name)
    shutil.copy(units / "regalia.sysusers.conf", "/etc/sysusers.d/regalia.conf")
    shutil.copy(units / "regalia.tmpfiles.conf", "/etc/tmpfiles.d/regalia.conf")
    sh("systemd-sysusers")
    sh("systemd-tmpfiles", "--create", "/etc/tmpfiles.d/regalia.conf")
    sh("systemctl", "daemon-reload")


def provision(work):
    """What enrolment (#190) will do, by hand: keys, the site configuration, the measurements document, the
    first manifest committed under the TPM anchor (as the regalia-sync user owns its store)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    os.makedirs("/etc/regalia", exist_ok=True)
    keys = {}
    for name in ("a", "b", "c"):
        private = sh("wg", "genkey").stdout.strip()
        keys[name] = (private, wgsvc.hex_key(sh("wg", "pubkey", input=private + "\n").stdout.strip()))
    pathlib.Path("/etc/regalia/wg-service.key").write_text(keys["a"][0] + "\n")
    os.chmod("/etc/regalia/wg-service.key", 0o600)
    root, revoke = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()   # noqa: E731
    reference = {"label": "e2e", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}
    document = {"schema": measurements.SCHEMA, "name": "e2e", "nodes": {n: {"accepted": [dict(reference)]} for n in ("a", "b", "c")}}
    pathlib.Path("/etc/regalia/measurements.json").write_text(json.dumps(document))
    manifest = {"schema": membership.SCHEMA, "epoch": 1, "prev_digest": "", "policy_version": measurements.version(document),
                "issued_at": "2026-10-01T00:00:00Z", "revocation_keys": [raw(revoke)],
                "nodes": [{"node_id": n, "state": "ACTIVE", "ek_name": "000b" + ("%02x" % (0x10 + i)) * 32, "ak_name": "000b" + ("%02x" % (0x40 + i)) * 32,
                           "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": keys[n][1], "hsm_serials": ["E2E%d" % i]}
                          for i, n in enumerate(("a", "b", "c"))]}
    envelope = {"manifest": manifest, "signature": {"signer": "root", "key": raw(root), "sig": root.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}
    site = {"schema": "regalia.baremetal-site/v1", "site": "e2e", "host_ipv4": "192.0.2.10", "kms_port": 8443, "ssh_port": 22,
            "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["203.0.113.128/32"], "admin_cidrs": ["203.0.113.0/28"],
            "outbound": [{"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514},
                         {"name": "ntp", "cidr": "203.0.113.193/32", "proto": "udp", "port": 123}],
            "boot_mesh": {"node_id": "a", "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443,
                          "peers": [{"node_id": "b", "underlay": "192.0.2.20", "address": "10.89.0.2"},
                                    {"node_id": "c", "underlay": "192.0.2.30", "address": "10.89.0.3"}]},
            "service_mesh": {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444, "authority": None}}
    pathlib.Path("/etc/regalia/site.json").write_text(json.dumps(site))
    cfg = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
    cfg.update(node_id="a", root_key=raw(root), time_servers=["127.0.0.2", "127.0.0.3"])
    pathlib.Path("/etc/regalia/node.json").write_text(json.dumps(cfg))
    for directory, owner in (("/var/lib/regalia-sync", "regalia-sync"), ("/var/lib/regalia-admission", "root")):
        os.makedirs(directory, exist_ok=True)
        shutil.chown(directory, owner, owner)
    os.chmod("/var/lib/regalia-sync", 0o755)
    # the anchor and the first manifest, written by the user that owns the store; the TPM through its group
    program = ("import json, sys\nsys.path.insert(0, %r)\nfrom deploy.baremetal import membership as m\n"
               "a = m.HighWater(%r, lock_path='/var/lib/regalia-sync/highwater.lock')\na.define()\n"
               "s = m.Store('/var/lib/regalia-sync/membership.json', %r, a)\ns.commit(json.load(sys.stdin))\nprint(s.load()['epoch'])\n"
               % (PREFIX, cfg["nv_epoch"], raw(root)))
    epoch = sh("runuser", "-u", "regalia-sync", "-g", "regalia-sync", "-G", "tss", "--", "python3", "-I", "-c", program, input=json.dumps(envelope)).stdout.strip()
    counter = ("import sys\nsys.path.insert(0, %r)\nfrom deploy.baremetal import heartbeat\n"
               "heartbeat.Counter(%r, lock_path='/var/lib/regalia-sync/heartbeat-counter.lock').define()\n" % (PREFIX, cfg["nv_heartbeat"]))
    sh("runuser", "-u", "regalia-sync", "-g", "regalia-sync", "-G", "tss", "--", "python3", "-I", "-c", counter)
    return cfg, epoch


def scenario(work):
    header("0  the TPM, as a device, and the controls")
    device = tpm(work)
    ok(device is not None and os.path.exists(device), "a software TPM behind the kernel's vTPM proxy: %s" % device, device)
    rm = (device or "").replace("/dev/tpm", "/dev/tpmrm")
    ok(rm == "/dev/tpmrm0", "its resource manager is /dev/tpmrm0, the device the units allow", rm)
    info = os.stat(rm) if os.path.exists(rm) else None
    ok(info is not None and oct(info.st_mode & 0o777) == "0o660" and sh("stat", "-c", "%G", rm).stdout.strip() == "tss",
       "the device is the tss group's, 0660 (the udev rule a host has)", sh("ls", "-l", rm, check=False).stdout.strip())
    probe = sh("systemd-run", "--wait", "--pipe", "--collect", "-p", "User=root", "-p", "CapabilityBoundingSet=", "-p", "DevicePolicy=closed",
               "-p", "DeviceAllow=/dev/tpmrm0 rw", "-E", "TPM2TOOLS_TCTI=device:/dev/tpmrm0", "--", "tpm2_getrandom", "8", check=False)
    ok(probe.returncode != 0, "control: root with no capability and without the tss group cannot use it", probe.stderr.strip()[-200:])

    header("1  regalia-authtime: chrony with two NTS servers")
    servers = chrony(work)
    install()
    cfg, epoch = provision(work)
    sh("systemctl", "start", "regalia-authtime.service")
    status = pathlib.Path("/run/regalia/authtime.json")
    got = until(lambda: json.loads(status.read_text())["authenticated"] and json.loads(status.read_text()), 120, 2)
    ok(isinstance(got, dict) and got.get("authenticated") is True, "regalia-authtime publishes: authenticated", got if not isinstance(got, dict) else "")
    if not isinstance(got, dict):
        print(journal("regalia-authtime.service"))
        print(sh("chronyc", "-N", "sources", check=False).stdout)
    ok(os.stat(status).st_uid == 0 and oct(os.stat(status).st_mode & 0o777) == "0o644", "root's, 0644, in root's /run/regalia")
    servers[1].terminate()
    servers[1].wait(10)
    gone = until(lambda: not json.loads(status.read_text())["authenticated"] and json.loads(status.read_text()), 150, 3)
    ok(isinstance(gone, dict) and gone.get("authenticated") is False, "one server stops: not authenticated (%s)" % (gone.get("reason", "")[:60] if isinstance(gone, dict) else ""), gone)
    servers[1] = None

    header("2  provisioning, by hand (#190 is not built)")
    ok(epoch == "1", "the first manifest is committed under the TPM anchor, by regalia-sync's user through the tss group", epoch)

    header("3  regalia-sync and regalia-wg-apply")
    sh("systemctl", "start", "regalia-wg-apply.path")
    sh("systemctl", "start", "regalia-sync.service")
    chain = pathlib.Path("/var/lib/regalia-sync/chain.json")
    ok(until(lambda: chain.exists(), 30), "regalia-sync publishes the chain", journal("regalia-sync.service")[-600:])
    ok(oct(os.stat(chain).st_mode & 0o777) == "0o644" and pathlib.Path(chain).owner() == "regalia-sync", "0644, regalia-sync's")
    applied = until(lambda: show("regalia-wg-apply.service", "Result", "ExecMainStatus").get("ExecMainStatus") == "0"
                    and sh("ip", "link", "show", "wg-svc", check=False).returncode == 0, 60, 2)
    ok(applied, "the path unit runs regalia-wg-apply, which verifies the chain against the TPM anchor and brings the tunnels up",
       journal("regalia-wg-apply.service")[-800:])
    for name in ("wg-svc", "wg-unlock"):
        state = sh("ip", "-o", "link", "show", name, check=False).stdout
        ok("UP" in state.split(">")[0] if ">" in state else False, "%s is up" % name, state.strip())
    peers = sh("wg", "show", "wg-svc", "allowed-ips", check=False).stdout
    ok(len(peers.splitlines()) == 2 and all(line.split("\t")[1].endswith("/128") for line in peers.splitlines()),
       "wg-svc's peers are the manifest's two others, one /128 each", peers)
    listening = until(lambda: ":7444" in sh("ss", "-ltn", check=False).stdout and "10.89.0.1:7443" in sh("ss", "-ltn", check=False).stdout, 60, 2)
    ok(listening, "regalia-sync listens on wg-svc (7444) and on wg-unlock (7443)", sh("ss", "-ltn", check=False).stdout[-600:])
    ok(show("regalia-sync.service", "ActiveState")["ActiveState"] == "active", "and stays up", journal("regalia-sync.service")[-600:])

    header("4  regalia-admission")
    sh("systemctl", "start", "regalia-admission.service")
    admission = pathlib.Path("/run/regalia/admission.json")
    doc = until(lambda: json.loads(admission.read_text()), 60, 2)
    ok(isinstance(doc, dict) and doc.get("serve_until_boottime_ms") == 0, "the admission file says: not admitted (%s)" % (doc.get("reason", "")[:70] if isinstance(doc, dict) else ""),
       journal("regalia-admission.service")[-600:])
    ok(pathlib.Path("/run/regalia/boot-session").exists() and pathlib.Path("/run/regalia/boot-session.pub").exists(),
       "with no unlock client this boot, it made a session and wrote both files")

    header("5  the sandboxes as systemd applied them")
    for unit, want in (("regalia-sync.service", {"User": "regalia-sync", "CapabilityBoundingSet": "", "NoNewPrivileges": "yes"}),
                       ("regalia-admission.service", {"User": "root", "CapabilityBoundingSet": ""}),
                       ("regalia-authtime.service", {"CapabilityBoundingSet": "cap_dac_override", "ProtectProc": "invisible"}),
                       ("regalia-wg-apply.service", {"CapabilityBoundingSet": "cap_net_admin"})):
        have = show(unit, *want)
        ok(all(have.get(k) == v for k, v in want.items()), "%s: %s" % (unit, ", ".join("%s=%s" % kv for kv in want.items())), have)
    # the measurement: would chronyd accept a group-writable /run/chrony (so regalia-authtime needs no capability)?
    os.chmod("/run/chrony", 0o770)
    sh("systemctl", "restart", "chrony", check=False)
    accepted = until(lambda: show("chrony.service", "ActiveState")["ActiveState"] == "active" and os.path.exists("/run/chrony/chronyd.sock"), 20)
    print("  MEASURED: chronyd with /run/chrony 0770 -> %s; mode now %s"
          % ("starts" if accepted else "does not start", oct(os.stat("/run/chrony").st_mode & 0o777) if os.path.exists("/run/chrony") else "absent"))
    print(journal("chrony.service", 8))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
