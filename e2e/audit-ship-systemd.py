#!/usr/bin/env python3
"""The trail shipper (#278) under the runner's real systemd, against the real audit collector.

    REGALIA_E2E_BIN=<dir with regalia-audit-ship, regalia-audit-collector> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_E2E_BIN \\
        python3 -Es e2e/audit-ship-systemd.py

IT CHANGES THE MACHINE (a binary in /usr/bin, a unit, /etc/regalia/audit-ship*, users from the shipped
sysusers files, which stay), so it runs only on a
GitHub-hosted runner (RUNNER_ENVIRONMENT=github-hosted), or on a throwaway host whose /etc/machine-id is in
REGALIA_SHIP_HOST_OK.

  0  the shipper runs as its own user with no capability: without its instance's drop-in (the trail's
     group) it cannot read the trail regalia-sync wrote, 0640, and ships nothing;
  1  with units/regalia-audit-ship@sync.service.d as shipped, it reads it through the group and ships it;
  2  a line appended later ships on the next pass, and the collector's stream holds every line;
  2b the client certificate is rotated: `regalia-audit-ship handover` (the old key signs, the new certificate
     presents it), the files swapped, the unit restarted: the same stream goes on, and the old certificate is
     refused (#291);
  3  the trail cut short under what was shipped: the instance ends with status 3, systemd does NOT restart
     it, the collector's alarm log holds the shipper's alarm, and the metrics say tampered;
  4  a manual start repeats the refusal: it never quietly resumes.
"""
import grp
import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
UNIT = HERE.parent / "deploy" / "baremetal" / "units" / "regalia-audit-ship@.service"
TRAILS = HERE.parent / "deploy" / "baremetal" / "trails.py"
INSTANCE = "regalia-audit-ship@sync.service"
COLLECTOR_UNIT = "regalia-e2e-collector.service"
BIN = pathlib.Path("/usr/bin/regalia-audit-ship")
ETC = pathlib.Path("/etc/regalia/audit-ship")
ENV = pathlib.Path("/etc/regalia/audit-ship.env")
INSTALLED = pathlib.Path("/etc/systemd/system/regalia-audit-ship@.service")
DROPIN = pathlib.Path("/etc/systemd/system/regalia-audit-ship@sync.service.d")
UNITS = HERE.parent / "deploy" / "baremetal" / "units"
METRICS = pathlib.Path("/var/lib/regalia-audit-ship/sync.prom")
HEAD = pathlib.Path("/var/lib/regalia-audit-ship/sync.head.json")      # the unit's -head, for prune
PORT = 18443
WORK = pathlib.Path("/var/lib/audit-ship-e2e")   # not under /tmp: the unit has PrivateTmp=yes and would not see it
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


def sh(*argv, check=True, **kw):
    done = subprocess.run(list(argv), capture_output=True, text=True, **kw)
    if check and done.returncode != 0:
        raise SystemExit("audit-ship-systemd: %s failed (%d): %s %s" % (" ".join(argv[:3]), done.returncode, done.stdout.strip()[-800:], done.stderr.strip()[-800:]))
    return done


def until(what, seconds, interval=1.0):
    deadline, last = time.monotonic() + seconds, None
    while time.monotonic() < deadline:
        last = what()
        if last:
            return last
        time.sleep(interval)
    return last


def show(unit, *properties):
    out = sh("systemctl", "show", unit, "-p", ",".join(properties), check=False).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def journal(unit, lines=30):
    return sh("journalctl", "-u", unit, "-n", str(lines), "--no-pager", check=False).stdout


def append_as_writer(path, n, start):
    """trails.append, run as regalia-sync, the sync trail's writer: never the shipper."""
    script = "import sys; sys.path.insert(0, sys.argv[1]); import trails\nfor i in range(int(sys.argv[3])): trails.append(sys.argv[2], {'event': 'sync-pull', 'outcome': 'ALLOW', 'i': int(sys.argv[4]) + i})"
    sh("setpriv", "--reuid=regalia-sync", "--regid=regalia-sync", "--clear-groups", "--", sys.executable, "-Es", "-c", script, str(WORK / "lib"), str(path), str(n), str(start))


def certificates(work):
    """A one-run CA, the collector's certificate for 127.0.0.1 and the shipper's client certificate."""
    def issue(name, extensions):
        sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(work / (name + ".key")),
           "-out", str(work / (name + ".csr")), "-subj", "/CN=" + name)
        (work / (name + ".ext")).write_text(extensions)
        sh("openssl", "x509", "-req", "-in", str(work / (name + ".csr")), "-CA", str(work / "ca.pem"), "-CAkey", str(work / "ca.key"),
           "-CAcreateserial", "-days", "1", "-out", str(work / (name + ".pem")), "-extfile", str(work / (name + ".ext")))
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(work / "ca.key"),
       "-out", str(work / "ca.pem"), "-subj", "/CN=audit-ship-e2e-ca", "-days", "1",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    issue("collector", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    issue("shipper", "extendedKeyUsage=clientAuth\n")
    issue("shipper2", "extendedKeyUsage=clientAuth\n")                # the rotation's new certificate (#291)


def stream_lines(state):
    streams = list((state / "streams").glob("*/site-sitea.sync.jsonl"))
    if len(streams) != 1:
        return 0
    return len(streams[0].read_text().splitlines())


def scenario(work, binaries):
    certificates(work)
    (work / "lib").mkdir()
    shutil.copy(TRAILS, work / "lib" / "trails.py")             # the writer may not traverse the checkout: a copy it can read
    state = work / "collector"
    sh("systemd-sysusers", str(UNITS / "regalia.sysusers.conf"), str(UNITS / "regalia-audit-ship.sysusers.conf"))
    trail_dir = work / "regalia-sync"                          # as its StateDirectory: regalia-sync's, 0755
    trail_dir.mkdir()
    shutil.chown(trail_dir, "regalia-sync", "regalia-sync")
    os.chmod(trail_dir, 0o755)
    trail = trail_dir / "sync-audit.jsonl"

    sh("systemd-run", "--unit", COLLECTOR_UNIT, "--collect", str(binaries / "regalia-audit-collector"), "-state", str(state),
       "-listen", "127.0.0.1:%d" % PORT, "-tls-cert", str(work / "collector.pem"), "-tls-key", str(work / "collector.key"),
       "-client-ca", str(work / "ca.pem"))
    shutil.copy(binaries / "regalia-audit-ship", BIN)
    os.chmod(BIN, 0o755)
    ETC.mkdir(parents=True)
    for source, target, mode in (("shipper.pem", "client.crt", 0o644), ("shipper.key", "client.key", 0o640), ("ca.pem", "collector-ca.pem", 0o644)):
        shutil.copy(work / source, ETC / target)
        shutil.chown(ETC / target, "root", "regalia-audit-ship")
        os.chmod(ETC / target, mode)
    ENV.write_text("COLLECTOR=https://127.0.0.1:%d\nSITE=sitea\n" % PORT)
    (ETC / "sync.env").write_text("TRAIL_PATH=%s\n" % trail)
    shutil.copy(UNIT, INSTALLED)
    sh("systemctl", "daemon-reload")

    print("\n### 0  its own user, no capability: outside the trail's group it reads nothing")
    append_as_writer(trail, 3, 0)
    info = trail.stat()
    ok((info.st_mode & 0o777, info.st_uid, info.st_gid) == (0o640, pwd.getpwnam("regalia-sync").pw_uid, grp.getgrnam("regalia-sync").gr_gid),
       "the trail is regalia-sync's, 0640, in its group", oct(info.st_mode))
    sh("systemctl", "start", INSTANCE)
    time.sleep(8)
    unit = show(INSTANCE, "ActiveState", "CapabilityBoundingSet", "User")
    ok(unit.get("User") == "regalia-audit-ship" and unit.get("CapabilityBoundingSet") == "" and unit.get("ActiveState") == "active",
       "it runs as regalia-audit-ship with no capability", unit)
    ok(stream_lines(state) == 0 and "permission denied" in journal(INSTANCE), "without the drop-in it cannot read the trail, and ships nothing",
       journal(INSTANCE, 5))
    sh("systemctl", "stop", INSTANCE)

    print("\n### 1  with its drop-in it reads through the trail's group, and ships")
    DROPIN.mkdir()
    shutil.copy(UNITS / "regalia-audit-ship@sync.service.d" / "reader.conf", DROPIN / "reader.conf")
    sh("systemctl", "daemon-reload")
    sh("systemctl", "start", INSTANCE)
    ok(until(lambda: stream_lines(state) == 3, 60), "the collector's stream holds the trail's 3 lines", stream_lines(state))

    print("\n### 2  a line appended later ships on the next pass")
    append_as_writer(trail, 2, 3)
    ok(until(lambda: stream_lines(state) == 5, 75), "the stream holds 5 lines after the next pass", stream_lines(state))
    metrics = METRICS.read_text() if METRICS.exists() else ""
    ok('regalia_audit_trail_committed{trail="sync"} 5' in metrics and 'regalia_audit_trail_tampered{trail="sync"} 0' in metrics,
       "the metrics say 5 committed, not tampered", metrics)

    print("\n### 2b  the client certificate rotated: a hand-over, and the stream goes on (#291)")
    done = sh(str(BIN), "handover", "-collector", "https://127.0.0.1:%d" % PORT, "-old-cert", str(work / "shipper.pem"),
              "-old-key", str(work / "shipper.key"), "-tls-cert", str(work / "shipper2.pem"), "-tls-key", str(work / "shipper2.key"),
              "-server-ca", str(work / "ca.pem"), check=False)
    ok(done.returncode == 0, "regalia-audit-ship handover: the old key signs, the new certificate presents it", done.stdout + done.stderr)
    for source, target, mode in (("shipper2.pem", "client.crt", 0o644), ("shipper2.key", "client.key", 0o640)):
        shutil.copy(work / source, ETC / target)
        shutil.chown(ETC / target, "root", "regalia-audit-ship")
        os.chmod(ETC / target, mode)
    sh("systemctl", "restart", INSTANCE)
    append_as_writer(trail, 1, 5)
    ok(until(lambda: stream_lines(state) == 6, 75) and 'regalia_audit_trail_tampered{trail="sync"} 0' in METRICS.read_text(),
       "under the new certificate the same stream goes on to 6 lines, not tampered", (stream_lines(state), journal(INSTANCE, 5)))
    refused = sh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--cert", str(work / "shipper.pem"), "--key", str(work / "shipper.key"),
                 "--cacert", str(work / "ca.pem"), "-H", "X-Regalia-Site: sitea.sync", "https://127.0.0.1:%d/v1/stream-position" % PORT, check=False)
    ok(refused.stdout.strip() == "403", "the old certificate is retired: the collector refuses it", refused.stdout)

    print("\n### 3  the trail cut short: an alarm, status 3, and no restart")
    lines = trail.read_bytes().splitlines(keepends=True)
    trail.write_bytes(b"".join(lines[:2]))                     # root rewrites it in place: still regalia-sync's, 0640
    stopped = until(lambda: show(INSTANCE, "ActiveState").get("ActiveState") == "failed", 75)
    status = show(INSTANCE, "ActiveState", "ExecMainStatus", "NRestarts")
    ok(stopped and status.get("ExecMainStatus") == "3", "the instance failed with status 3", status)
    time.sleep(40)                                              # longer than RestartSec=30s
    status = show(INSTANCE, "ActiveState", "NRestarts")
    ok(status.get("ActiveState") == "failed" and status.get("NRestarts") == "0", "systemd did not restart it", status)
    alarms = [json.loads(line) for line in (state / "alarms.jsonl").read_text().splitlines()]
    ours = [a for a in alarms if a.get("site") == "sitea.sync" and "reported by the client" in a.get("reason", "")]
    ok(len(ours) == 1 and "cut short" in ours[0]["reason"], "the collector's alarm log holds the shipper's alarm", alarms)
    ok(stream_lines(state) == 6, "the collector's stream still holds the 6 committed lines", stream_lines(state))
    ok('regalia_audit_trail_tampered{trail="sync"} 1' in METRICS.read_text(), "the metrics say tampered")

    print("\n### 4  a manual start repeats the refusal")
    sh("systemctl", "start", INSTANCE, check=False)
    until(lambda: show(INSTANCE, "ActiveState").get("ActiveState") == "failed", 30)
    status = show(INSTANCE, "ActiveState", "ExecMainStatus")
    alarms = [line for line in (state / "alarms.jsonl").read_text().splitlines() if "reported by the client" in line]
    ok(status.get("ActiveState") == "failed" and status.get("ExecMainStatus") == "3" and len(alarms) == 2,
       "started by hand, it refuses again with a second alarm", (status, len(alarms)))
    ok(stream_lines(state) == 6, "and ships nothing", stream_lines(state))
    if failed:
        print(journal(INSTANCE))
        print(journal(COLLECTOR_UNIT))
    return 1 if failed else 0


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_SHIP_HOST_OK") != machine):
        print("audit-ship-systemd: refused: this changes the machine (/usr/bin, a unit, /etc/regalia). It runs on a GitHub-hosted "
              "runner; on another throwaway host set REGALIA_SHIP_HOST_OK to its /etc/machine-id.")
        return 2
    present = [str(p) for p in (BIN, ETC, ENV, INSTALLED, DROPIN, METRICS.parent, WORK) if p.exists()]
    if present:
        print("audit-ship-systemd: refused: %s exists: this looks like a host where the shipper is installed" % ", ".join(present))
        return 2
    if os.geteuid() != 0:
        print("audit-ship-systemd: run as root")
        return 2
    binaries = pathlib.Path(os.environ.get("REGALIA_E2E_BIN", "/nonexistent"))
    if not all((binaries / name).is_file() for name in ("regalia-audit-ship", "regalia-audit-collector")):
        print("audit-ship-systemd: REGALIA_E2E_BIN must name a directory with regalia-audit-ship and regalia-audit-collector built")
        return 2
    work = WORK
    work.mkdir(mode=0o755)
    os.chmod(work, 0o755)
    try:
        return scenario(work, binaries)
    finally:
        for unit in (INSTANCE, COLLECTOR_UNIT):
            sh("systemctl", "stop", unit, check=False)
            sh("systemctl", "reset-failed", unit, check=False)
        for path in (DROPIN / "reader.conf", INSTALLED, BIN, ENV, ETC / "sync.env", ETC / "client.crt", ETC / "client.key", ETC / "collector-ca.pem", METRICS, HEAD):
            if path.exists():
                path.unlink()
        for directory in (DROPIN, ETC, METRICS.parent):
            if directory.exists():
                directory.rmdir()
        sh("systemctl", "daemon-reload", check=False)
        shutil.rmtree(work, ignore_errors=True)
        print("\naudit-ship-systemd: %d passed, %d failed" % (passed, failed))


if __name__ == "__main__":
    raise SystemExit(main())
