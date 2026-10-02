#!/usr/bin/env python3
"""Authenticated time, against live chrony daemons with NTS (#69, #80).

    python3 e2e/authtime-chrony-nts.py        (CHRONYD= and CHRONYC= name the binaries if not on the path)

Private daemons only, on the loopback, on ports of their own, none of them allowed to touch the machine's
clock (-x): two NTS servers (each with its own certificate, as two independent operators would have) and
one client configured as authtime.conf() configures a host (every source NTS, `authselectmode require`,
`minsources 2`). deploy/baremetal/authtime.py then asks the client's chronyd, through its command socket,
exactly as the root service will on a host:

  1  both servers answer: chrony is synchronised to two agreeing NTS sources -> authenticated, published,
     and believed by an unprivileged reader
  2  one server stops: one source left -> not authenticated, with that reason
  3  a plain NTP source (a third server) is configured beside the two NTS ones -> not authenticated,
     whatever chrony does with it
  4  the only source is plain NTP -> not authenticated
  5  the root service stops: a minute later (here, two seconds) the published answer is no longer believed
"""
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from deploy.baremetal import authtime                                       # noqa: E402
from deploy.baremetal import membership as m                                # noqa: E402

CHRONYD = os.environ.get("CHRONYD") or shutil.which("chronyd") or "/usr/sbin/chronyd"
CHRONYC = os.environ.get("CHRONYC") or shutil.which("chronyc") or "/usr/bin/chronyc"
passed, failed = 0, 0


def ok(condition, text, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  \033[32mPASS\033[0m %s" % text)
    else:
        failed += 1
        print("  \033[31mFAIL\033[0m %s%s" % (text, (": %s" % (detail,)) if detail != "" else ""))


def header(text):
    print("\n\033[1m### %s\033[0m" % text)


def main():
    for tool in (CHRONYD, CHRONYC, shutil.which("openssl")):
        if not tool or not os.path.exists(tool):
            print("authtime-chrony-nts: chronyd, chronyc and openssl are required (CHRONYD=, CHRONYC= to point at them)")
            return 2
    work = tempfile.mkdtemp(prefix="authtime-")      # 0700: chronyd refuses a command socket in a directory others can enter
    daemons = {}

    def stop(name):
        process = daemons.pop(name, None)
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()

    try:
        return scenario(work, daemons, stop)
    finally:
        for name in list(daemons):
            stop(name)
        shutil.rmtree(work, ignore_errors=True)


def scenario(work, daemons, stop):
    base = random.randrange(20000, 40000, 10)
    servers = {"one": ("127.0.0.1", base + 1, base + 2), "two": ("127.0.0.2", base + 3, base + 4)}
    user = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()

    def start(name, text):
        path = os.path.join(work, name + ".conf")
        with open(path, "w") as f:
            f.write(text + "cmdport 0\nbindcmdaddress %s/%s.sock\npidfile %s/%s.pid\n" % (work, name, work, name))
        daemons[name] = subprocess.Popen([CHRONYD, "-x", "-U", "-u", user, "-n", "-f", path], cwd=work,
                                         stdout=open(os.path.join(work, name + ".log"), "w"), stderr=subprocess.STDOUT)

    for name, (address, port, ke) in servers.items():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                        "-keyout", "%s/%s.key" % (work, name), "-out", "%s/%s.crt" % (work, name), "-subj", "/CN=" + address,
                        "-addext", "subjectAltName=IP:" + address], check=True, capture_output=True)
        start(name, "local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s/%s.key\nntsservercert %s/%s.crt\nallow 127.0.0.0/8\nntsdumpdir %s\n"
              % (port, ke, address, work, name, work, name, work))
    trust = "".join("ntstrustedcerts %s/%s.crt\n" % (work, name) for name in servers)

    def client(sources):
        stop("client")
        start("client", sources + trust + "authselectmode require\nminsources 2\n")

    def nts(name):
        address, port, ke = servers[name]
        return "server %s port %d nts ntsport %d iburst minpoll 0 maxpoll 1\n" % (address, port, ke)

    sock = os.path.join(work, "client.sock")
    ask = lambda: authtime.ask(chronyc=CHRONYC, socket_path=sock)       # noqa: E731

    def verdict():
        try:
            authtime.judge(ask(), time.time())
            return ""
        except m.Refused as refused:
            return str(refused)

    def until(wanted, seconds):
        deadline, last = time.monotonic() + seconds, None
        while time.monotonic() < deadline:
            last = verdict()
            if wanted(last):
                return last
            time.sleep(1)
        return last

    published = os.path.join(work, "run")           # where the status goes: its own directory, 0755 as /run/regalia is
    os.mkdir(published, 0o755)
    os.chmod(published, 0o755)
    status = os.path.join(published, "authtime.json")
    service = authtime.Service(status, reading=ask)
    believed = authtime.clock(status, owner=os.getuid())

    header("1  two NTS servers answer: the clock is authenticated")
    client(nts("one") + nts("two"))
    said = until(lambda v: v == "", 90)
    ok(said == "", "chrony is synchronised to two agreeing NTS sources, and authtime says authenticated", said)
    if said:                                         # nothing below can be shown without it: say what the daemons said
        for name in ("one", "two", "client"):
            print("--- %s.log\n%s" % (name, open(os.path.join(work, name + ".log")).read()[-1500:]))
        print("\nauthtime-chrony-nts: %d passed, %d failed" % (passed, failed))
        return 1
    sources = ask()["sources"]
    ok(sorted(s["mode"] for s in sources) == ["NTS", "NTS"] and all(s["keyed"] for s in sources),
       "chrony reports both sources in NTS mode, with keys from a completed key exchange", sources)
    document = service.step()
    ok(document["authenticated"] is True and document["reason"] == "", "the root service publishes it", document)
    ok(believed()[1] is True, "and an unprivileged reader believes it")

    header("2  one server stops: one source is not enough")
    stop("two")
    said = until(lambda v: v != "", 120)
    ok("only 1 NTS source(s) agree" in said or "has stopped answering" in said or "holds no NTS keys" in said,
       "with one NTS source left, not authenticated (%s)" % said[:70], said)
    document = service.step()
    ok(document["authenticated"] is False and believed()[1] is False, "published as such, and believed as such", document)

    header("3  a plain NTP source beside the two NTS ones")
    address, port, ke = servers["two"]
    start("two", "local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s/two.key\nntsservercert %s/two.crt\nallow 127.0.0.0/8\nntsdumpdir %s\n"
          % (port, ke, address, work, work, work))
    client(nts("one") + nts("two"))
    ok(until(lambda v: v == "", 90) == "", "(both NTS servers back: authenticated again)")
    plain = ("127.0.0.3", base + 5)                  # a third operator's server, without NTS
    start("three", "local stratum 8\nport %d\nbindaddress %s\nallow 127.0.0.0/8\n" % (plain[1], plain[0]))
    client(nts("one") + nts("two") + "server %s port %d iburst minpoll 0 maxpoll 1\n" % plain)
    said = until(lambda v: "without NTS" in v, 60)
    ok("a time source without NTS is configured" in said, "a plain NTP source anywhere in the configuration refuses", said)

    header("4  the only source is plain NTP")
    client("server %s port %d iburst minpoll 0 maxpoll 1\n" % plain)
    time.sleep(8)
    said = verdict()
    ok(said != "", "not authenticated", said)
    ok("not synchronised" in said or "without NTS" in said, "because chrony selects nothing it cannot authenticate, or the source is not NTS", said)

    header("5  the root service stops")
    client(nts("one") + nts("two"))
    ok(until(lambda v: v == "", 90) == "", "(authenticated again)")
    service.step()
    stale = authtime.clock(status, owner=os.getuid(), max_stale=2)
    ok(stale()[1] is True, "a fresh status is believed")
    time.sleep(3)
    ok(stale()[1] is False, "nobody re-checked for longer than the bound: the same status is no longer believed")

    print("\nauthtime-chrony-nts: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
