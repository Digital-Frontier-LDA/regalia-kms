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
  2  the second source agrees but chrony leaves it out of the combination ("-", as with two servers at
     different distances) -> still authenticated
  3  one server stops: one source left -> not authenticated, with that reason
  4  a plain NTP source (a third server) is configured beside the two NTS ones -> not authenticated,
     whatever chrony does with it; and so is a third NTS server that nobody declared
  5  the only source is plain NTP -> not authenticated
  6  the root service stops: a minute later (here, two seconds) the published answer is no longer believed
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
    # The daemons run from a COPY of chronyd. A distribution confines /usr/sbin/chronyd by its path (AppArmor)
    # to its own directories, and a confined chronyd cannot read a configuration in a scratch directory. The
    # copy is the same program, unconfined, and it is never given the right to set the clock (-x).
    chronyd = os.path.join(work, "chronyd")
    shutil.copy(CHRONYD, chronyd)
    os.chmod(chronyd, 0o700)
    base = random.randrange(20000, 40000, 10)
    servers = {"one": ("127.0.0.1", base + 1, base + 2), "two": ("127.0.0.2", base + 3, base + 4)}
    user = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()

    def start(name, text):
        path = os.path.join(work, name + ".conf")
        with open(path, "w") as f:
            f.write(text + "cmdport 0\nbindcmdaddress %s/%s.sock\npidfile %s/%s.pid\n" % (work, name, work, name))
        daemons[name] = subprocess.Popen([chronyd, "-x", "-U", "-u", user, "-n", "-f", path], cwd=work,
                                         stdout=open(os.path.join(work, name + ".log"), "w"), stderr=subprocess.STDOUT)

    for name, (address, port, ke) in servers.items():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                        "-keyout", "%s/%s.key" % (work, name), "-out", "%s/%s.crt" % (work, name), "-subj", "/CN=" + address,
                        "-addext", "subjectAltName=IP:" + address], check=True, capture_output=True)
        start(name, "local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s/%s.key\nntsservercert %s/%s.crt\nallow 127.0.0.0/8\nntsdumpdir %s\n"
              % (port, ke, address, work, name, work, name, work))
    trust = "".join("ntstrustedcerts %s/%s.crt\n" % (work, name) for name in servers)

    def client(sources, more=""):
        stop("client")
        start("client", sources + trust + "authselectmode require\nminsources 2\n" + more)

    def nts(name):
        address, port, ke = servers[name]
        return "server %s port %d nts ntsport %d iburst minpoll 0 maxpoll 1\n" % (address, port, ke)

    sock = os.path.join(work, "client.sock")
    ask = lambda: authtime.ask(chronyc=CHRONYC, socket_path=sock)       # noqa: E731

    declared = [servers["one"][0], servers["two"][0]]

    def verdict():
        try:
            authtime.judge(ask(), time.time(), declared)
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
    service = authtime.Service(status, declared, reading=ask)
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

    header("2  a source that agrees and is not combined still counts")
    client(nts("one") + nts("two"), "combinelimit 0\n")
    said = until(lambda v: v == "", 90)
    states = sorted(s["state"] for s in ask()["sources"])
    ok(states == ["*", "-"], "chrony selects one source and leaves the other out of the combination (states %s)" % states, states)
    ok(said == "", "and the clock is authenticated: two NTS sources agree", said)
    client(nts("one") + nts("two"))
    ok(until(lambda v: v == "", 90) == "", "(back to the usual configuration: authenticated)")

    header("3  one server stops: one source is not enough")
    stop("two")
    said = until(lambda v: v != "", 120)
    ok("only 1 NTS source(s) agree" in said or "has stopped answering" in said or "holds no NTS keys" in said,
       "with one NTS source left, not authenticated (%s)" % said[:70], said)
    document = service.step()
    ok(document["authenticated"] is False and believed()[1] is False, "published as such, and believed as such", document)

    header("4  a plain NTP source beside the two NTS ones, and an NTS source nobody declared")
    address, port, ke = servers["two"]
    start("two", "local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s/two.key\nntsservercert %s/two.crt\nallow 127.0.0.0/8\nntsdumpdir %s\n"
          % (port, ke, address, work, work, work))
    client(nts("one") + nts("two"))
    ok(until(lambda v: v == "", 90) == "", "(both NTS servers back: authenticated again)")
    plain = ("127.0.0.3", base + 5)                  # a third operator's server, without NTS
    start("three", "local stratum 8\nport %d\nbindaddress %s\nallow 127.0.0.0/8\n" % (plain[1], plain[0]))
    client(nts("one") + nts("two") + "server %s port %d iburst minpoll 0 maxpoll 1\n" % plain)
    said = until(lambda v: "without NTS" in v, 60)
    ok("a time source nobody declared is configured" in said or "a time source without NTS is configured" in said,
       "a plain NTP source anywhere in the configuration refuses (%s)" % said[:60], said)
    # the same third server WITH NTS, and still not one the site declared: a pool or a DHCP-supplied server would look like this
    stop("three")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                    "-keyout", "%s/three.key" % work, "-out", "%s/three.crt" % work, "-subj", "/CN=" + plain[0],
                    "-addext", "subjectAltName=IP:" + plain[0]], check=True, capture_output=True)
    start("three", "local stratum 8\nport %d\nntsport %d\nbindaddress %s\nntsserverkey %s/three.key\nntsservercert %s/three.crt\nallow 127.0.0.0/8\nntsdumpdir %s\n"
          % (plain[1], base + 6, plain[0], work, work, work))
    client(nts("one") + nts("two") + "server %s port %d nts ntsport %d iburst minpoll 0 maxpoll 1\n" % (plain[0], plain[1], base + 6),
           "ntstrustedcerts %s/three.crt\n" % work)
    said = until(lambda v: "nobody declared" in v, 60)
    ok("a time source nobody declared is configured: %s" % plain[0] in said, "an NTS source that was not declared refuses too", said)
    undeclared = [s for s in ask()["sources"] if s["name"] == plain[0]]
    ok(len(undeclared) == 1 and undeclared[0]["mode"] == "NTS", "(chrony itself reports that third source in NTS mode)", undeclared)
    stop("three")
    start("three", "local stratum 8\nport %d\nbindaddress %s\nallow 127.0.0.0/8\n" % (plain[1], plain[0]))

    header("5  the only source is plain NTP")
    client("server %s port %d iburst minpoll 0 maxpoll 1\n" % plain)
    time.sleep(8)
    said = verdict()
    ok(said != "", "not authenticated", said)
    ok("not synchronised" in said or "without NTS" in said or "nobody declared" in said,
       "because chrony selects nothing it cannot authenticate, or the source is not one of ours", said)

    header("6  the root service stops")
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
