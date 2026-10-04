#!/usr/bin/env python3
"""#388: a re-anchor in a total outage, rehearsed on three nodes (e2e/lib/threenode.py, v4: each node its real services in
its own namespace against its own TPM, the nodes signing their own heartbeats; no authority host).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-reanchor.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

The procedure it holds to (deploy/baremetal/MEMBERSHIP-RECOVERY.md, "In a total outage"): every server is down and b's
TPM anchor is unusable. Without an authority host, `reanchor` needs whole chains from two OTHER nodes, so the other two
are opened by hand too, each with its own recovery key; their published chain.json is taken from each, by its holder;
`reanchor --peer a=… --peer c=…` runs on b, as root at b's console, its phrase typed at the terminal; then the three
start and b serves again. A server whose two peers are both destroyed has no such path: that is a root ceremony.

  1  three nodes, a second epoch delivered by the root (deliver.py, to a running node), every node leased on it
  2  the total outage: all three powered off
  3  b's anchor made unusable: its epoch counter undefined in its TPM (a record slot still holds epoch 2): b's own
     membership no longer loads, and says why
  4  a and c opened by hand with their recovery keys; their chain.json taken, one from each
  5  b opened by hand; the refusals, each changing nothing: one peer only; b's own chain as a peer; the phrase mistyped
  6  the re-anchor from a's and c's chains: typed at the terminal, done, recorded ALLOW; b's membership loads at epoch 2
     under the new anchor, and the file is regalia-sync's again (#388: written by root, given back); run again, it is
     refused, since the anchor is usable
  7  the three start: b holds a heartbeat the nodes signed and a lease, and issues one: it serves again
"""
import json
import os
import pathlib
import pty
import pwd
import select
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402
from deploy.baremetal import membership, node        # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")


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


def refusal(fn):
    try:
        fn()
    except membership.Refused as refused:
        return str(refused)
    return None


def at_console(cluster, name, argv, answer=None, timeout=180):
    """`argv` run as root at `name`'s console: a transient unit in its namespace, with what a booted host's systemd-stub
    gives (the node's PCR signatures and system-phase key, bound where the node's own services read them), on a terminal
    (systemd-run --pty, itself driven through a pty here). `answer`: what the operator types at the "Type exactly:" prompt
    (True: the phrase as printed; a string: that string; None: nothing). Returns (exit status, what the terminal showed).
    No TPM2TOOLS_TCTI reaches it: the unit's environment is its own."""
    identity = set(cluster.identity("sync"))
    props = [p for p in cluster.properties(name, "sync") if p.split("=", 1)[0] not in identity]   # root's, not regalia-sync's
    unit = "%s%s-console-%d" % (threenode.UNIT_PREFIX, name, int(time.monotonic() * 1000))
    command = ["systemd-run", "--unit", unit, "--collect", "--quiet", "--pty", "--wait"] + sum((["-p", p] for p in props), []) + argv
    pid, fd = pty.fork()
    if pid == 0:                                                       # the child: systemd-run on the pty's terminal
        os.execvp(command[0], command)
    shown, typed, deadline = b"", False, time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 2)
        if not ready:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:                                                # the terminal closed: the command ended
            break
        if not data:
            break
        shown += data
        if answer is not None and not typed and b"Type exactly: " in shown and b"\n> " in shown.replace(b"\r", b""):
            phrase = shown.replace(b"\r", b"").split(b"Type exactly: ", 1)[1].split(b"\n", 1)[0]
            os.write(fd, (phrase if answer is True else answer.encode()) + b"\n")
            typed = True
    else:
        os.kill(pid, 9)
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), shown.decode(errors="replace").replace("\r", "")


def scenario(cluster, work):
    names = list(cluster.nodes)
    a, b, c = names

    header("1  three nodes, a second epoch from the root, every node leased on it")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    manifest, _ = cluster.advance(a)                  # the root's envelope, given to a running a (deliver.py); b and c pull it
    fresh = cluster.fresh(names, manifest["epoch"], timeout=300)
    ok(all(fresh.values()) and all(cluster.node(n).store().load()["epoch"] == 2 for n in names),
       "every node holds epoch 2 (the root's, delivered to a, pulled by b and c) and a heartbeat the nodes signed for it (%s)" % fresh,
       cluster.beat_events(names))
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 150, 3)), "%s holds a lease" % name, cluster.journal(name, "admission")[-600:])

    header("2  the total outage")
    for name in names:
        cluster.stop(name)
    ok(not any(cluster.running(n) for n in names), "a, b and c are powered off")

    header("3  b's anchor unusable: its epoch counter gone from its TPM")
    cfg = cluster.node(b).cfg
    index = "0x%x" % int(str(cfg["nv_epoch"]), 0)
    gone = sh("tpm2_nvundefine", "-T", cluster.nodes[b].tcti, "-C", "o", index, check=False)
    said = refusal(lambda: cluster.node(b).store().load())
    ok(gone.returncode == 0 and said is not None,
       "b's epoch counter %s undefined in its TPM: b's own membership no longer loads (%s)" % (index, (said or "it loads")[:120]),
       gone.stderr[-300:])

    header("4  a and c opened by hand, each with its own recovery key; their chains taken, one from each")
    d = work / "reanchor"
    d.mkdir(mode=0o700)
    chains = {}
    for name in (a, c):
        got = cluster.recover(name)
        ok(got["rc"] == 0 and got["peer"] is None and got["marker"],
           "%s's volume opened by hand with its recovery key (keyslot %s, no peer's) and read back" % (name, got["slot"]), got)
        chains[name] = d / ("%s-chain.json" % name)
        shutil.copyfile(cluster.nodes[name].state / node.PUBLISHED, chains[name])
    held = {n: membership.load(chains[n].read_bytes(), membership.MAX_CHAIN_BYTES) for n in (a, c)}
    ok(all(len(held[n]) == 2 for n in (a, c)) and membership.digest(held[a][-1]["manifest"]) == membership.digest(held[c][-1]["manifest"]),
       "a's and c's published chains both end at epoch 2, at one manifest",
       {n: [e["manifest"]["epoch"] for e in held[n]] for n in (a, c)})

    header("5  b opened by hand; what is refused, changing nothing")
    got = cluster.recover(b)
    ok(got["rc"] == 0 and got["peer"] is None and got["marker"], "b's volume opened by hand with its recovery key", got)
    shutil.copyfile(cluster.nodes[b].state / node.PUBLISHED, d / "b-chain.json")
    trail = d / "b-reanchor.jsonl"

    def reanchor(peers, answer=None):
        argv = ["/usr/bin/python3", "-Es", "-m", "deploy.baremetal.reanchor", "--membership", str(cluster.node(b).path("membership.json")),
                "--root-key", cfg["root_key"], "--tpm-index", index, "--tcti", cluster.nodes[b].tcti, "--node-id", b,
                "--node-config", str(cluster.nodes[b].cfg_path), "--audit-log", str(trail)]
        for peer, path in peers:
            argv += ["--peer", "%s=%s" % (peer, path)]
        return at_console(cluster, b, argv, answer)

    def unchanged():
        return refusal(lambda: cluster.node(b).store().load()) is not None
    rc, shown = reanchor([(a, chains[a])])
    ok(rc == 1 and "at least two other nodes" in shown and unchanged(), "one peer's chain only: refused (status %s), nothing changed" % rc, shown[-400:])
    rc, shown = reanchor([(a, chains[a]), (b, d / "b-chain.json")])
    ok(rc == 1 and "cannot be a source for its own re-anchor" in shown and unchanged(),
       "b's own chain given as a peer's: refused (status %s), nothing changed" % rc, shown[-400:])
    rc, shown = reanchor([(a, chains[a]), (c, chains[c])], answer="re-anchor b")
    ok(rc == 1 and "not confirmed" in shown and unchanged(), "the phrase mistyped at the terminal: refused (status %s), nothing changed" % rc,
       shown[-400:])

    header("6  the re-anchor from a's and c's chains, typed at b's terminal")
    rc, shown = reanchor([(a, chains[a]), (c, chains[c])], answer=True)
    digest = membership.digest(held[a][-1]["manifest"])
    ok(rc == 0 and ("reanchor: done. b now holds epoch 2, manifest %s" % digest) in shown,
       "done (status %s): b holds epoch 2, manifest %s..., under a new anchor" % (rc, digest[:16]), shown[-800:])
    lines = [json.loads(line) for line in trail.read_text().splitlines() if line.strip()]
    ok([e.get("outcome") for e in lines if e.get("event") == "reanchor"][-1:] == ["ALLOW"]
       and any(e.get("event") == "reanchor-requested" and e.get("epoch") == 2 for e in lines),
       "its audit trail records the request at epoch 2, then ALLOW", lines[-3:])
    loaded = refusal(lambda: cluster.node(b).store().load())
    ok(loaded is None and cluster.node(b).store().load()["epoch"] == 2, "b's own membership loads again, at epoch 2", loaded)
    sync = pwd.getpwnam("regalia-sync")
    held_by = os.stat(cluster.node(b).path("membership.json"))
    ok((held_by.st_uid, held_by.st_gid) == (sync.pw_uid, sync.pw_gid),
       "the membership file root wrote is regalia-sync's again (#388), as its directory is", (held_by.st_uid, held_by.st_gid))
    rc, shown = reanchor([(a, chains[a]), (c, chains[c])], answer=True)
    ok(rc == 1 and "the TPM anchor is usable" in shown, "run again, it is refused (status %s): a usable anchor is never reset" % rc, shown[-400:])

    header("7  the three start: b serves again")
    since = time.time()
    for name in names:
        cluster.start(name, SERVICES)
    fresh = cluster.fresh(names, 2, timeout=300)
    ok(all(fresh.values()), "every node holds a heartbeat for epoch 2 the nodes signed (%s)" % fresh, cluster.beat_events(names))
    ok(bool(until(lambda: cluster.lease(b), 150, 3)), "b holds a lease again (from %s)" % cluster.lease_issuer(b), cluster.journal(b, "admission")[-600:])
    issued = until(lambda: [e.get("subject") for e in cluster.trail(b) if e.get("event") == "sync-lease" and e.get("outcome") == "ALLOW"
                            and e.get("at", 0) >= since], 300, 5)
    ok(bool(issued), "and b issues leases to its peers again (%s): it serves" % sorted(set(issued or [])), cluster.journal(b, "sync")[-600:])


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-reanchor: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("three-node-reanchor: refused: %s exists: another run's leftovers are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-reanchor: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work)
    try:
        scenario(cluster, work)
    except Exception:                     # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-1500:])
        for name in list(cluster.nodes):
            print("----- %s sync\n%s\n----- %s admission\n%s" % (name, cluster.journal(name, "sync"), name, cluster.journal(name, "admission")))
        print("----- heartbeat events\n%s" % cluster.beat_events(list(cluster.nodes), last=8))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-reanchor: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
