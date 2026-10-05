#!/usr/bin/env python3
"""regalia-sync over real WireGuard, in network namespaces (#80, step 2).

    sudo python3 -Es e2e/regalia-sync-netns.py

Three throwaway namespaces on one bridge: the nodes a, b and c. Each has a real
WireGuard interface `wg-svc`, configured by wgsvc.reconcile from the manifest it holds, with real keys and
the addresses derived from them. sync.Server answers on each node's tunnel address; sync.Client asks from
inside the caller's namespace. Nothing here touches the machine's own network: every interface, address and
route lives in a namespace that is deleted at the end.

The membership side is the fixture of tests/test_baremetal_sync.py (stores, heartbeats, the lease issuer),
with the manifest's wg_service_pub set to the real keys. The TPM is the fixtures' stand-in: what is proven
here is the transport, on the kernel's WireGuard. A new epoch enters at b from the fixture's seed chain, in
process (where revoke.py's commit or a root envelope would put it on a host, #199): every step after that is
node to node, through the tunnels.

  1  the interfaces are what the manifest says, read back from the kernel
  2  a node with nothing pulls the chain and the heartbeat from a peer through the tunnel
  3  a lease is asked for and issued across the tunnel
  4  c is revoked: the peers converge; c is refused by name while its tunnel is still up, and
     gets no answer at all once the peer's interface is reconciled
  5  an address that is not its key's does not get through WireGuard
  6  a peer list that is not the manifest's is detected by the read-back, and repaired
  7  a partitioned node catches up in rounds, and authorizes nothing until a heartbeat for the tip arrives
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from deploy.baremetal import lease, sync, wgsvc                          # noqa: E402
from deploy.baremetal import heartbeat as hb                            # noqa: E402
from deploy.baremetal import membership as m                            # noqa: E402
import tests.test_baremetal_heartbeat as hbt                            # noqa: E402
import tests.test_baremetal_replacement as rt                           # noqa: E402
import tests.test_baremetal_sync as st                                  # noqa: E402

SFX = "rs%d" % os.getpid()
NODES = ("a", "b", "c")
HOSTS = NODES
UNDERLAY = {"a": "192.0.2.11", "b": "192.0.2.12", "c": "192.0.2.13"}
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


def ns(host):
    return "%s-%s" % (host, SFX)


def sh(*argv, **kw):
    return subprocess.run(list(argv), capture_output=True, check=True, **kw)


def in_ns(host):
    """A `run` for wgsvc that executes inside `host`'s namespace."""
    def run(argv, **kw):
        return subprocess.run(["ip", "netns", "exec", ns(host)] + list(argv), **kw)
    return run


def inside(host, fn):
    """Run fn() in a thread that has entered `host`'s network namespace (sockets it creates live there)."""
    out = {}

    def enter():
        try:
            fd = os.open("/run/netns/" + ns(host), os.O_RDONLY)
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


class Fixture(st.Case):
    """The sync tests' fixture with real WireGuard keys in the manifest."""
    wg = {}

    def runTest(self):
        pass

    def manifest(self, epoch=1, prev="", **states):
        manifest = super().manifest(epoch, prev, **states)
        for node in manifest["nodes"]:
            node["wg_service_pub"] = self.wg.get(node["node_id"], node["wg_service_pub"])
        return manifest

    def entry(self, node_id, state="ACTIVE", n=None, **override):
        entry = super().entry(node_id, state, n, **override)
        entry["wg_service_pub"] = self.wg.get(node_id, entry["wg_service_pub"])
        return entry


def main():
    if os.geteuid() != 0:
        print("regalia-sync-netns: run as root (sudo): it creates network namespaces and WireGuard interfaces")
        return 2
    for tool in ("ip", "wg", "openssl"):
        if not shutil.which(tool):
            print("regalia-sync-netns: %s is required (iproute2, wireguard-tools, openssl)" % tool)
            return 2
    work = tempfile.mkdtemp()
    stop, threads = [], []
    Fixture.setUpClass()
    fixture = Fixture()

    def cleanup():
        stop.append(True)
        for thread in threads:
            thread.join(5)
        for host in HOSTS + ("sw",):
            subprocess.run(["ip", "netns", "del", ns(host)], capture_output=True)
        try:
            fixture.doCleanups()
            Fixture.tearDownClass()
        finally:
            shutil.rmtree(work, ignore_errors=True)

    try:
        return scenario(fixture, stop, threads)
    finally:
        cleanup()


def scenario(fixture, stop, threads):
    # ---- the underlay: one bridge, three hosts -----------------------------------------------------------
    sh("ip", "netns", "add", ns("sw"))
    sh("ip", "-n", ns("sw"), "link", "add", "br0", "type", "bridge")
    sh("ip", "-n", ns("sw"), "link", "set", "br0", "up")
    for i, host in enumerate(HOSTS):
        veth = "v%d%s" % (i, SFX)
        sh("ip", "netns", "add", ns(host))
        sh("ip", "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", ns(host))
        sh("ip", "link", "set", veth, "netns", ns("sw"))
        sh("ip", "-n", ns("sw"), "link", "set", veth, "master", "br0", "up")
        sh("ip", "-n", ns(host), "link", "set", "lo", "up")
        sh("ip", "-n", ns(host), "addr", "add", UNDERLAY[host] + "/24", "dev", "eth0")
        sh("ip", "-n", ns(host), "link", "set", "eth0", "up")

    # ---- real WireGuard keys; the manifest pins the public halves ----------------------------------------
    private, public = {}, {}
    for host in HOSTS:
        private[host] = sh("wg", "genkey").stdout.decode().strip()
        public[host] = wgsvc.hex_key(sh("wg", "pubkey", input=private[host].encode()).stdout.decode().strip())
    Fixture.wg = {name: public[name] for name in NODES}
    fixture.setUp()
    address = {host: wgsvc.address(public[host]) for host in HOSTS}
    stores = dict(fixture.stores)
    freshness = {"a": fixture.own, "b": fixture.peers["b"]["freshness"], "c": fixture.peers["c"]["freshness"]}
    events = {host: [] for host in HOSTS}

    def reconcile(host, manifest=None):
        """The root side on `host`, under the manifest it holds (or the one given)."""
        manifest = manifest or stores[host].load()
        others = {n: UNDERLAY[n] for n in NODES if n != host}
        return wgsvc.reconcile(manifest, host, others, private[host], run=in_ns(host))

    def peers_of(host):
        shown = in_ns(host)(["wg", "show", "wg-svc", "allowed-ips"], capture_output=True).stdout.decode()
        return {key for keys in wgsvc.owners(shown).values() for key in keys}

    # ---- 1 ------------------------------------------------------------------------------------------------
    header("1  the interfaces are what the manifest says, read back from the kernel")
    # node a holds nothing yet: it is given the first manifest as an enrolled node is (the chain is verified by its store)
    stores["a"].commit(fixture.e1)
    for host in HOSTS:
        own = reconcile(host)
        ok(own == address[host], "%s: wg-svc is up at the address its key derives, and the kernel's peers are the manifest's" % host, own)
    ok(peers_of("a") == {public["b"], public["c"]}, "a's peers: b and c, by the manifest's keys, and nobody else")

    # ---- the servers, each listening on its tunnel address inside its namespace ----------------------------
    servers = {
        "b": sync.Server("b", stores["b"], freshness["b"], fixture.peers["b"]["attester"], fixture.peers["b"]["signer"],
                         wgsvc.key_at, events["b"].append, clock=lambda: fixture.now),
        "c": sync.Server("c", stores["c"], freshness["c"], fixture.peers["c"]["attester"], fixture.peers["c"]["signer"],
                         wgsvc.key_at, events["c"].append, clock=lambda: fixture.now),
    }
    for host, server in servers.items():
        listener = inside(host, lambda host=host: socket.create_server((address[host], sync.PORT), family=socket.AF_INET6))
        listener.settimeout(0.1)
        thread = threading.Thread(target=sync.serve, args=(server, listener, lambda: bool(stop)), daemon=True)
        thread.start()
        threads.append(thread)

    def transport(caller, target, source=None, timeout=4):
        send = sync.tcp_transport(address[target], sync.PORT, source=source or address[caller], timeout=timeout)
        return lambda raw: inside(caller, lambda: send(raw))

    def client(caller, store, fresh):
        sources = {name: transport(caller, name) for name in ("b", "c") if name != caller}
        if caller == "b":                                                 # where a new epoch enters: in process, not a tunnel
            sources["seed"] = fixture.wire("seed", "b")
        return sync.Client(caller, store, fresh, sources, events[caller].append)

    def refusal(fn):
        try:
            fn()
        except m.Refused as refused:
            return str(refused)
        return ""

    clients = {name: client(name, stores[name], freshness[name]) for name in NODES}

    # ---- 2 ------------------------------------------------------------------------------------------------
    header("2  a node pulls the heartbeat it lacks from a peer, through the tunnel")
    ok("no heartbeat is held" in refusal(lambda: freshness["a"].check(stores["a"].load())), "before: a holds the manifest and no heartbeat, so it authorizes nobody")
    now_at, fresh = clients["a"].pull("b")
    ok(now_at["epoch"] == 1 and fresh == hb.MAX_LIFETIME - 60, "a pulled from b over wg-svc: epoch 1 and b's heartbeat (%s s left)" % fresh, (now_at, fresh))
    last = events["b"][-1]
    ok((last["event"], last["outcome"], last["subject"], last["peer"]) == ("sync-pull", "ALLOW", "a", "b"),
       "b recorded the caller as node a: identified by the tunnel address its key derives", last)

    # ---- 3 ------------------------------------------------------------------------------------------------
    header("3  a lease is asked for and issued across the tunnel")
    envelope = clients["a"].renewer("b", fixture.quote)(fixture.holder.request())
    left = fixture.holder.install(envelope, stores["a"].load())
    ok(left == lease.MAX_LIFETIME and envelope["lease"]["issuer"] == "b", "b issued a lease for a (%d s), and a's holder installed it" % left, envelope["lease"])
    kinds = [(e["event"], e["outcome"], e["subject"]) for e in events["b"][-2:]]
    ok(kinds == [("sync-lease-nonce", "ALLOW", "a"), ("sync-lease", "ALLOW", "a")], "b's trail: the nonce and the lease, both for a", kinds)

    # ---- 4 ------------------------------------------------------------------------------------------------
    header("4  c is revoked: convergence, and the revoked node's two refusals")
    revoked = fixture.revoke(fixture.m1, node="c")["manifest"]
    fixture.sequence += 1
    fixture.held.envelope = hbt.beat(revoked, fixture.sequence, issued=fixture.now)
    now_at, fresh = clients["b"].pull("seed")
    ok(now_at["epoch"] == 2 and fresh == hb.MAX_LIFETIME, "b took epoch 2 and its heartbeat (in process, from the seed chain)", (now_at, fresh))
    now_at, fresh = clients["a"].pull("b")
    ok(now_at["epoch"] == 2 and fresh == hb.MAX_LIFETIME, "a pulled both from b: the revocation travelled peer to peer", (now_at, fresh))
    ok(public["c"] in peers_of("b"), "(b's interface still lists c: it has not been reconciled yet)")
    said = refusal(lambda: clients["c"].pull("b"))
    ok(said == "the source refused: refused", "c asks b through its tunnel, which is still up: refused, and told nothing more", said)
    last = events["b"][-1]
    ok((last["subject"], last["outcome"], last["epoch"]) == ("c", "DENY", 2) and "c is REVOKED_STOLEN under epoch 2" in last["reason"],
       "b recorded the denial against node c, by name, under the current manifest", last)
    reconcile("b")
    reconcile("a")
    ok(public["c"] not in peers_of("b") and public["c"] not in peers_of("a"),
       "after the root side ran under epoch 2, nobody lists c as a peer")
    before = len(events["b"])
    slow = sync.Client("c", stores["c"], freshness["c"], {"b": transport("c", "b", timeout=3)}, events["c"].append)
    said = refusal(lambda: slow.pull("b"))
    ok("b did not answer" in said and len(events["b"]) == before, "c now gets no answer at all: its packets do not reach b's listener", said)

    # ---- 5 ------------------------------------------------------------------------------------------------
    header("5  an address that is not its key's does not get through WireGuard")
    # c's address (no longer a peer of anyone's) on a's interface: a's packets to b leave from it, with a's key
    in_ns("a")(["ip", "-6", "address", "add", address["c"] + "/128", "dev", "wg-svc", "nodad"], capture_output=True, check=True)
    before = len(events["b"])
    forged = sync.Client("a", stores["a"], freshness["a"], {"b": transport("a", "b", source=address["c"], timeout=3)}, events["a"].append)
    said = refusal(lambda: forged.pull("b"))
    ok("did not answer" in said and len(events["b"]) == before,
       "a sends from c's tunnel address with its own key: b's WireGuard drops it, and the listener never sees a request", said)
    in_ns("a")(["ip", "-6", "address", "del", address["c"] + "/128", "dev", "wg-svc"], capture_output=True, check=True)
    now_at, _ = clients["a"].pull("b")
    ok(now_at["epoch"] == 2 and events["b"][-1]["subject"] == "a", "from its own address, a is answered and recorded as a")

    # ---- 6 ------------------------------------------------------------------------------------------------
    header("6  a peer list that is not the manifest's is detected by the read-back, and repaired")
    text = wgsvc.conf(stores["b"].load(), "b", {"a": UNDERLAY["a"]})
    wgsvc.verify(text, run=in_ns("b"))
    in_ns("b")(["wg", "set", "wg-svc", "peer", wgsvc.wg_key(public["a"]), "allowed-ips", str(wgsvc.PREFIX)], capture_output=True, check=True)
    said = refusal(lambda: wgsvc.verify(text, run=in_ns("b")))
    ok("the tunnel's peers are not the manifest's" in said and str(wgsvc.PREFIX) in said,
       "a's peer on b is widened to the whole prefix by hand: the read-back names the range", said)
    reconcile("b")
    ok(refusal(lambda: wgsvc.verify(text, run=in_ns("b"))) == "", "the root side's next run restores exactly one /128 per key")
    in_ns("b")(["wg", "set", "wg-svc", "peer", wgsvc.wg_key(public["c"]), "allowed-ips", address["c"] + "/128"], capture_output=True, check=True)
    said = refusal(lambda: wgsvc.verify(text, run=in_ns("b")))
    ok(wgsvc.wg_key(public["c"]) in said, "the revoked node added back by hand is named as a peer that differs", said)
    reconcile("b")
    ok(public["c"] not in peers_of("b"), "and removed again")

    # ---- 7 ------------------------------------------------------------------------------------------------
    header("7  a partitioned node catches up in rounds, and authorizes nothing until a heartbeat for the tip arrives")
    sh("ip", "-n", ns("a"), "link", "set", "eth0", "down")
    tip = fixture.advance(70)                                             # 70 more manifests while a is cut off
    fixture.held.envelope = None                                          # no heartbeat for the tip has been signed yet
    now_at, fresh = clients["b"].pull("seed")
    ok(now_at["epoch"] == 72 and fresh is None, "b caught up to epoch 72, in rounds, with no heartbeat for it yet", (now_at, fresh))
    quick = sync.Client("a", stores["a"], freshness["a"], {"b": transport("a", "b", timeout=3)}, events["a"].append)
    said = refusal(lambda: quick.pull("b"))
    ok("b did not answer" in said, "a is cut off: it reaches nobody", said)
    ok(freshness["a"].check(stores["a"].load()) > 0, "(and still holds a live heartbeat for epoch 2: the exposure the heartbeat bound limits)")
    sh("ip", "-n", ns("a"), "link", "set", "eth0", "up")
    before = len([e for e in events["a"] if e["event"] == "sync-apply" and e["outcome"] == "ALLOW"])
    now_at, fresh = clients["a"].pull("b")
    rounds = len([e for e in events["a"] if e["event"] == "sync-apply" and e["outcome"] == "ALLOW"]) - before
    ok(now_at["epoch"] == 72 and fresh is None and rounds == 3, "back on the network, a caught up to epoch 72 from b in %d rounds of at most 64" % rounds, (now_at, fresh, rounds))
    said = refusal(lambda: freshness["a"].check(stores["a"].load()))
    ok("the heartbeat is for epoch 2" in said, "a holds the tip and no heartbeat for it: it authorizes nobody", said)
    fixture.sequence += 1
    fixture.held.envelope = hbt.beat(tip, fixture.sequence, issued=fixture.now)
    clients["b"].pull("seed")
    now_at, fresh = clients["a"].pull("b")
    ok(fresh == hb.MAX_LIFETIME and freshness["a"].check(stores["a"].load()) == hb.MAX_LIFETIME,
       "a heartbeat for the tip is signed; it reaches b, then a from b: a may authorize again", (now_at, fresh))

    print("\nregalia-sync-netns: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
