#!/usr/bin/env python3
"""Writes tests/vectors/bootcreds-v1.json: regalia.site documents and the boot credentials
deploy/baremetal/bootcreds.render gives for them under many manifests, byte for byte, so the initrd's Go
renderer (cmd/regalia-unlock/bootcfg) is held to the very same output: which peers, in which order, their
WireGuard keys, the ruleset, boot.env, and every refusal.

    python3 -Es tests/vectors/make-bootcreds-v1.py > tests/vectors/bootcreds-v1.json

Everything here is fixed (no key is generated): the vector is reproducible. Manifests are not signed:
render() takes a manifest the chain verification already accepted; the Go side runs membership.Validate.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import bootcreds, membership, sitecfg  # noqa: E402

DEVICE = "/dev/disk/by-partlabel/regalia-root"
WHERE = {"a": ("192.0.2.10", "10.89.0.1"), "b": ("198.51.100.7", "10.89.0.2"), "c": ("198.51.100.9", "10.89.0.3"),
         "d": ("203.0.113.20", "10.89.0.4")}


def site(node, nodes=("a", "b", "c"), reverse=False, **mesh):
    doc = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "deploy", "baremetal", "site.example.json")))
    doc["host_ipv4"] = WHERE[node][0]
    peers = [{"node_id": n, "underlay": WHERE[n][0], "address": WHERE[n][1]} for n in nodes if n != node]
    doc["boot_mesh"] = dict({"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": WHERE[node][1], "unlock_port": 7443,
                             "nic_mac": "52:54:00:ab:cd:%02x" % (ord(node) - 96), "prefix": 32, "gateway": None,
                             "peers": peers[::-1] if reverse else peers}, **mesh)
    return sitecfg.validate(doc)


def node(i, nid, state):
    return {"node_id": nid, "state": state, "ek_name": "000b" + ("%02x" % (0x10 + i)) * 32, "ak_name": "000b" + ("%02x" % (0x40 + i)) * 32,
            # service keys of 0xfb.. bytes: their base64 holds "+" and "/", so the standard alphabet is what is checked
            "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xfb + i)) * 32, "hsm_serials": ["DENK04041%02d" % i]}


def manifest(epoch=1, v2=False, order=("a", "b", "c"), **states):
    nodes = [node(i, n, states.get(n, "ACTIVE")) for i, n in enumerate(order)]
    man = {"schema": membership.SCHEMA, "epoch": epoch, "prev_digest": "" if epoch == 1 else "ab" * 32, "policy_version": "p1",
           "issued_at": "2026-10-03T12:00:00Z", "revocation_keys": ["5e" * 32], "nodes": nodes}
    if v2:
        man.update(schema=membership.SCHEMA_V2, heartbeat_max_lifetime_s=86400)
        for i, n in enumerate(man["nodes"]):
            n["ssh_host_pub"] = ("%02x" % (0xd0 + i)) * 32
    membership.validate(man)
    return man


SITES = {
    "a": site("a"), "b": site("b"), "c": site("c"),
    "a, peers listed in reverse": site("a", reverse=True),
    "a, a /24 with a gateway": site("a", prefix=24, gateway="192.0.2.1"),
    "a, a /31 gateway": site("a", prefix=31, gateway="192.0.2.11"),
    "a, other ports": site("a", listen_port=51999, unlock_port=7999),
    "a, with d": site("a", nodes=("a", "b", "c", "d")),
    "a, b only": site("a", nodes=("a", "b")),
}
MANIFESTS = {
    "all active": manifest(),
    "c quarantined": manifest(c="QUARANTINED"), "c in maintenance": manifest(c="MAINTENANCE"), "c draining": manifest(c="DRAINING"),
    "c retired": manifest(c="RETIRED"), "c revoked as stolen": manifest(c="REVOKED_STOLEN"),
    "b and c quarantined": manifest(b="QUARANTINED", c="QUARANTINED"),
    "a in maintenance": manifest(a="MAINTENANCE"), "a quarantined": manifest(a="QUARANTINED"),
    "nodes listed c, b, a": manifest(order=("c", "b", "a")),
    "v2": manifest(v2=True), "a large epoch": manifest(epoch=123456789012),
    "with d active": manifest(order=("a", "b", "c", "d")), "with d quarantined": manifest(order=("a", "b", "c", "d"), d="QUARANTINED"),
    "without a": manifest(order=("b", "c", "d")),
    "b's EK Name not a SHA-256 Name": dict(manifest(), nodes=[dict(n, ek_name="000c" + n["ek_name"][4:]) if n["node_id"] == "b" else n
                                                              for n in manifest()["nodes"]]),
}

renders = []
for site_name, cfg in SITES.items():
    raw = bootcreds.site_document(cfg, DEVICE)
    parsed, device = bootcreds.read_site(raw)
    for man_name, man in MANIFESTS.items():
        try:
            files = bootcreds.render(man, parsed, device)
            outcome = {"files": {name: body.decode("ascii") for name, body in sorted(files.items())}}
            assert files == bootcreds.render(man, cfg, DEVICE)            # the document carries all render() needs
        except membership.Refused as refusal:
            outcome = {"refused": str(refusal)}
        renders.append({"site": site_name, "manifest": man_name, **outcome})

# regalia.site documents the initrd must refuse, each one change from a valid one
good = json.loads(bootcreds.site_document(SITES["a"], DEVICE))


def changed(fn):
    doc = copy.deepcopy(good)
    fn(doc)
    return membership.canonical(doc)


raw_sites = {
    "valid": membership.canonical(good),
    "not canonical (spaces)": json.dumps(good, sort_keys=True).encode(),
    "not canonical (a newline)": membership.canonical(good) + b"\n",
    "another schema": changed(lambda d: d.update(schema="regalia.boot-site/v2")),
    "an extra field": changed(lambda d: d.update(extra=1)),
    "no device": changed(lambda d: d.pop("device")),
    "a device with a space": changed(lambda d: d.update(device="/dev/disk/by-partlabel/regalia root")),
    "host_ipv4 a network": changed(lambda d: d.update(host_ipv4="192.0.2.0/24")),
    "host_ipv4 loopback": changed(lambda d: d.update(host_ipv4="127.0.0.1")),
    "boot_mesh null": changed(lambda d: d.update(boot_mesh=None)),
    "an upper-case MAC": changed(lambda d: d["boot_mesh"].update(nic_mac="52:54:00:AB:CD:01")),
    "a multicast MAC": changed(lambda d: d["boot_mesh"].update(nic_mac="01:00:5e:00:00:01")),
    "prefix 0": changed(lambda d: d["boot_mesh"].update(prefix=0)),
    "prefix true": changed(lambda d: d["boot_mesh"].update(prefix=True)),
    "a gateway off the link": changed(lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.3.1")),
    "the host as gateway": changed(lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.2.10")),
    "the broadcast as gateway": changed(lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.2.255")),
    "no peers": changed(lambda d: d["boot_mesh"].update(peers=[])),
    "nine peers": changed(lambda d: d["boot_mesh"].update(peers=[{"node_id": "p%d" % i, "underlay": "198.18.0.%d" % (i + 1),
                                                                 "address": "10.90.0.%d" % (i + 1)} for i in range(9)])),
    "a peer that is the node": changed(lambda d: d["boot_mesh"]["peers"][0].update(node_id="a")),
    "two peers at one address": changed(lambda d: d["boot_mesh"]["peers"][1].update(address=d["boot_mesh"]["peers"][0]["address"])),
    "a peer at the host's address": changed(lambda d: d["boot_mesh"]["peers"][0].update(underlay="192.0.2.10")),
    "the tunnel address is the host's": changed(lambda d: d["boot_mesh"].update(address="192.0.2.10")),
    "the initrd's interface": changed(lambda d: d["boot_mesh"].update(interface="wg-boot")),
    "port 0": changed(lambda d: d["boot_mesh"].update(listen_port=0)),
    "a node ID in upper case": changed(lambda d: d["boot_mesh"].update(node_id="A")),
    "a peer with an extra field": changed(lambda d: d["boot_mesh"]["peers"][0].update(key="x")),
    "a float port": json.dumps(good, sort_keys=True, separators=(",", ":")).replace('"listen_port":51820', '"listen_port":51820.0').encode(),
    "a duplicate field": membership.canonical(good).replace(b'{"boot_mesh"', b'{"device":"x","boot_mesh"', 1),
}
documents = []
for name, raw in raw_sites.items():
    try:
        bootcreds.read_site(raw)
        outcome = {"taken": True}
    except membership.Refused as refusal:
        outcome = {"taken": False, "refused": str(refusal)}
    assert outcome["taken"] == (name == "valid"), (name, outcome)
    documents.append({"name": name, "hex": raw.hex(), **outcome})

print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "device": DEVICE,
                  "sites": {name: bootcreds.site_document(cfg, DEVICE).decode("ascii") for name, cfg in SITES.items()},
                  "manifests": MANIFESTS, "renders": renders, "documents": documents}, indent=1, sort_keys=True))
