#!/usr/bin/env python3
"""etcd's configuration on a KMS server, rendered from the root-signed membership manifest (ADR-0002 D32, #432;
deploy/baremetal/ETCD.md has the unit, regalia-etcd.service, which reads CONFIG_PATH).

WHO IS A MEMBER. The manifest says, and nothing else: the nodes whose state keeps them in the cluster (MEMBER_STATES:
ACTIVE, MAINTENANCE, DRAINING). A quarantined, retired or revoked node is in no initial cluster and in no trusted bundle.

THE TLS TRUST HAS NO CA (regalia-kms-ed on #484). Each member makes its etcd peer key at enrolment (the key goes into a
systemd credential, never a file in clear) and a self-signed certificate, and binds the certificate ONCE with the
signing key the manifest pins for it (v4 `signing_key`, P-256, on its TPM):

    binding = {"schema": "regalia.etcd-cert/v1", "node_id", "cert_sha256", "issued_at"}
    envelope = {"binding": binding, "sig": "<128 hex: r || s, low S>"}     signed over DOMAIN + canonical(binding)

A renderer takes, for each member, the latest binding that verifies under the CURRENT manifest's signing_key for that
node, and never goes back to an older one than it has rendered before (`seen`). A node re-enrolled on a new TPM has a
new signing_key in the manifest, so its old bindings stop verifying by themselves. The trusted-peer bundle is exactly
the bound certificates of the members: a node the root did not add cannot be bound, and one it quarantines drops out
at the next render. Equivalent to pinning each certificate in the manifest, with no schema change (#432, 6002085936).

THE TIMINGS come from the measured round trip (D32 item 5): the heartbeat at the worst p99 round trip between any two
servers (at least etcd's 100 ms), the election timeout ten times that. A round trip above MAX_RTT_MS is a
commissioning failure, refused here, not tuned around.

The configuration is written as JSON, which etcd's YAML reader takes, so no value can be mis-quoted.
"""
import hashlib
import json
import math
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from deploy.baremetal import heartbeat, membership, wgsvc

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.etcd-cert/v1"
DOMAIN = b"regalia-etcd-cert/v1\0"
MEMBER_STATES = ("ACTIVE", "MAINTENANCE", "DRAINING")
CONFIG_PATH = "/etc/regalia/etcd.conf.yml"
CERT_DIR = "/etc/regalia/etcd"                     # public: this member's certificates and the rendered bundles
CREDENTIALS = "/run/credentials/regalia-etcd.service"      # the keys, LoadCredentialEncrypted= (regalia-etcd.service)
DATA_DIR = "/var/lib/regalia-etcd"
PEER_PORT = 2380
CLIENT_URL = "unix://client.sock:0"                # in the unit's WorkingDirectory, /run/regalia-etcd (ETCD.md)
MIN_HEARTBEAT_MS = 100                             # etcd's default: never below it
MAX_RTT_MS = 500                                   # above: a commissioning failure (election timeout would pass 5 s)
MAX_ELECTION_MS = 50000                            # etcd refuses more
MAX_PEM_BYTES = 16 * 1024


def cert_der(pem):
    """The DER of the one certificate in `pem` (text), or Refused."""
    require(isinstance(pem, str) and len(pem) <= MAX_PEM_BYTES and pem.count("-----BEGIN CERTIFICATE-----") == 1,
            "an etcd certificate is one PEM certificate of at most %d bytes" % MAX_PEM_BYTES)
    try:
        return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    except ValueError:
        raise Refused("the etcd certificate is not a certificate") from None


def binding(node_id, pem, issued_at):
    return {"schema": SCHEMA, "node_id": node_id, "cert_sha256": hashlib.sha256(cert_der(pem)).hexdigest(), "issued_at": issued_at}


def message(body):
    membership.exact(body, ("schema", "node_id", "cert_sha256", "issued_at"), "the etcd certificate binding")
    require(body["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    membership.hex_field(body["cert_sha256"], 64, "cert_sha256")
    heartbeat.parse_time(body["issued_at"], "issued_at")
    return DOMAIN + membership.canonical(body)


def sign(body, signer):
    """`signer(message)` returns r || s hex (signkey.sign with the node's TPM-held key)."""
    return {"binding": body, "sig": signer(message(body))}


def verify(manifest, envelope, pem):
    """The binding of `pem` if `envelope` binds it for its node under `manifest`'s signing_key for that node, else Refused."""
    membership.exact(envelope, ("binding", "sig"), "the etcd certificate binding envelope")
    body = envelope["binding"]
    raw = message(body)
    nodes = membership.validate(manifest)
    node = nodes.get(body["node_id"])
    require(node is not None and "signing_key" in node, "%s has no signing key in the manifest at epoch %d" % (body["node_id"], manifest["epoch"]))
    require(body["cert_sha256"] == hashlib.sha256(cert_der(pem)).hexdigest(), "the binding is for another certificate than %s's" % body["node_id"])
    alg, key = membership.typed_key(node["signing_key"], "%s's signing_key" % body["node_id"], membership.SIGNING_KEY_ALGS)
    membership.verify_revocation(alg, key, raw, envelope["sig"], "%s's etcd certificate binding" % body["node_id"])
    return body


def members(manifest):
    """{node_id: node} of the manifest's etcd members, by its order."""
    return {n["node_id"]: n for n in manifest["nodes"] if n["state"] in MEMBER_STATES}


def choose(manifest, offered, seen=None):
    """{node_id: pem} for every member: the latest binding of each that verifies. `offered`: {node_id: [{"cert": pem,
    "binding": envelope}, ...]}; `seen`: {node_id: issued_at} rendered before, never gone back on. Refused if a member
    has none, or only bindings older than what was seen: etcd is not rendered with a member missing or rolled back."""
    seen = seen or {}
    out = {}
    for node_id in members(manifest):
        good = []
        for item in offered.get(node_id, []):
            try:
                body = verify(manifest, item["binding"], item["cert"])
            except (Refused, KeyError, TypeError):
                continue
            if body["node_id"] == node_id:
                good.append((heartbeat.parse_time(body["issued_at"], "issued_at"), body["issued_at"], item["cert"]))
        require(good, "no certificate of %s is bound by its signing key under epoch %d: etcd is not rendered without it"
                % (node_id, manifest["epoch"]))
        at, stamp, pem = max(good)
        if node_id in seen:
            require(at >= heartbeat.parse_time(seen[node_id], "seen"), "the newest binding of %s (%s) is older than the one rendered "
                    "before (%s): refused, never rolled back" % (node_id, stamp, seen[node_id]))
        out[node_id] = pem
    return out


def timings(rtt_p99_ms):
    """(heartbeat-interval, election-timeout) in ms from the worst measured p99 round trip between two servers."""
    require(isinstance(rtt_p99_ms, (int, float)) and not isinstance(rtt_p99_ms, bool) and 0 < rtt_p99_ms <= MAX_RTT_MS,
            "the measured p99 round trip must be over 0 and at most %d ms (a commissioning failure otherwise, D32)" % MAX_RTT_MS)
    beat = max(MIN_HEARTBEAT_MS, int(math.ceil(rtt_p99_ms / 10.0)) * 10)
    election = 10 * beat
    require(election <= MAX_ELECTION_MS, "an election timeout of %d ms is more than etcd takes" % election)
    return beat, election


def peer_url(node):
    return "https://[%s]:%d" % (wgsvc.address(node["wg_service_pub"]), PEER_PORT)


def render(manifest, me, genesis_digest, certs, rtt_p99_ms, state="new"):
    """(etcd.conf.yml text, the trusted-peer bundle's text) for member `me`. `certs`: choose()'s {node_id: pem};
    `genesis_digest`: the epoch-1 manifest's digest (the cluster token); `state`: "new" when the cluster is formed,
    "existing" when this member joins one that runs."""
    nodes = members(manifest)
    require(me in nodes, "%s is not an etcd member under epoch %d (%s)" % (me, manifest["epoch"],
                                                                       {n["node_id"]: n["state"] for n in manifest["nodes"]}.get(me, "not in the manifest")))
    require(set(certs) == set(nodes), "the certificates are for %s; the members are %s" % (sorted(certs), sorted(nodes)))
    membership.hex_field(genesis_digest, 64, "genesis_digest")
    require(state in ("new", "existing"), "initial-cluster-state is new or existing")
    beat, election = timings(rtt_p99_ms)
    for pem in certs.values():
        cert_der(pem)
    tls = {"cert-file": "%s/%%s.crt" % CERT_DIR, "key-file": "%s/etcd-%%s.key" % CREDENTIALS}
    config = {
        "name": me,
        "data-dir": DATA_DIR,
        "listen-peer-urls": peer_url(nodes[me]),
        "initial-advertise-peer-urls": peer_url(nodes[me]),
        "listen-client-urls": CLIENT_URL,
        "advertise-client-urls": CLIENT_URL,
        "initial-cluster": ",".join("%s=%s" % (n, peer_url(nodes[n])) for n in nodes),
        "initial-cluster-state": state,
        "initial-cluster-token": "regalia-" + genesis_digest[:32],
        "heartbeat-interval": beat,
        "election-timeout": election,
        "strict-reconfig-check": True,
        "enable-pprof": False,
        "tls-min-version": "TLS1.3",
        "client-transport-security": {"cert-file": tls["cert-file"] % "server", "key-file": tls["key-file"] % "server",
                                      "client-cert-auth": True, "trusted-ca-file": "%s/clients.pem" % CERT_DIR, "auto-tls": False},
        "peer-transport-security": {"cert-file": tls["cert-file"] % "peer", "key-file": tls["key-file"] % "peer",
                                    "client-cert-auth": True, "trusted-ca-file": "%s/peers.pem" % CERT_DIR, "auto-tls": False},
        "logger": "zap",
        "log-outputs": ["stderr"],
    }
    bundle = "".join(certs[n].strip() + "\n" for n in nodes)
    return json.dumps(config, indent=1, sort_keys=True) + "\n", bundle


def check(text):
    """The safety settings of a rendered configuration, or Refused naming the first that is not as it must be: no
    client on a TCP port, peers only on the mesh, both sides authenticated by certificate, no automatic TLS."""
    config = json.loads(text)
    require(config["listen-client-urls"] == CLIENT_URL and config["advertise-client-urls"] == CLIENT_URL,
            "clients connect only over the unix socket")
    for key in ("listen-peer-urls", "initial-advertise-peer-urls"):
        for url in config[key].split(","):
            found = re.fullmatch(r"https://\[([0-9a-f:]+)\]:%d" % PEER_PORT, url)
            require(found is not None and found.group(1).startswith("fd72:6567:6c61:"), "%s %s is not on the service mesh over TLS" % (key, url))
    for side in ("client-transport-security", "peer-transport-security"):
        require(config[side]["client-cert-auth"] is True and config[side]["auto-tls"] is False, "%s must require certificates, no auto TLS" % side)
        require(config[side]["key-file"].startswith(CREDENTIALS + "/"), "%s's key must come from the unit's credentials" % side)
    require(config["tls-min-version"] == "TLS1.3" and config["enable-pprof"] is False and config["strict-reconfig-check"] is True,
            "TLS 1.3, no pprof, strict reconfiguration checks")
    require(config["election-timeout"] >= 10 * config["heartbeat-interval"] >= 10 * MIN_HEARTBEAT_MS, "the election timeout is ten heartbeats")
    return config
