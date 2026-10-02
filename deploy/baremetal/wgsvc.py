#!/usr/bin/env python3
"""The service tunnel, `wg-svc`: the WireGuard interface regalia-sync talks over (#80, step 2).

WHO IS A PEER, AND AT WHICH ADDRESS, COMES FROM THE MANIFEST ALONE.

  * A node's tunnel address is DERIVED FROM ITS WG-SERVICE PUBLIC KEY: the fixed prefix fd72:6567:6c61::/48
    followed by the first 80 bits of SHA-256 of the key (address()). The manifest needs no address field,
    two nodes cannot disagree about who has which address, and an address says which key it belongs to.
  * conf() renders the interface from the manifest this node holds: one peer for every other node that is
    not in a terminal state, by its `wg_service_pub`, allowed EXACTLY its derived address (/128). A node
    that is itself retired or revoked in its own manifest knows nobody. Where the others ARE (their
    underlay addresses) is local configuration and decides nothing: WireGuard authenticates by key.

TWO PROCESSES, AND WHY THE ONE THAT READS THE NETWORK HOLDS NO CAPABILITY.

  * reconcile() is the root side (the oneshot `regalia-wg-apply`): it brings the interface up, applies
    conf() of the CURRENT manifest with `wg syncconf` (on standard input, with the private key:
    bootnet.with_key; a syncconf without the key would unset it), and then READS THE RESULT BACK
    (`wg show <interface> allowed-ips`) and requires it to be exactly what was rendered: the same keys,
    each allowed its one derived /128, nothing else. If it is not, the interface is taken down and the
    run fails: a peer list that is not the manifest's is not one to answer on.
  * key_at() is regalia-sync's side, and needs nothing from the kernel: the caller of a connection from
    address X is the node of the CURRENT manifest whose key derives X.

THE ARGUMENT THAT MAKES key_at() SOUND. WireGuard's cryptokey routing delivers a packet with source
address X on the interface only if it decrypted under the key of the peer whose allowed addresses contain
X. reconcile() makes that exactly one /128 per key of the manifest, and that /128 is a hash of the key. So
a connection from X came from the holder of the one key that derives X. regalia-sync parses untrusted
input, so it is the process that must not be able to reconfigure the host's network; what it trusts is
that the interface was configured by reconcile(), which checks its own result.
A STALE INTERFACE DOES NOT HELP A REVOKED NODE: key_at() and sync.pinned() look in the manifest held NOW,
so a node that is revoked there is refused although its peer entry has not been removed yet.

THE REVOCATION AUTHORITY is one more peer, configured locally by its key and underlay (it is not a node of
the manifest). Nodes ask it; it never asks them, and nothing it sends is trusted for coming from it.

ONE MORE CONDITION, ON THE HOST: a packet with a tunnel source address must not reach the sync port by any
other way than the tunnel. Linux takes packets for a local address on any interface, and IPv6 has no
reverse-path filter, so a host on the same link could send one in plaintext. The host firewall closes
that (firewall.py, #189): IPv6 is accepted only on the service interface; on every other it is dropped.

`wg` and `ip` are found through PATH; the units pin it.

NOT HERE: the units, the trigger that re-runs reconcile() after an accepted manifest, and the site
configuration that names the interface (step 3).
"""
import base64
import binascii
import contextlib
import hashlib
import ipaddress
import re
import subprocess

from deploy.baremetal import bootnet, membership

Refused, require = membership.Refused, membership.require

INTERFACE = "wg-svc"
LISTEN_PORT = 51821              # UDP; 51820 is wg-unlock's (#66)
PREFIX = ipaddress.IPv6Network("fd72:6567:6c61::/48")
AUTHORITY_KEYS = ("key", "underlay", "port")
AUTHORITY = "@authority"         # convergence.AUTHORITY: the one name here that is not a node ID


def address(key):
    """The tunnel address of the node holding the WireGuard public key `key` (64 hex), as text."""
    membership.hex_field(key, 64, "a WireGuard public key")
    return str(ipaddress.IPv6Address(PREFIX.network_address.packed[:6] + hashlib.sha256(bytes.fromhex(key)).digest()[:10]))


def wg_key(key):
    """A manifest's key (64 hex) as WireGuard writes it (base64)."""
    membership.hex_field(key, 64, "a WireGuard public key")
    return base64.b64encode(bytes.fromhex(key)).decode()


def hex_key(text):
    """A key as WireGuard writes it (base64), as the manifest writes it (64 hex)."""
    try:
        raw = base64.b64decode(text, validate=True) if isinstance(text, str) else b""
    except (binascii.Error, ValueError):
        raw = b""
    require(len(raw) == 32, "not a WireGuard public key")
    return raw.hex()


def _underlay(value, label):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, TypeError):
        raise Refused("%s is not an IPv4 address" % label)


def _port(value, label):
    require(isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535, "%s must be a port number 1-65535" % label)
    return value


def conf(manifest, node_id, underlays, authority=None, listen_port=LISTEN_PORT, own_key=None):
    """The `wg setconf` text for `node_id`'s service interface under `manifest`, without the private key.
    `underlays` maps a node ID to its IPv4 underlay address (a peer with none is still a peer: it can call,
    and is answered where it called from). `authority` is None or {"key", "underlay", "port"}."""
    entries = {node["node_id"]: node for node in manifest["nodes"]}
    require(node_id in entries or node_id == AUTHORITY, "%s is not in the manifest" % (node_id,))
    require(isinstance(underlays, dict), "underlays maps node IDs to addresses")
    text = "[Interface]\nListenPort = %d\n" % _port(listen_port, "listen_port")
    if node_id == AUTHORITY:        # the authority's own interface: every node that may still be talked to
        require(authority is None, "the authority is not its own peer")
        seen = set()
    elif entries[node_id]["state"] in membership.TERMINAL:
        return text
    else:
        seen = {entries[node_id]["wg_service_pub"]}
    for other in manifest["nodes"]:
        if other["node_id"] == node_id or other["state"] in membership.TERMINAL:
            continue
        key = other["wg_service_pub"]
        text += "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/128\n" % (other["node_id"], wg_key(key), address(key))
        if other["node_id"] in underlays:
            text += "Endpoint = %s:%d\n" % (_underlay(underlays[other["node_id"]], "the underlay of %s" % other["node_id"]), listen_port)
        seen.add(key)
    if authority is not None:
        membership.exact(authority, AUTHORITY_KEYS, "authority")
        key = authority["key"]
        membership.hex_field(key, 64, "authority.key")
        require(key not in seen and key not in {n["wg_service_pub"] for n in manifest["nodes"]}, "the authority's key is a node's key")
        text += "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/128\nEndpoint = %s:%d\n" % (
            "authority", wg_key(key), address(key), _underlay(authority["underlay"], "authority.underlay"), _port(authority["port"], "authority.port"))
    # ONE ADDRESS, ONE KEY. Two keys whose hashes share 80 bits would share an address, and the caller of
    # a connection from it could not be told apart. Finding such a pair takes about 2^40 work, but only a
    # key the root signer pins is ever a peer, so it would take the signer's help; still, it is refused
    # here rather than assumed: every node of the manifest (this one and terminal ones included) and the
    # authority must derive addresses of their own.
    if own_key is not None:      # the authority's own interface: its key is no node's, and derives an address of its own
        membership.hex_field(own_key, 64, "the authority's key")
        require(own_key not in {n["wg_service_pub"] for n in manifest["nodes"]}, "the authority's key is a node's key")
    keys = [n["wg_service_pub"] for n in manifest["nodes"]] + [k for k in ((authority or {}).get("key"), own_key) if k is not None]
    derived = [address(k) for k in keys]
    require(len(set(derived)) == len(derived), "two keys derive the same tunnel address: they could not be told apart")
    return text


def _interface(name):
    require(isinstance(name, str) and re.fullmatch(r"wg-[a-z0-9-]{1,12}", name) is not None and name != bootnet.BOOT_INTERFACE,
            "the interface must be a WireGuard interface of its own, named wg-...")
    return name


def _run(run, argv, what, **kw):
    try:
        done = run(argv, capture_output=True, timeout=10, **kw)
    except (OSError, subprocess.SubprocessError) as failure:
        raise Refused("%s (%s)" % (what, type(failure).__name__)) from None
    require(done.returncode == 0, what)
    return done.stdout.decode(errors="replace")


def apply(text, private_key, interface=INTERFACE, run=subprocess.run):
    """Make the interface's peers exactly those of `text` (conf()), keeping its key."""
    _run(run, ["wg", "syncconf", _interface(interface), "/dev/stdin"], "the tunnel's configuration could not be applied",
         input=bootnet.with_key(text, private_key).encode())


def prepare(own_key, interface=INTERFACE, run=subprocess.run):
    """Create the interface if it is not there and give it this node's derived address, LEAVING IT DOWN:
    it carries nothing until its peers have been applied and read back (reconcile). Returns the address.
    THE MTU IS LEFT AT WIREGUARD'S DEFAULT, THE SAME ON EVERY HOST, and must stay so: the host firewall drops
    every ICMPv6 inside the tunnel, the "packet too big" that path-MTU discovery needs included, so a site
    with a smaller MTU on its interface would silently lose the others' large segments."""
    name, own = _interface(interface), address(own_key)
    try:
        present = run(["ip", "link", "show", "dev", name], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        present = False
    if not present:
        _run(run, ["ip", "link", "add", "dev", name, "type", "wireguard"], "the tunnel interface could not be created")
    _run(run, ["ip", "-6", "address", "replace", own + "/128", "dev", name, "nodad"], "the tunnel address could not be set")
    return own


def up(interface=INTERFACE, run=subprocess.run):
    """Bring the interface up, with the route to the tunnel prefix: only once its peers are verified."""
    name = _interface(interface)
    _run(run, ["ip", "link", "set", "dev", name, "up"], "the tunnel interface could not be brought up")
    _run(run, ["ip", "-6", "route", "replace", str(PREFIX), "dev", name], "the route to the tunnel prefix could not be set")


def down(interface=INTERFACE, run=subprocess.run):
    """Take the interface out of service, and make sure it is: down, or if that fails deleted. Raises
    Refused if neither could be done, naming it, so that nobody takes the interface for safe."""
    name = _interface(interface)
    for argv in (["ip", "link", "set", "dev", name, "down"], ["ip", "link", "del", "dev", name]):
        try:
            if run(argv, capture_output=True, timeout=10).returncode == 0:
                return
        except (OSError, subprocess.SubprocessError):
            pass
    raise Refused("the tunnel interface %s could not be taken down or deleted: it may still carry its old peers" % name)


def owners(text):
    """`wg show <interface> allowed-ips`, parsed: {allowed network: [keys (hex) that list it]}. A line that
    does not parse is refused: what is not understood is not guessed at."""
    found = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        require(len(fields) == 2, "the tunnel's peer list is not understood")
        key = hex_key(fields[0])
        for item in fields[1].split():
            if item == "(none)":
                continue
            try:
                network = ipaddress.ip_network(item, strict=True)
            except ValueError:
                raise Refused("the tunnel's peer list is not understood")
            found.setdefault(network, []).append(key)
    return found


def expected(text):
    """What `wg show <interface> allowed-ips` must say after conf() `text` is applied: {network: [key]}."""
    found, key = {}, None
    for line in text.splitlines():
        if line.startswith("PublicKey = "):
            key = hex_key(line[len("PublicKey = "):])
        elif line.startswith("AllowedIPs = "):
            found.setdefault(ipaddress.ip_network(line[len("AllowedIPs = "):]), []).append(key)
    return found


def verify(text, interface=INTERFACE, run=subprocess.run):
    """Require the interface's peers, as the kernel has them now, to be exactly those of conf() `text`: the
    same keys, each allowed its one /128, no other peer and no other range. Refused names what differs."""
    name = _interface(interface)
    shown = _run(run, ["wg", "show", name, "allowed-ips"], "the tunnel's peers cannot be read back")
    peers = {hex_key(line.split("\t")[0]) for line in shown.splitlines() if line.strip() and "\t" in line}
    have, want = owners(shown), expected(text)
    wanted_keys = {keys[0] for keys in want.values()}
    wrong = sorted(str(net) for net in set(have) ^ set(want)) + sorted(str(net) for net in set(have) & set(want) if have[net] != want[net])
    strangers = sorted(wg_key(key) for key in peers ^ wanted_keys)
    require(not wrong and not strangers, "the tunnel's peers are not the manifest's: allowed addresses that differ %s, "
            "peers that differ %s" % (wrong, strangers))


def reconcile(manifest, node_id, underlays, private_key, authority=None, listen_port=LISTEN_PORT, interface=INTERFACE, run=subprocess.run,
              own_key=None):
    """The root side: make the interface what `manifest` says, and prove it. The interface is brought UP
    only after its peers have been applied and read back. On ANY failure once it exists it is taken DOWN
    (or deleted, if it will not go down) before the refusal is raised. `own_key` is this host's public key
    when it is the authority (node_id AUTHORITY); a node's is the manifest's."""
    membership.validate(manifest)
    entries = {node["node_id"]: node for node in manifest["nodes"]}
    text = conf(manifest, node_id, underlays, authority, listen_port, own_key)
    require((own_key is None) == (node_id in entries), "a node's key is the manifest's; the authority's is given")
    name = _interface(interface)
    try:
        own = prepare(own_key or entries[node_id]["wg_service_pub"], name, run)
        apply(text, private_key, name, run)
        verify(text, name, run)
        up(name, run)
    except BaseException as failure:
        try:
            down(name, run)
        except Refused as stuck:
            raise Refused("%s; and %s" % (failure, stuck)) from None
        raise
    return own


def key_at(manifest, source):
    """regalia-sync's `identify`: the WG-SERVICE key (hex) of the node of `manifest` whose derived address
    is `source`. A node in a terminal state is still found here (sync.peer_of then refuses it by name)."""
    try:
        where = ipaddress.IPv6Address(source) if isinstance(source, str) and "%" not in source else None
    except ipaddress.AddressValueError:
        where = None
    require(where is not None and where in PREFIX, "%s is not an address of the service tunnel" % _printable(source))
    keys = [node["wg_service_pub"] for node in manifest["nodes"] if address(node["wg_service_pub"]) == str(where)]
    require(len(keys) == 1, "no node of the current manifest (epoch %d) has the address %s" % (manifest["epoch"], where))
    return keys[0]


def _printable(text):
    return "".join(c if " " <= c <= "~" else "?" for c in str(text))[:80]
