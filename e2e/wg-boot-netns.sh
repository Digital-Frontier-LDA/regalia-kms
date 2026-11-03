#!/usr/bin/env bash
# wg-boot-netns.sh — the boot mesh, proven by behaviour: who can reach a peer's unlock port at all
# (regalia-kms#66, Phase 6: PoC 6.1, 6.4 and the firewall half of the acceptance criteria).
#
#   sudo e2e/wg-boot-netns.sh
#
# Throwaway network namespaces on one bridge; real WireGuard interfaces; every ruleset is loaded ONLY
# inside a namespace, never on the machine running the test.
#
#   alder    the node that boots: interface wg-boot with its WG-BOOT key, the initrd ruleset
#             (bootnet.boot_ruleset), as its initrd would have them. No root filesystem is involved.
#   birch     two running peers: interface wg-unlock with their WG-SERVICE keys (bootnet.peer_wg_conf),
#   acacia      the host firewall (firewall.py) with the boot-mesh rules, and unlock.py's serve() on the
#             unlock port with bootnet.caller_of. The peer is unlock.Peer with its two decisions
#             replaced by fixed answers: what is under test is who gets an answer, not what it says.
#   outsider  a host on the same network, in no list
#   away      alder's own WG-BOOT key, on an address the site never declared: the stolen server,
#             powered on somewhere else (THREE-SITE-THREAT-MODEL.md, attacker case 1)
#
#   0  controls, before any ruleset: every path a later check finds closed is open now, so a refusal
#      below is the configuration's doing. That includes `away`: WireGuard itself accepts a known key
#      from any address.
#   1  the rendered rulesets pass nft -c and load; every chain defaults to drop
#   2  the stolen server away from its datacenter: a valid key, a live session, an undeclared address,
#      and no answer
#   3  PoC 6.1: alder boots and reaches both peers' unlock port through the tunnel; a request made in
#      another node's name is refused by the peer
#   4  the booting node's own ruleset: nothing but WireGuard to the peers and the unlock port
#   5  the PEER's firewall, asked from inside the tunnel by a node that ignores its own ruleset: no
#      SSH, no KMS port, nothing but the unlock port, and on that port nothing but the beginning of a
#      connection (a lone ACK, which connection tracking would call new, does not reach the peer's TCP)
#   6  the outsider reaches the unlock port neither at the peer's address nor at its tunnel address
#   7  a revoked node leaves the WireGuard list of the peer that took the manifest, and is still
#      answered by the peer that has not (the window #69 bounds)
#   8  PoC 6.4: packet loss and latency, an unreachable peer, a wrong key: each ends within a bound
#
# NOT covered: an initrd, the TPM-sealed WG-BOOT key, the systemd units, a real boot (the QEMU test),
# and the real datacenter networks.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; cd "$HERE" || exit 2
export PATH="$PATH:/usr/sbin:/sbin"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ "$(id -u)" = 0 ] || { echo "wg-boot-netns: run as root (sudo)"; exit 2; }
for t in ip nft wg tc conntrack python3; do
  command -v "$t" >/dev/null || { echo "wg-boot-netns: $t is required (iproute2, nftables, wireguard-tools, conntrack, python3)"; exit 2; }
done

T="$(mktemp -d)"; chmod 700 "$T"; SFX="wb$$"
NS=(alder birch acacia outsider away)
declare -A IP=([alder]=192.0.2.10 [birch]=198.51.100.7 [acacia]=198.51.100.9 [outsider]=203.0.113.66 [away]=203.0.113.77)
declare -A TUN=([alder]=10.89.0.1 [birch]=10.89.0.2 [acacia]=10.89.0.3)
WG=51820; UNLOCK=7443
n(){ echo "$1-$SFX"; }
x(){ local h="$1"; shift; ip netns exec "$(n "$h")" "$@"; }
cleanup(){
  for h in "${NS[@]}"; do ip netns pids "$(n "$h")" 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del "$(n "$h")" 2>/dev/null; done
  ip netns del "sw-$SFX" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT

# One switch namespace holding a bridge; every host on it with its address as /32 and an on-link default
# route, so the hosts reach each other directly (no router to confuse the test).
ip netns add "sw-$SFX"; ip -n "sw-$SFX" link add br0 type bridge; ip -n "sw-$SFX" link set br0 up
i=0
for h in "${NS[@]}"; do
  i=$((i+1)); ip netns add "$(n "$h")"
  ip link add "v$i$SFX" type veth peer name eth0 netns "$(n "$h")"
  ip link set "v$i$SFX" netns "sw-$SFX"; ip -n "sw-$SFX" link set "v$i$SFX" master br0 up
  x "$h" ip link set lo up; x "$h" ip link set eth0 up
  x "$h" ip addr add "${IP[$h]}/32" dev eth0; x "$h" ip route add default dev eth0
done
# the booting node's card, by the address regalia.boot-env names it with (its name may differ in an initrd)
ALDER_MAC=52:54:00:ab:cd:01
x alder ip link set eth0 address "$ALDER_MAC"

# Keys: a WG-BOOT and a WG-SERVICE pair per node, as the manifest lists them (hex), and one for the outsider.
umask 077
for h in alder birch acacia; do for k in boot service; do wg genkey > "$T/$h.$k.key"; wg pubkey < "$T/$h.$k.key" > "$T/$h.$k.pub"; done; done
wg genkey > "$T/outsider.key"; wg genkey > "$T/wrong.key"

# The manifests (epoch 1: all ACTIVE; epoch 2: alder REVOKED_STOLEN), the three site configs, and
# everything rendered from them. The manifest is built here as a fixture; on a host it is the verified
# one from membership.Store.
python3 -IB - "$HERE" "$T" <<'PY' || { echo "wg-boot-netns: rendering failed"; exit 2; }
import sys; sys.path.append(sys.argv.pop(1))
import base64, json, sys
from deploy.baremetal import bootnet, firewall, sitecfg
from deploy.baremetal import membership as m
T = sys.argv[1]
IP = {"alder": "192.0.2.10", "birch": "198.51.100.7", "acacia": "198.51.100.9"}
TUN = {"alder": "10.89.0.1", "birch": "10.89.0.2", "acacia": "10.89.0.3"}
def pub(node, kind):
    return base64.b64decode(open("%s/%s.%s.pub" % (T, node, kind)).read().strip()).hex()
def manifest(epoch, prev, **states):
    return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-10-02T09:00:00Z",
            "revocation_keys": ["ab" * 32],
            "nodes": [{"node_id": n, "state": states.get(n, "ACTIVE"), "ek_name": "000b" + ("%02x" % (0x10 + i)) * 32,
                       "ak_name": "000b" + ("%02x" % (0x40 + i)) * 32, "wg_boot_pub": pub(n, "boot"), "wg_service_pub": pub(n, "service"),
                       "hsm_serials": ["DENK04041%02d" % i]} for i, n in enumerate(IP)]}
def site(node):
    return sitecfg.validate({"schema": sitecfg.SCHEMA, "site": node, "host_ipv4": IP[node], "kms_port": 8443, "ssh_port": 22,
                             "client_cidrs": ["198.18.0.0/24"], "monitoring_cidrs": ["198.18.1.1/32"], "admin_cidrs": ["198.18.2.0/28"],
                             "outbound": [{"name": "audit", "cidr": "198.18.3.1/32", "proto": "tcp", "port": 6514}],
                             "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["198.18.3.2/32"]}, {"name": "nts-b.lab", "cidrs": ["198.18.3.3/32"]}]},
                             "boot_mesh": {"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": TUN[node], "unlock_port": 7443,
                                           "nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": None,
                                           "peers": [{"node_id": p, "underlay": IP[p], "address": TUN[p]} for p in IP if p != node]},
                             "service_mesh": None})
m1 = manifest(1, "")
m2 = manifest(2, m.digest(m1), alder="REVOKED_STOLEN")
def write(name, text):
    with open("%s/%s" % (T, name), "w") as f:
        f.write(text)
write("alder.boot.conf", bootnet.boot_wg_conf(site("alder"), m1))
write("alder.boot.nft", bootnet.boot_ruleset(site("alder"), m1))
write("alder.endpoints", json.dumps(bootnet.unlock_endpoints(site("alder"), m1), sort_keys=True))
for peer in ("birch", "acacia"):
    write(peer + ".unlock.conf", bootnet.peer_wg_conf(site(peer), m1))
    write(peer + ".unlock.revoked.conf", bootnet.peer_wg_conf(site(peer), m2))
    write(peer + ".nft", firewall.render(site(peer)))
    write(peer + ".site.json", json.dumps(site(peer)))
write("m1.json", json.dumps(m1))
PY

# WireGuard. The running peers: wg-unlock, WG-SERVICE key. The booting node: wg-boot, WG-BOOT key.
# apply <namespace> <interface> <rendered configuration> <private key file>: the key is added in memory
# and the whole thing piped to wg (bootnet.with_key): a configuration applied WITHOUT its key unsets it.
apply(){ python3 -IB -c 'import sys; sys.path.append(sys.argv.pop(1))
import sys
from deploy.baremetal import bootnet
sys.stdout.write(bootnet.with_key(open(sys.argv[1]).read(), open(sys.argv[2]).read()))' "$HERE" "$3" "$4" | x "$1" wg syncconf "$2" /dev/stdin; }
for h in birch acacia; do
  x "$h" ip link add wg-unlock type wireguard || { echo "wg-boot-netns: this kernel has no WireGuard"; exit 2; }
  apply "$h" wg-unlock "$T/$h.unlock.conf" "$T/$h.service.key"
  x "$h" ip addr add "${TUN[$h]}/32" dev wg-unlock; x "$h" ip link set wg-unlock up; x "$h" ip route add 10.89.0.0/24 dev wg-unlock
done
boot_up(){ # boot_up <namespace> <private key file>: alder's boot interface, in that namespace
  x "$1" ip link del wg-boot 2>/dev/null
  x "$1" ip link add wg-boot type wireguard; apply "$1" wg-boot "$T/alder.boot.conf" "$2"
  x "$1" ip addr add "${TUN[alder]}/32" dev wg-boot; x "$1" ip link set wg-boot up; x "$1" ip route add 10.89.0.0/24 dev wg-boot
}
boot_up alder "$T/alder.boot.key"
boot_up away "$T/alder.boot.key"            # the same key and configuration, at an address nobody declared
# The outsider: its own key, and a route that puts packets for a peer's tunnel address on the wire.
x outsider ip route add "${TUN[birch]}/32" via "${IP[birch]}" dev eth0 onlink

# Listeners on the peers, all bound to every address: if only the binding kept a port closed, a
# misbound service would open it. The firewall has to.
cat > "$T/serve.py" <<'PY'
import json, socket, sys, threading
from deploy.baremetal import bootnet, unlock
T, name, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
class StandIn(unlock.Peer):          # unlock.Peer's own handle(), with the two decisions replaced by fixed answers
    def __init__(self):
        self.peer_id = name
    def audit(self, event):
        with open("%s/%s.audit" % (T, name), "a") as f:
            f.write(json.dumps(event) + "\n")
    def hello(self, message):
        return {"v": 1, "peer_id": name, "epoch": 1, "nonce": "00" * 32}
    def unlock(self, message):
        return {"v": 1, "error": "DENIED"}
def plain(port):
    s = socket.create_server(("0.0.0.0", port))
    while True:
        c, _ = s.accept(); c.close()
for other in (8443, 22, 9999):
    threading.Thread(target=plain, args=(other,), daemon=True).start()
cfg, manifest = json.load(open("%s/%s.site.json" % (T, name))), json.load(open(T + "/m1.json"))
unlock.serve(StandIn(), socket.create_server(("0.0.0.0", port)), caller=bootnet.caller_of(cfg, manifest))
PY
for h in birch acacia; do x "$h" env PYTHONPATH="$HERE" python3 -s "$T/serve.py" "$T" "$h" "$UNLOCK" & disown; done
for h in outsider:443 alder:22; do
  x "${h%%:*}" python3 -I -c "
import socket
s = socket.create_server(('0.0.0.0', ${h##*:}))
while True:
    c, _ = s.accept(); c.close()" & disown
done
sleep 1

# asked <namespace> <address> [timeout] [node]: an unlock request in `node`'s name (alder's) is answered
# by the peer with a nonce. Exit 3 when the peer answers with a refusal instead.
asked(){ x "$1" python3 -IB -c "import sys; sys.path.append(sys.argv.pop(1))
import json, sys
from deploy.baremetal import unlock
unlock.IO_TIMEOUT = float(sys.argv[2])
try:
    reply = json.loads(unlock.tcp_transport(sys.argv[1] + ':$UNLOCK')(json.dumps({'v': 1, 'op': 'hello', 'node_id': sys.argv[3]}).encode()))
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if reply.get('nonce') else 3 if reply == {'v': 1, 'error': 'DENIED'} else 1)" "$HERE" "$2" "${3:-3}" "${4:-alder}"; }
tcpok(){ x "$1" python3 -I -c "
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()
except OSError:
    sys.exit(1)" "$2" "$3"; }
# stray <namespace> <address> <port>: a lone ACK segment, belonging to no connection, sent to that port.
# Exit 0 when the host's TCP answered it (a RST): the segment reached the stack. Exit 1 when nothing came.
stray(){ x "$1" python3 -I -c "
import os, socket, struct, sys, time
there, port = sys.argv[1], int(sys.argv[2])
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe.connect((there, port)); here = probe.getsockname()[0]; probe.close()
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
mine = 20000 + os.getpid() % 20000
def total(data):
    data += b'\\0' * (len(data) % 2)
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def segment(checksum):
    return struct.pack('!HHIIBBHHH', mine, port, 1000, 2000, 5 << 4, 0x10, 1024, checksum, 0)
pseudo = socket.inet_aton(here) + socket.inet_aton(there) + struct.pack('!BBH', 0, socket.IPPROTO_TCP, 20)
raw.sendto(segment(total(pseudo + segment(0))), (there, 0))
end = time.monotonic() + 2
while time.monotonic() < end:
    raw.settimeout(max(0.05, end - time.monotonic()))
    try:
        packet, sender = raw.recvfrom(4096)
    except OSError:
        break
    tcp = packet[(packet[0] & 15) * 4:]
    if sender[0] == there and struct.unpack('!HH', tcp[:4]) == (port, mine) and tcp[13] & 0x04:
        sys.exit(0)
sys.exit(1)" "$2" "$3"; }
shook(){ # shook <peer> <public key file>: the peer has completed a handshake with that key
  x "$1" wg show wg-unlock latest-handshakes | awk -v k="$(cat "$2")" '$1 == k && $2 > 0 { found = 1 } END { exit !found }'; }

hdr "0  controls, before any ruleset: everything a later check finds closed is open now"
asked alder "${TUN[birch]}" && asked alder "${TUN[acacia]}" && P "control: alder reaches both peers' unlock port through the tunnel" || F "control: the tunnel does not work at all"
tcpok alder "${TUN[birch]}" 22 && tcpok alder "${TUN[birch]}" 8443 && tcpok alder "${TUN[birch]}" 9999 \
  && P "control: inside the tunnel, SSH, the KMS port and port 9999 of a peer answer" || F "control: the listeners inside the tunnel do not answer"
stray alder "${TUN[birch]}" "$UNLOCK" && P "control: a lone ACK to the unlock port, inside the tunnel, reaches the peer's TCP and is answered with a reset" \
  || F "control: the lone ACK got no reset even without a firewall"
tcpok alder "${IP[birch]}" "$UNLOCK" && tcpok alder "${IP[birch]}" 22 && P "control: at the peer's own address, the unlock port and SSH answer" || F "control: the peer's own address does not answer"
tcpok alder "${IP[outsider]}" 443 && P "control: alder reaches an undeclared host" || F "control: alder has no path to the outsider"
tcpok outsider "${IP[alder]}" 22 && P "control: a listener on the booting node answers the outsider" || F "control: nothing listens on the booting node"
tcpok outsider "${IP[birch]}" "$UNLOCK" && P "control: the outsider reaches the unlock port at the peer's address" || F "control: the outsider has no path to the peer"
tcpok outsider "${TUN[birch]}" "$UNLOCK" && P "control: the outsider reaches the peer's tunnel address from outside the tunnel" || F "control: no path to the tunnel address from outside"
asked away "${TUN[birch]}" && shook birch "$T/alder.boot.pub" \
  && P "control: WireGuard alone lets alder's key in from an address nobody declared" || F "control: the undeclared address does not work even without a firewall"

hdr "1  the rendered rulesets: nft -c, then loaded inside their namespaces only"
for h in birch acacia; do
  x "$h" nft -c -f "$T/$h.nft" && x "$h" nft -f "$T/$h.nft" && P "$h: the host firewall with the boot mesh loads" || F "$h: the host firewall does not load"
done
x alder nft -c -f "$T/alder.boot.nft" && x alder nft -f "$T/alder.boot.nft" && P "alder: the initrd ruleset loads" || F "alder: the initrd ruleset does not load"
pol="$(x alder nft -j list table inet regalia_boot | python3 -I -c '
import json, sys
d = json.load(sys.stdin)["nftables"]
print(" ".join(sorted("%s=%s" % (c["chain"]["name"], c["chain"].get("policy")) for c in d if "chain" in c)))')"
[ "$pol" = "forward=drop input=drop output=drop" ] && P "alder: every chain defaults to drop" || F "alder: policies: $pol"
# A ruleset does not cut a flow that was already established: the controls above left some. A host
# loads its ruleset at boot, before any flow; here the connection tracking table is emptied instead.
for h in alder birch acacia; do x "$h" conntrack -F >/dev/null 2>&1; done

hdr "2  the stolen server away from its datacenter: alder's key, a live session, an undeclared address"
# The control a moment ago left birch holding a live session with `away` (the last to shake hands with
# that key). Without the firewall its next request would be answered, as it just was.
# The real alder is not there (it is the one that was stolen): its interface is down, so that a
# handshake seen by a peer below can only be the copy's.
x alder ip link del wg-boot
shaken(){ x "$1" wg show wg-unlock latest-handshakes | awk -v k="$(cat "$T/alder.boot.pub")" '$1 == k { print $2 }'; }
before="$(shaken birch)"; before_acacia="$(shaken acacia)"
asked away "${TUN[birch]}" 4 && F "alder's key was answered from an undeclared address" || P "alder's key, with a live session, gets no answer from an undeclared address"
asked away "${TUN[acacia]}" 4 && F "alder's key was answered by the other peer from an undeclared address" || P "nor a first handshake with the other peer"
[ "$(shaken birch)" = "$before" ] && [ "$(shaken acacia)" = "$before_acacia" ] && P "neither peer shook hands with it" \
  || F "a peer shook hands with the undeclared address (birch: $before -> $(shaken birch), acacia: $before_acacia -> $(shaken acacia))"

hdr "3  PoC 6.1: the node boots and reaches both peers' unlock port through the tunnel"
# The boot is made by the script the initrd runs (deploy/baremetal/initrd/wg-boot, as
# regalia-wg-boot.service runs it): the ruleset first, then the address, then WireGuard with the key
# from the credentials directory. A boot starts with a handshake. (A node whose session a peer has
# replaced, as `away` did to alder's here, otherwise waits out WireGuard's own timers, some 15 s.)
x alder ip addr flush dev eth0; x alder nft delete table inet regalia_boot
C="$T/creds"; mkdir "$C"; cp "$T/alder.boot.conf" "$C/regalia.wg-boot-conf"; cp "$T/alder.boot.nft" "$C/regalia.boot-nft"; cp "$T/alder.boot.key" "$C/regalia.wg-boot-key"
# boot.env is data to the script, not its environment: a line that would be code if it were sourced or
# exported (LD_PRELOAD, a command substitution) is in it, and must change nothing.
printf 'BOOT_NIC_MAC=%s\nBOOT_ADDRESS=%s/32\nBOOT_GATEWAY=\nBOOT_TUNNEL=%s\nLD_PRELOAD=%s/evil.so\nBOOT_EXTRA=$(touch %s/sourced)\n' \
  "$ALDER_MAC" "${IP[alder]}" "${TUN[alder]}" "$T" "$T" > "$C/regalia.boot-env"
R="$T/run-wg-boot"; mkdir "$R"
# the script runs with only the programs the dracut module puts in the image on its PATH, as in the initrd
mkdir "$T/initrd-bin"; for t in ip wg nft sed cat sleep; do ln -s "$(command -v "$t")" "$T/initrd-bin/$t"; done
# (the rendered files and the sealed key in one directory here: in the initrd they are /run/regalia-boot and the
# unit's credentials, #66 B3)
initrd(){ x alder env PATH="$T/initrd-bin" CREDENTIALS_DIRECTORY="$C" REGALIA_BOOT_DIR="$C" RUNTIME_DIRECTORY="$R" /bin/sh "$HERE/deploy/baremetal/initrd/wg-boot" "$1"; }
initrd up && P "the initrd's script brings the boot mesh up" || F "deploy/baremetal/initrd/wg-boot up failed"
[ "$(x alder wg show wg-boot private-key)" = "$(cat "$T/alder.boot.key")" ] && [ "$(x alder wg show wg-boot peers | wc -l)" = 2 ] \
  && P "wg-boot has the node's key and its two peers" || F "wg-boot is not configured as rendered"
[ ! -e "$T/sourced" ] && P "boot.env was read as data: nothing in it ran" || F "a line of boot.env was executed"
[ "$(cat "$R/boot-nic")" = eth0 ] && P "the card was found by its address (eth0, $ALDER_MAC)" || F "wg-boot recorded $(cat "$R/boot-nic") for $ALDER_MAC"
# the card's address in another spelling, or on two interfaces: refused, never guessed
cp "$C/regalia.boot-env" "$T/good.env"
sed -i "s|^BOOT_NIC_MAC=.*|BOOT_NIC_MAC=$(echo "$ALDER_MAC" | tr a-f A-F)|" "$C/regalia.boot-env"     # the same card, upper case
initrd up 2>"$T/up.err" && F "a MAC address in upper case was taken" || { grep -q "BOOT_NIC_MAC must be a MAC address" "$T/up.err" \
  && P "a MAC address that is not lower case is refused" || F "refused for another reason: $(cat "$T/up.err")"; }
cp "$T/good.env" "$C/regalia.boot-env"
x alder ip link add regalia-twin type dummy && x alder ip link set regalia-twin address "$ALDER_MAC" || F "no dummy interface: the shared-address case did not run"
initrd up 2>"$T/up.err" && F "an address on two interfaces was taken" || { grep -q "more than one interface has the address" "$T/up.err" \
  && P "an address on two interfaces is refused (which card is meant is not guessed)" || F "refused for another reason: $(cat "$T/up.err")"; }
x alder ip link del regalia-twin
# a start that fails part-way leaves nothing behind: here the key is not a key, after the ruleset would have loaded
cp "$C/regalia.wg-boot-key" "$T/good"; echo "not-a-wireguard-key" > "$C/regalia.wg-boot-key"
initrd up 2>"$T/up.err" && F "the script accepted a credential that is not a key" || P "a credential that is not a key is refused"
grep -q "not-a-wireguard-key" "$T/up.err" && F "the refused credential was printed" || P "and it is not printed"
cp "$T/good" "$C/regalia.wg-boot-key"; printf '# a comment first\n' | cat - "$T/alder.boot.conf" > "$C/regalia.wg-boot-conf"
initrd up 2>"$T/up.err" && F "the script accepted a configuration it did not render" || P "a configuration that does not begin with [Interface] is refused"
grep -q "$(cat "$T/alder.boot.key")" "$T/up.err" && F "the key was printed" || P "and the key is not printed"
cp "$T/alder.boot.conf" "$C/regalia.wg-boot-conf"
# the ruleset is a credential from the ESP: it may read no other file (nft would print it, key and all) and
# make no other table (one that outlived the boot would be in the running host's path)
cp "$C/regalia.boot-nft" "$T/good.nft"; printf 'include "%s"\n' "$C/regalia.wg-boot-key" >> "$C/regalia.boot-nft"
initrd up 2>"$T/up.err" && F "a ruleset that includes a file was loaded" || P "a ruleset that includes another file is refused"
grep -q "$(cat "$T/alder.boot.key")" "$T/up.err" && F "the included key was printed" || P "and the key it named is not printed"
cp "$T/good.nft" "$C/regalia.boot-nft"; printf 'table netdev extra {\n}\n' >> "$C/regalia.boot-nft"
initrd up 2>/dev/null && F "a ruleset with another table was loaded" || P "a ruleset that makes another table is refused"
[ "$(x alder nft list tables)" = "" ] && P "and no table at all is left" || F "tables left: $(x alder nft list tables | tr '\n' ' ')"
cp "$T/good.nft" "$C/regalia.boot-nft"; sed -i 's|^BOOT_TUNNEL=.*|BOOT_TUNNEL=not-an-address|' "$C/regalia.boot-env"
initrd up 2>/dev/null && F "the script succeeded with an impossible tunnel address" || P "a start that fails after the ruleset loaded"
x alder ip link show wg-boot >/dev/null 2>&1 || x alder nft list table inet regalia_boot >/dev/null 2>&1 || [ -n "$(x alder ip -4 addr show dev eth0)" ] \
  && F "the failed start left the interface, the ruleset or the address behind" || P "leaves no interface, no ruleset and no address behind"
sed -i "s|^BOOT_TUNNEL=.*|BOOT_TUNNEL=${TUN[alder]}|" "$C/regalia.boot-env"
initrd up && P "and the next start succeeds" || F "the start after a failed one does not succeed"
for h in birch acacia; do
  asked alder "${TUN[$h]}" && P "alder is answered by $h on the unlock port, inside the tunnel" || F "alder is not answered by $h"
done
endpoint="$(x birch wg show wg-unlock endpoints | awk -v k="$(cat "$T/alder.boot.pub")" '$1 == k { print $2 }')"
[ "$endpoint" = "${IP[alder]}:$(x alder wg show wg-boot listen-port)" ] && P "the peer now knows that key at its declared address ($endpoint)" || F "the peer's endpoint for alder's key is $endpoint"
[ "$(cat "$T/alder.endpoints")" = "{\"acacia\": \"${TUN[acacia]}:$UNLOCK\", \"birch\": \"${TUN[birch]}:$UNLOCK\"}" ] \
  && P "the endpoints for the client's boot configuration are those two" || F "endpoints: $(cat "$T/alder.endpoints")"
asked alder "${TUN[birch]}" 3 acacia; rc=$?
[ "$rc" = 3 ] && grep -q '"unlock-caller"' "$T/birch.audit" && P "a request in acacia's name from alder's tunnel address is refused by the peer, and audited" \
  || F "a request in another node's name: rc=$rc (3 is a refusal)"

hdr "4  the booting node's own ruleset: nothing but WireGuard to the peers and the unlock port"
for port in 22 8443 9999; do
  tcpok alder "${TUN[birch]}" "$port" && F "inside the tunnel, alder reached port $port of a peer" || P "inside the tunnel, alder does not reach port $port of a peer"
done
tcpok alder "${IP[outsider]}" 443 && F "the booting node reached an undeclared host" || P "the booting node reaches no undeclared host"
tcpok outsider "${IP[alder]}" 22 && F "the listener on the booting node answered" || P "the listener on the booting node answers nobody"

hdr "5  the peer's firewall, asked from inside the tunnel by a node that ignores its own ruleset"
# What a retired but signed image, or anything else holding the boot key at the declared address, can
# do: bring the tunnel up and send what it likes. alder's ruleset is taken away; birch's must hold.
x alder nft delete table inet regalia_boot
tcpok alder "${IP[outsider]}" 443 && P "control: without its ruleset alder reaches an undeclared host again" || F "control: alder's ruleset is still in the way"
asked alder "${TUN[birch]}" && P "inside the tunnel, the unlock port answers" || F "the unlock port stopped answering"
for port in 22 8443 9999; do
  tcpok alder "${TUN[birch]}" "$port" && F "inside the tunnel, port $port of the peer answered" || P "inside the tunnel, port $port of the peer does not answer"
done
# The unlock rule admits the beginning of a connection, a SYN, and nothing else that conntrack would call new.
[ "$(x birch sysctl -n net.netfilter.nf_conntrack_tcp_loose)" = 1 ] && P "control: birch's connection tracking would take a mid-stream segment for a new connection" \
  || F "control: nf_conntrack_tcp_loose is not 1 on birch, so the next check shows nothing"
stray alder "${TUN[birch]}" "$UNLOCK" && F "a lone ACK to the unlock port reached the peer's TCP" || P "a lone ACK to the unlock port, inside the tunnel, does not reach the peer's TCP"
asked alder "${TUN[birch]}" && P "... and a real request is still answered" || F "the unlock port stopped answering"
for port in "$UNLOCK" 22 8443; do
  tcpok alder "${IP[birch]}" "$port" && F "at the peer's own address, port $port answered alder" || P "at the peer's own address, port $port does not answer alder"
done
x alder nft -f "$T/alder.boot.nft"

hdr "6  the outsider"
tcpok outsider "${IP[birch]}" "$UNLOCK" && F "the outsider reached the unlock port at the peer's address" || P "the outsider does not reach the unlock port at the peer's address"
tcpok outsider "${TUN[birch]}" "$UNLOCK" && F "the outsider reached the peer's tunnel address from outside the tunnel" || P "the outsider does not reach the peer's tunnel address from outside the tunnel"
x outsider ip link add wg-out type wireguard; x outsider wg set wg-out private-key /dev/stdin < <(cat "$T/outsider.key") peer "$(cat "$T/birch.service.pub")" \
  allowed-ips "${TUN[birch]}/32" endpoint "${IP[birch]}:$WG"
x outsider ip route del "${TUN[birch]}/32"; x outsider ip addr add 10.89.0.9/32 dev wg-out; x outsider ip link set wg-out up; x outsider ip route add "${TUN[birch]}/32" dev wg-out
asked outsider "${TUN[birch]}" 2 && F "a key that is in no manifest got an answer" || P "a key that is in no manifest gets no answer"

hdr "7  revocation: the peer that took the manifest drops the key; the peer that has not still answers"
apply birch wg-unlock "$T/birch.unlock.revoked.conf" "$T/birch.service.key"
x birch wg show wg-unlock peers | grep -qx "$(cat "$T/alder.boot.pub")" && F "birch still lists the revoked node's key" || P "birch no longer lists the revoked node's key"
# so that the refusal below is the list's doing: birch still has its own key and still lists the other node
[ "$(x birch wg show wg-unlock private-key)" = "$(cat "$T/birch.service.key")" ] && x birch wg show wg-unlock peers | grep -qx "$(cat "$T/acacia.boot.pub")" \
  && P "birch keeps its own key and the other node's" || F "applying the manifest took birch's key or the other node's away"
asked alder "${TUN[birch]}" 4 && F "the revoked node was answered by the peer that took the manifest" || P "the revoked node gets no answer from birch"
asked alder "${TUN[acacia]}" && P "acacia, which has not taken the manifest, still answers: the window that the heartbeat bounds (#69)" || F "acacia stopped answering without the manifest"
apply birch wg-unlock "$T/birch.unlock.conf" "$T/birch.service.key"
boot_up alder "$T/alder.boot.key"          # the next boot: birch dropped the old session with the key
asked alder "${TUN[birch]}" && P "(the manifest put back for the checks below: at its next boot alder is answered by birch again)" || F "birch does not answer after the peer list was restored"

hdr "8  PoC 6.4: loss and latency, an unreachable peer, a wrong key: each ends within a bound"
timed(){ local start=$SECONDS; "$@"; local rc=$?; took=$((SECONDS - start)); return $rc; }
x alder tc qdisc add dev eth0 root netem loss 20% delay 100ms || F "netem is not available: the loss and latency case did not run"
# regalia-6x5: two questions, kept apart.
#  (1) Is the configured loss what is applied? Deterministic: the qdisc must read exactly loss 20% delay 100ms.
#  (2) Do requests still succeed under it, each within a bound? Statistical, sized on MEASURED rates: under this netem,
#      1 of 193 requests failed over three CI runs (#566, run 40069307386 attempts 1-3); the one-sided 95% upper bound
#      is p <= 0.024, and the rule is sized on p <= 0.05 for margin. Ask at most 35 times; pass once 27 are answered
#      (then at most 8 failed), fail at the 9th failure. By chance alone it fails with P(Bin(35, 0.05) > 8) = 4.2e-5 per
#      run. It still catches a regression in the client's retries: at p = 0.5 it passes with 9.4e-4, at p = 0.8 with
#      5.7e-13 (the old "4 of 5" failed by chance 2.3% of runs at p = 0.05, and passed 19% of the time at p = 0.5).
#      Every request must end within 12 s. Each is printed (o answered, x not) so the rate can be re-measured.
qd="$(x alder tc qdisc show dev eth0)"
grep -q "netem" <<< "$qd" && grep -qw "delay 100ms" <<< "$qd" && grep -qw "loss 20%" <<< "$qd" && P "netem applies exactly what the case is sized on: $qd" || F "netem is not loss 20% delay 100ms: $qd"
ok=0; bad=0; worst=0; seen=""
while [ "$ok" -lt 27 ] && [ "$bad" -le 8 ]; do
  if timed asked alder "${TUN[acacia]}" 10; then ok=$((ok+1)); seen="${seen}o"; else bad=$((bad+1)); seen="${seen}x"; fi
  [ "$took" -gt "$worst" ] && worst=$took
done
echo "  (loss and delay: attempts $seen)"
[ "$ok" -ge 27 ] && [ "$worst" -le 12 ] && P "with 20% loss and 100 ms delay: 27 requests answered, $bad not, each ending within ${worst}s" \
  || F "with loss and delay: $ok answered and $bad not (fails at 9), the slowest ending in ${worst}s"
x alder tc qdisc del dev eth0 root
x acacia ip link set eth0 down
timed asked alder "${TUN[acacia]}" 3; rc=$?
[ "$rc" != 0 ] && [ "$took" -le 10 ] && P "an unreachable peer: refused after ${took}s, and the other peer is asked" || F "an unreachable peer: rc=$rc after ${took}s"
asked alder "${TUN[birch]}" && P "the other peer still answers" || F "the other peer does not answer"
x acacia ip link set eth0 up; x acacia ip route add default dev eth0 2>/dev/null
# what bootnet.py warns of, shown: a configuration applied without its key leaves the interface with none
# Piped from this root shell: ubuntu-26.04's AppArmor profile for wg reads no file in $T, and a refused read
# left the key in place, which this check took for wg's behaviour (regalia-kms#550). So the apply must succeed.
if ! x acacia wg syncconf wg-unlock /dev/stdin < <(cat "$T/acacia.unlock.conf"); then
  F "wg syncconf of the keyless configuration failed: nothing was measured"
elif [ "$(x acacia wg show wg-unlock private-key)" = "(none)" ]; then
  P "measured: wg syncconf with a file that has no PrivateKey unsets the interface's key"
else
  F "wg syncconf without a key did not unset it: bootnet.py's warning is out of date"
fi
boot_up alder "$T/wrong.key"
timed asked alder "${TUN[birch]}" 3; rc=$?
[ "$rc" != 0 ] && [ "$took" -le 10 ] && P "a wrong WG-BOOT key: no answer, after ${took}s" || F "a wrong key: rc=$rc after ${took}s"
initrd up >/dev/null 2>&1
# as ExecStopPost runs it: the credentials are gone, the runtime directory is still there
x alder env PATH="$T/initrd-bin" RUNTIME_DIRECTORY="$R" /bin/sh "$HERE/deploy/baremetal/initrd/wg-boot" down
x alder ip link show wg-boot >/dev/null 2>&1 || x alder nft list table inet regalia_boot >/dev/null 2>&1 || [ -n "$(x alder ip -4 addr show dev eth0)" ] \
  && F "the boot interface, its ruleset or its address is still there" || P "without its credentials, as at switch-root, the script takes the interface, the ruleset and the address down"

echo; echo "wg-boot-netns: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
