#!/usr/bin/env bash
# baremetal-firewall-netns.sh — the bare-metal host firewall, proven by behaviour, not by reading rules.
#
#   sudo e2e/baremetal-firewall-netns.sh
#
# Builds throwaway network namespaces on one bridge: the KMS host (the rendered ruleset is loaded ONLY
# inside its namespace, never on the machine running the test), a client, a monitoring host, an admin
# host, an unauthorized host, and the audit and NTP sinks. Then:
#   1  network_probe.py from each zone: KMS port and SSH port exactly as the site config says
#   2  a listener on an undeclared port of the KMS host is reachable from nowhere
#   3  outbound: the KMS host reaches the audit sink (TCP) and the NTS server (NTS-KE TCP 4460, NTP UDP 123,
#      rendered from time.nts, #303), and nothing else
#   4  the rendered file passes nft -c and loads; forward and IPv6 are dropped
#   5  the service tunnel (#80), with real WireGuard: IPv6 is carried only on wg-svc, only between addresses
#      of the tunnel's prefix, only to the sync port; nothing else gets in or out by the tunnel, a zone's
#      address inside it included; a valid key at an undeclared address gets no handshake
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; BM="$HERE/deploy/baremetal"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ "$(id -u)" = 0 ] || { echo "baremetal-firewall-netns: run as root (sudo)"; exit 2; }
for t in ip nft python3 wg; do command -v "$t" >/dev/null || { echo "baremetal-firewall-netns: $t is required (iproute2, nftables, wireguard-tools)"; exit 2; }; done

T="$(mktemp -d)"; SFX="bm$$"
NS=(kms client mon admin unauth audit ntp peer stranger)
declare -A IP=([kms]=192.0.2.10 [client]=198.51.100.20 [mon]=203.0.113.128 [admin]=203.0.113.4
               [unauth]=203.0.113.66 [audit]=203.0.113.192 [ntp]=203.0.113.193 [peer]=192.0.2.20 [stranger]=192.0.2.66)
n(){ echo "$1-$SFX"; }
cleanup(){
  for h in "${NS[@]}"; do ip netns pids "$(n "$h")" 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del "$(n "$h")" 2>/dev/null; done
  ip netns del "sw-$SFX" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT

# One switch namespace holding a bridge; every host on it, each with its address as /32 and an on-link
# default route, so the hosts reach each other directly at layer 2 (no router to confuse the test).
ip netns add "sw-$SFX"; ip -n "sw-$SFX" link add br0 type bridge; ip -n "sw-$SFX" link set br0 up
i=0
for h in "${NS[@]}"; do
  i=$((i+1)); ip netns add "$(n "$h")"
  ip link add "v$i$SFX" type veth peer name eth0 netns "$(n "$h")"
  ip link set "v$i$SFX" netns "sw-$SFX"; ip -n "sw-$SFX" link set "v$i$SFX" master br0 up
  ip -n "$(n "$h")" link set lo up; ip -n "$(n "$h")" link set eth0 up
  ip -n "$(n "$h")" addr add "${IP[$h]}/32" dev eth0
  ip -n "$(n "$h")" route add default dev eth0
done
x(){ local h="$1"; shift; ip netns exec "$(n "$h")" "$@"; }

# IPv6 on the bridge (ULA, no duplicate-address wait): the KMS host and the client, to prove IPv6 is dropped.
x kms ip addr add fd00:5:7::10/64 dev eth0 nodad; x client ip addr add fd00:5:7::20/64 dev eth0 nodad
# A routed segment BEHIND the KMS host: the "inside" host is reachable only by forwarding through it, so
# the forward chain carries real traffic. The unauthorized host routes to it via the KMS host.
ip netns add "$(n inside)"; NS+=(inside)
ip link add "vin$SFX" type veth peer name eth0 netns "$(n inside)"; ip link set "vin$SFX" netns "$(n kms)"
x kms ip addr add 10.99.0.1/24 dev "vin$SFX"; x kms ip link set "vin$SFX" up
x inside ip link set lo up; x inside ip link set eth0 up; x inside ip addr add 10.99.0.2/24 dev eth0
x inside ip route add default via 10.99.0.1
x kms sysctl -qw net.ipv4.ip_forward=1
x unauth ip route add 10.99.0.0/24 via "${IP[kms]}" dev eth0 onlink

cat > "$T/site.json" <<EOF
{"schema": "regalia.baremetal-site/v1", "site": "lab", "host_ipv4": "${IP[kms]}", "kms_port": 8443, "ssh_port": 22,
 "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["${IP[mon]}/32"], "admin_cidrs": ["203.0.113.0/28"],
 "outbound": [{"name": "audit", "cidr": "${IP[audit]}/32", "proto": "tcp", "port": 6514}],
 "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["${IP[ntp]}/32"]}, {"name": "nts-b.lab", "cidrs": ["203.0.113.195/32"]}]},
 "boot_mesh": null, "service_mesh": null}
EOF

# Listeners: a TCP server answers on each port given; a UDP echo answers one datagram.
cat > "$T/listen.py" <<'PY'
import socket, sys, threading
def tcp(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", p)); s.listen()
    while True:
        c, _ = s.accept(); c.close()
def tcp6(p):
    s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1); s.bind(("::", p)); s.listen()
    while True:
        c, _ = s.accept(); c.close()
def udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", p))
    while True:
        d, a = s.recvfrom(64); s.sendto(d, a)
for spec in sys.argv[1:]:
    proto, port = spec.split(":"); threading.Thread(target={"tcp": tcp, "tcp6": tcp6, "udp": udp}[proto], args=(int(port),), daemon=True).start()
threading.Event().wait()
PY
x kms python3 -Es "$T/listen.py" tcp:8443 tcp:22 tcp:9999 tcp6:8443 &
x inside python3 -Es "$T/listen.py" tcp:80 &
x audit python3 -Es "$T/listen.py" tcp:6514 tcp:7000 &
x ntp python3 -Es "$T/listen.py" udp:123 udp:124 tcp:4460 tcp:4461 &
x unauth python3 -Es "$T/listen.py" tcp:6514 tcp:443 &
sleep 1

tcpok(){ local h="$1" dst="$2" port="$3"; x "$h" python3 -I -c "
import socket, sys
try:
    socket.create_connection(('$dst', $port), timeout=1).close(); sys.exit(0)
except OSError:
    sys.exit(1)"; }
udpok(){ x kms python3 -I -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(b'x', ('${IP[ntp]}', $1)); s.recvfrom(64); sys.exit(0)
except OSError:
    sys.exit(1)"; }
hdr "0  control: before the ruleset, the lab really connects (so a later refusal is the firewall's)"
tcpok client fd00:5:7::10 8443 && P "control: the client reaches the KMS port over IPv6 before the ruleset" || F "control: no IPv6 path: the IPv6 check below would prove nothing"
tcpok unauth 10.99.0.2 80 && P "control: traffic is FORWARDED through the KMS host before the ruleset" || F "control: no routed path through the KMS host: the forward check below would prove nothing"
tcpok unauth "${IP[kms]}" 9999 && P "port 9999 on the KMS host is reachable before the ruleset" || F "the lab cannot connect at all: every refusal below would prove nothing"
tcpok kms "${IP[unauth]}" 443 && P "the KMS host reaches an undeclared host before the ruleset" || F "outbound control failed"
# Every listener a negative check below relies on must answer now; a listener that failed to bind would
# otherwise make "not reachable" pass whatever the firewall does.
tcpok kms "${IP[audit]}" 7000 && P "control: audit:7000 answers before the ruleset" || F "control: audit:7000 not listening"
tcpok kms "${IP[unauth]}" 6514 && P "control: unauth:6514 answers before the ruleset" || F "control: unauth:6514 not listening"
udpok 124 && P "control: ntp:124/udp answers before the ruleset" || F "control: ntp:124/udp not listening"
tcpok kms "${IP[ntp]}" 4461 && P "control: ntp:4461 answers before the ruleset" || F "control: ntp:4461 not listening"

hdr "4  the rendered ruleset: nft -c, then loaded in the KMS namespace only"
python3 -Es "$BM/firewall.py" "$T/site.json" > "$T/kms.nft" && P "rendered" || F "render failed"
x kms nft -c -f "$T/kms.nft" && P "nft -c accepts it" || F "nft -c refuses it"
x kms nft -f "$T/kms.nft" && P "loaded inside the KMS namespace" || F "load failed"
pol="$(x kms nft -j list table inet regalia_kms | python3 -I -c '
import json, sys
d = json.load(sys.stdin)["nftables"]
print(" ".join(sorted("%s=%s" % (c["chain"]["name"], c["chain"].get("policy")) for c in d if "chain" in c)))')"
[ "$pol" = "forward=drop input=drop output=drop" ] && P "every chain defaults to drop ($pol)" || F "policies: $pol"

hdr "1  network_probe.py from each zone"
for role in client:client monitoring:mon admin:admin unauthorized:unauth; do
  r="${role%%:*}"; h="${role##*:}"
  out="$(x "$h" python3 -Es "$BM/network_probe.py" "$T/site.json" --role "$r" --source-ip "${IP[$h]}" --timeout 1)"; rc=$?
  [ "$rc" = 0 ] && P "$r: matrix matches the config" || F "$r (rc=$rc): $out"
done
out="$(x client python3 -Es "$BM/network_probe.py" "$T/site.json" --role admin --source-ip "${IP[client]}" 2>&1)"; rc=$?
[ "$rc" = 2 ] && P "a probe claiming a zone it is not in is refused (exit 2)" || F "role/source mismatch rc=$rc"

hdr "2  an undeclared port on the KMS host is reachable from nowhere"
for h in client mon admin unauth; do
  tcpok "$h" "${IP[kms]}" 9999 && F "$h reached port 9999" || P "$h cannot reach port 9999"
done

hdr "2b  IPv6 and forwarding are denied by behaviour, not only by policy"
tcpok client fd00:5:7::10 8443 && F "the KMS port was reachable over IPv6" || P "the KMS port is not reachable over IPv6 (dropped)"
tcpok unauth 10.99.0.2 80 && F "traffic was forwarded through the KMS host" || P "nothing is forwarded through the KMS host (forward chain drops)"

hdr "3  outbound: only the declared sinks"
tcpok kms "${IP[audit]}" 6514 && P "audit sink 6514/tcp reachable" || F "audit sink unreachable"
tcpok kms "${IP[audit]}" 7000 && F "the audit host on an undeclared port was reachable" || P "the audit host on another port is not"
tcpok kms "${IP[unauth]}" 6514 && F "an undeclared host was reachable" || P "an undeclared host (even on 6514) is not"
tcpok kms "${IP[unauth]}" 443 && F "an undeclared host:443 was reachable" || P "an undeclared host on 443 is not"
udpok 123 && P "NTS server: NTP 123/udp reachable (rendered from time.nts)" || F "NTS server: NTP unreachable"
tcpok kms "${IP[ntp]}" 4460 && P "NTS server: NTS-KE 4460/tcp reachable" || F "NTS server: NTS-KE unreachable"
udpok 124 && F "the NTS server on an undeclared UDP port was reachable" || P "the NTS server on another UDP port is not"
tcpok kms "${IP[ntp]}" 4461 && F "the NTS server on an undeclared TCP port was reachable" || P "the NTS server on another TCP port is not"

# ---- 5: the service tunnel ---------------------------------------------------------------------------------
hdr "5  the service tunnel (#80): real WireGuard, and what the ruleset lets through it"
PREFIX="$(python3 -IB -c "import sys; sys.path.insert(0, '$BM'); import sitecfg; print(sitecfg.SERVICE_PREFIX)")"
# a tunnel address is derived from the WireGuard public key: the prefix, then 80 bits of SHA-256 of the key
derive(){ python3 -I -c "
import base64, hashlib, ipaddress, sys
key = base64.b64decode(open(sys.argv[1]).read().strip())
print(ipaddress.IPv6Address(ipaddress.IPv6Network('$PREFIX').network_address.packed[:6] + hashlib.sha256(key).digest()[:10]))" "$1"; }
for h in kms peer stranger; do (umask 077; wg genkey > "$T/$h.key"); wg pubkey < "$T/$h.key" > "$T/$h.pub"; done
A_KMS="$(derive "$T/kms.pub")"; A_PEER="$(derive "$T/peer.pub")"; A_STR="$(derive "$T/stranger.pub")"
ZONE4=198.51.100.77   # an address of the CLIENT zone, held by the peer INSIDE the tunnel
OUT6=fd00:9::1        # an IPv6 address outside the tunnel's prefix, held by the peer inside the tunnel
# The KMS host. The peer is allowed MORE than its one derived address on purpose: this test is of the
# firewall, so WireGuard must not be what stops the wrong addresses (wgsvc.py's read-back is tested elsewhere).
x kms ip link add wg-svc type wireguard
x kms wg set wg-svc listen-port 51821 private-key "$T/kms.key" \
  peer "$(cat "$T/peer.pub")" allowed-ips "$A_PEER/128,fd00:9::/64,$ZONE4/32" endpoint "${IP[peer]}:51821" \
  peer "$(cat "$T/stranger.pub")" allowed-ips "$A_STR/128"
x kms ip -6 addr add "$A_KMS/128" dev wg-svc nodad; x kms ip link set wg-svc up
x kms ip -6 route add "$PREFIX" dev wg-svc; x kms ip -6 route add fd00:9::/64 dev wg-svc
x kms sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.wg-svc.rp_filter=0
for h in peer stranger; do
  x "$h" ip link add wg-svc type wireguard
  x "$h" wg set wg-svc listen-port 51821 private-key "$T/$h.key" peer "$(cat "$T/kms.pub")" allowed-ips "$A_KMS/128,${IP[kms]}/32" endpoint "${IP[kms]}:51821"
  x "$h" ip link set wg-svc up
done
x peer ip -6 addr add "$A_PEER/128" dev wg-svc nodad; x peer ip -6 addr add "$OUT6/128" dev wg-svc nodad
x peer ip addr add "$ZONE4/32" dev wg-svc
x peer ip -6 route add "$PREFIX" dev wg-svc
# only what the peer sends FROM the zone address goes to the KMS host's own address through the tunnel;
# WireGuard's own packets keep using the wire
x peer ip rule add from "$ZONE4" table 77; x peer ip route add "${IP[kms]}/32" dev wg-svc table 77
x stranger ip -6 addr add "$A_STR/128" dev wg-svc nodad; x stranger ip -6 route add "$PREFIX" dev wg-svc
x kms python3 -Es "$T/listen.py" tcp6:7444 tcp6:7445 &
x peer python3 -Es "$T/listen.py" tcp6:7444 tcp6:7445 &
sleep 1
from(){ local h="$1" src="$2" dst="$3" port="$4"; x "$h" python3 -I -c "
import socket, sys
try:
    socket.create_connection(('$dst', $port), timeout=2, source_address=('$src', 0)).close(); sys.exit(0)
except OSError:
    sys.exit(1)"; }

# 5.0 controls, with NO ruleset: every path a refusal below relies on really connects
x kms nft delete table inet regalia_kms
from peer "$A_PEER" "$A_KMS" 7444 && P "control: the peer reaches the sync port through the tunnel" || F "control: the tunnel does not carry the sync port"
from peer "$OUT6" "$A_KMS" 7444 && P "control: so does an address outside the tunnel's prefix (WireGuard is told to allow it here)" || F "control: the out-of-prefix path does not connect: its refusal below would prove nothing"
from peer "$A_PEER" "$A_KMS" 7445 && P "control: another port inside the tunnel answers" || F "control: tunnel port 7445 does not answer"
from peer "$ZONE4" "${IP[kms]}" 8443 && P "control: a client-zone address INSIDE the tunnel reaches the KMS port" || F "control: the zone-address path through the tunnel does not connect"
from peer "$ZONE4" "${IP[kms]}" 22 && P "control: and the SSH port" || F "control: the zone-address path to SSH does not connect"
from kms "$A_KMS" "$A_PEER" 7444 && P "control: the KMS host reaches the peer's sync port through the tunnel" || F "control: no outbound path through the tunnel"
from kms "$A_KMS" "$A_PEER" 7445 && P "control: and another port of the peer" || F "control: peer port 7445 does not answer"
tcpok client fd00:5:7::10 7444 && P "control: the sync port answers over IPv6 on the WIRE too (the listener binds every address)" || F "control: no IPv6 path on the wire to the sync port"

cat > "$T/site-mesh.json" <<EOF
{"schema": "regalia.baremetal-site/v1", "site": "lab", "host_ipv4": "${IP[kms]}", "kms_port": 8443, "ssh_port": 22,
 "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["${IP[mon]}/32"], "admin_cidrs": ["203.0.113.0/28"],
 "outbound": [{"name": "audit", "cidr": "${IP[audit]}/32", "proto": "tcp", "port": 6514}],
 "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["${IP[ntp]}/32"]}, {"name": "nts-b.lab", "cidrs": ["203.0.113.195/32"]}]},
 "boot_mesh": {"node_id": "kms", "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443, "nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": null,
               "peers": [{"node_id": "peer", "underlay": "${IP[peer]}", "address": "10.89.0.2"}]},
 "service_mesh": {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444, "authority": null}}
EOF
python3 -Es "$BM/firewall.py" "$T/site-mesh.json" > "$T/mesh.nft" && x kms nft -c -f "$T/mesh.nft" && x kms nft -f "$T/mesh.nft" \
  && P "the ruleset with both meshes renders, passes nft -c and loads inside the KMS namespace" || F "the meshed ruleset did not load"
# Loaded again from an empty ruleset. That does NOT empty connection tracking: a flow opened during the
# controls would still count as established. None is left that matters: each control's TCP connection
# was closed, every check below opens a new one, the peer's WireGuard flow is one the ruleset allows,
# and the stranger has sent nothing yet.
x kms nft flush ruleset >/dev/null 2>&1; x kms nft -f "$T/mesh.nft"

# 5.1 allowed: the sync port, inside the tunnel, between addresses of the prefix, both ways
from peer "$A_PEER" "$A_KMS" 7444 && P "the peer reaches the sync port through the tunnel" || F "the sync port is not reachable through the tunnel"
from kms "$A_KMS" "$A_PEER" 7444 && P "the KMS host reaches the peer's sync port through the tunnel" || F "the KMS host cannot reach the peer's sync port"
# 5.2 denied, each for one reason
from peer "$OUT6" "$A_KMS" 7444 && F "a source outside the tunnel's prefix reached the sync port" || P "wrong source prefix: an address outside the prefix does not reach the sync port, though it came through the tunnel"
from peer "$A_PEER" "$A_KMS" 7445 && F "another port inside the tunnel was reachable" || P "wrong port: nothing but the sync port is reachable inside the tunnel"
tcpok client fd00:5:7::10 7444 && F "the sync port was reachable over IPv6 on the wire" || P "wrong interface: the sync port is not reachable over IPv6 on the wire"
tcpok client "${IP[kms]}" 7444 && F "the sync port was reachable over IPv4 on the wire" || P "wrong interface: nor over IPv4 from a client"
from peer "$ZONE4" "${IP[kms]}" 8443 && F "a client-zone address inside the tunnel reached the KMS port" || P "a zone's address inside the tunnel does not open the KMS port"
from peer "$ZONE4" "${IP[kms]}" 22 && F "a zone address inside the tunnel reached SSH" || P "nor SSH"
tcpok client "${IP[kms]}" 8443 && P "(the same KMS port still answers a client on the wire)" || F "the KMS port no longer answers a client"
from kms "$A_KMS" "$A_PEER" 7445 && F "the KMS host reached another port of the peer through the tunnel" || P "outbound: nothing but the sync port leaves by the tunnel"
# 5.3 a valid key at an undeclared address: no handshake, so nothing at all
from stranger "$A_STR" "$A_KMS" 7444 && F "a node at an undeclared address reached the sync port" || P "a peer with a valid key at an UNDECLARED address gets nothing (its WireGuard packets are dropped)"
hs="$(x kms wg show wg-svc latest-handshakes | awk -v k="$(cat "$T/stranger.pub")" '$1 == k {print $2}')"
[ "${hs:-0}" = 0 ] && P "and the KMS host never completed a handshake with it" || F "a handshake with the undeclared address completed ($hs)"
# ... and the same node, once its address is declared, connects: the refusal above was the address rule
python3 -I - "$T/site-mesh.json" "${IP[stranger]}" > "$T/site-mesh2.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["boot_mesh"]["peers"].append({"node_id": "stranger", "underlay": sys.argv[2], "address": "10.89.0.3"})
json.dump(doc, sys.stdout)
PY
python3 -Es "$BM/firewall.py" "$T/site-mesh2.json" > "$T/mesh2.nft" && x kms nft -f "$T/mesh2.nft"
# WireGuard retries a handshake that went unanswered every few seconds, backing off: give it time
declared=1; for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do from stranger "$A_STR" "$A_KMS" 7444 && { declared=0; break; }; done
[ "$declared" = 0 ] && P "(declared, the same node with the same key connects: the refusal was the address rule's)" || F "the declared node did not connect: the refusal above proves nothing"

echo; echo "baremetal-firewall-netns: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
