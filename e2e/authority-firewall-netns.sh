#!/usr/bin/env bash
# authority-firewall-netns.sh — the revocation authority host's firewall (#324), proven by behaviour, not by reading rules.
#
#   sudo e2e/authority-firewall-netns.sh
#
# Throwaway network namespaces on one bridge: the authority host (its rendered table is loaded ONLY inside its
# namespace, never on the machine running the test), a monitoring host, an admin host, an unauthorized host, the
# audit sink, an NTS server, a node of the manifest and a stranger. Then:
#   0  controls: every listener a refusal below relies on answers before the ruleset
#   1  the table rendered by firewall.render_authority from authority-site and authority.json values and a manifest:
#      nft -c, loaded in the authority's namespace only; every chain defaults to drop
#   2  in: node_exporter (9100) from monitoring only, SSH from admin only, an undeclared port from nobody; WireGuard
#      (UDP 51821) from the node of the manifest, not from a stranger
#   3  out: the audit sink and the NTS server on NTS-KE (TCP 4460) and NTP (UDP 123), nothing else there or anywhere;
#      WireGuard to the node, not to the stranger
#   4  the node marked REVOKED_STOLEN in the next epoch: re-rendered and reloaded, its WireGuard is refused both ways
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ "$(id -u)" = 0 ] || { echo "authority-firewall-netns: run as root (sudo)"; exit 2; }
for t in ip nft python3; do command -v "$t" >/dev/null || { echo "authority-firewall-netns: $t is required (iproute2, nftables)"; exit 2; }; done

T="$(mktemp -d)"; SFX="af$$"
NS=(auth mon admin unauth audit ntp node stranger)
declare -A IP=([auth]=203.0.113.50 [mon]=203.0.113.128 [admin]=203.0.113.4 [unauth]=203.0.113.66
               [audit]=203.0.113.192 [ntp]=203.0.113.193 [node]=192.0.2.10 [stranger]=192.0.2.66)
n(){ echo "$1-$SFX"; }
cleanup(){
  for h in "${NS[@]}"; do ip netns pids "$(n "$h")" 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del "$(n "$h")" 2>/dev/null; done
  ip netns del "sw-$SFX" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT
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

cat > "$T/site.json" <<EOF
{"schema": "regalia.authority-site/v1", "site": "lab-authority", "host_ipv4": "${IP[auth]}", "ssh_port": 22,
 "monitoring_cidrs": ["${IP[mon]}/32"], "admin_cidrs": ["203.0.113.0/28"],
 "outbound": [{"name": "audit", "cidr": "${IP[audit]}/32", "proto": "tcp", "port": 6514}],
 "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["${IP[ntp]}/32"]}, {"name": "nts-b.lab", "cidrs": ["203.0.113.195/32"]}]}}
EOF
render(){   # the table for a node in state $1 (the published manifest's), as regalia-authority-firewall renders it
  (cd "$HERE" && python3 -Es -c "
import json, sys
from deploy.baremetal import firewall, sitecfg
site = sitecfg.load_authority('$T/site.json')
cfg = {'listen_port': 51821, 'sync_port': 7444, 'time_servers': ['nts-a.lab', 'nts-b.lab'], 'underlays': {'a': '${IP[node]}'}}
sys.stdout.write(firewall.render_authority(site, cfg, {'epoch': int(sys.argv[2]), 'nodes': [{'node_id': 'a', 'state': sys.argv[1]}]}))" "$1" "$2")
}

cat > "$T/listen.py" <<'PY'
import socket, sys, threading
def tcp(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", p)); s.listen()
    while True:
        c, _ = s.accept(); c.close()
def udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", p))
    while True:
        d, a = s.recvfrom(64); s.sendto(d, a)
for spec in sys.argv[1:]:
    proto, port = spec.split(":"); threading.Thread(target={"tcp": tcp, "udp": udp}[proto], args=(int(port),), daemon=True).start()
threading.Event().wait()
PY
x auth python3 -Es "$T/listen.py" tcp:9100 tcp:22 tcp:9999 udp:51821 &
x audit python3 -Es "$T/listen.py" tcp:6514 tcp:7000 &
x ntp python3 -Es "$T/listen.py" udp:123 udp:124 tcp:4460 tcp:4461 &
x node python3 -Es "$T/listen.py" udp:51821 &
x stranger python3 -Es "$T/listen.py" udp:51821 tcp:443 &
sleep 1
tcpok(){ x "$1" python3 -I -c "
import socket, sys
try:
    socket.create_connection(('$2', $3), timeout=1).close(); sys.exit(0)
except OSError:
    sys.exit(1)"; }
udpok(){ x "$1" python3 -I -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(b'x', ('$2', $3)); s.recvfrom(64); sys.exit(0)
except OSError:
    sys.exit(1)"; }

hdr "0  controls: before the ruleset every listener answers (so a later refusal is the firewall's)"
for probe in "unauth ${IP[auth]} 9100" "unauth ${IP[auth]} 22" "unauth ${IP[auth]} 9999" "auth ${IP[audit]} 7000" "auth ${IP[ntp]} 4461" "auth ${IP[stranger]} 443"; do
  read -r h dst port <<< "$probe"
  tcpok "$h" "$dst" "$port" && P "control: $h reaches $dst:$port/tcp" || F "control: $dst:$port/tcp does not answer: its refusal below would prove nothing"
done
for probe in "auth ${IP[ntp]} 124" "auth ${IP[stranger]} 51821" "stranger ${IP[auth]} 51821"; do
  read -r h dst port <<< "$probe"
  udpok "$h" "$dst" "$port" && P "control: $h reaches $dst:$port/udp" || F "control: $dst:$port/udp does not answer: its refusal below would prove nothing"
done

hdr "1  the rendered table: nft -c, then loaded in the authority's namespace only"
render ACTIVE 4 > "$T/auth.nft" && P "rendered (node a ACTIVE, epoch 4)" || F "render failed"
x auth nft -c -f "$T/auth.nft" && P "nft -c accepts it" || F "nft -c refuses it"
x auth nft -f "$T/auth.nft" && P "loaded inside the authority's namespace" || F "load failed"
pol="$(x auth nft -j list table inet regalia_authority | python3 -I -c '
import json, sys
d = json.load(sys.stdin)["nftables"]
print(" ".join(sorted("%s=%s" % (c["chain"]["name"], c["chain"].get("policy")) for c in d if "chain" in c)))')"
[ "$pol" = "forward=drop input=drop output=drop" ] && P "every chain defaults to drop ($pol)" || F "policies: $pol"

hdr "2  in: each opening from its zone, nothing else"
tcpok mon "${IP[auth]}" 9100 && P "node_exporter from monitoring" || F "monitoring cannot reach node_exporter"
for h in admin unauth; do ! tcpok "$h" "${IP[auth]}" 9100 && P "node_exporter refused from $h" || F "node_exporter reachable from $h"; done
tcpok admin "${IP[auth]}" 22 && P "SSH from admin" || F "admin cannot reach SSH"
for h in mon unauth; do ! tcpok "$h" "${IP[auth]}" 22 && P "SSH refused from $h" || F "SSH reachable from $h"; done
for h in mon admin unauth; do ! tcpok "$h" "${IP[auth]}" 9999 && P "an undeclared port refused from $h" || F "port 9999 reachable from $h"; done
udpok node "${IP[auth]}" 51821 && P "WireGuard from the node of the manifest" || F "the node cannot reach the authority's WireGuard"
! udpok stranger "${IP[auth]}" 51821 && P "WireGuard refused from a stranger" || F "a stranger reaches the authority's WireGuard"

hdr "3  out: the audit sink and NTS only, and WireGuard to the node"
tcpok auth "${IP[audit]}" 6514 && P "the audit sink" || F "the audit sink is unreachable"
! tcpok auth "${IP[audit]}" 7000 && P "another port of the audit host refused" || F "audit:7000 reachable"
tcpok auth "${IP[ntp]}" 4460 && P "NTS-KE to the NTS server" || F "NTS-KE unreachable"
udpok auth "${IP[ntp]}" 123 && P "NTP to the NTS server" || F "NTP unreachable"
! tcpok auth "${IP[ntp]}" 4461 && P "another TCP port of the NTS server refused" || F "ntp:4461 reachable"
! udpok auth "${IP[ntp]}" 124 && P "another UDP port of the NTS server refused" || F "ntp:124/udp reachable"
! tcpok auth "${IP[stranger]}" 443 && P "an undeclared destination refused" || F "the authority reaches an undeclared host"
udpok auth "${IP[node]}" 51821 && P "WireGuard to the node of the manifest" || F "the authority cannot reach the node's WireGuard"
! udpok auth "${IP[stranger]}" 51821 && P "WireGuard to a stranger refused" || F "the authority reaches a stranger's WireGuard port"

hdr "4  the node marked stolen in the next epoch: re-rendered, reloaded, refused both ways"
render REVOKED_STOLEN 5 > "$T/auth5.nft" && x auth nft -f "$T/auth5.nft" && P "epoch 5 rendered and loaded" || F "epoch 5 failed"
! udpok node "${IP[auth]}" 51821 && P "the stolen node's WireGuard is refused" || F "the stolen node still reaches the authority"
! udpok auth "${IP[node]}" 51821 && P "the authority no longer sends WireGuard to it" || F "the authority still reaches the stolen node"
tcpok mon "${IP[auth]}" 9100 && P "control: the rest of the table is unchanged (monitoring still scrapes)" || F "epoch 5 broke the rest of the table"

echo; echo "authority-firewall-netns: $pass passed, $fail failed"
[ "$fail" = 0 ]
