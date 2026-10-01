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
#   3  outbound: the KMS host reaches the audit sink (TCP) and the NTP sink (UDP), and nothing else
#   4  the rendered file passes nft -c and loads; forward and IPv6 are dropped
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; BM="$HERE/deploy/baremetal"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ "$(id -u)" = 0 ] || { echo "baremetal-firewall-netns: run as root (sudo)"; exit 2; }
for t in ip nft python3; do command -v "$t" >/dev/null || { echo "baremetal-firewall-netns: $t is required (iproute2, nftables)"; exit 2; }; done

T="$(mktemp -d)"; SFX="bm$$"
NS=(kms client mon admin unauth audit ntp)
declare -A IP=([kms]=192.0.2.10 [client]=198.51.100.20 [mon]=203.0.113.128 [admin]=203.0.113.4
               [unauth]=203.0.113.66 [audit]=203.0.113.192 [ntp]=203.0.113.193)
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

cat > "$T/site.json" <<EOF
{"schema": "regalia.baremetal-site/v1", "site": "lab", "host_ipv4": "${IP[kms]}", "kms_port": 8443, "ssh_port": 22,
 "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["${IP[mon]}/32"], "admin_cidrs": ["203.0.113.0/28"],
 "outbound": [{"name": "audit", "cidr": "${IP[audit]}/32", "proto": "tcp", "port": 6514},
              {"name": "ntp", "cidr": "${IP[ntp]}/32", "proto": "udp", "port": 123}]}
EOF

# Listeners: a TCP server answers on each port given; a UDP echo answers one datagram.
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
    proto, port = spec.split(":"); threading.Thread(target=tcp if proto == "tcp" else udp, args=(int(port),), daemon=True).start()
threading.Event().wait()
PY
x kms python3 "$T/listen.py" tcp:8443 tcp:22 tcp:9999 &
x audit python3 "$T/listen.py" tcp:6514 tcp:7000 &
x ntp python3 "$T/listen.py" udp:123 udp:124 &
x unauth python3 "$T/listen.py" tcp:6514 tcp:443 &
sleep 1

tcpok(){ local h="$1" dst="$2" port="$3"; x "$h" python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(1)
try:
    s.connect(('$dst', $port)); sys.exit(0)
except OSError:
    sys.exit(1)"; }
udpok(){ x kms python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(b'x', ('${IP[ntp]}', $1)); s.recvfrom(64); sys.exit(0)
except OSError:
    sys.exit(1)"; }
hdr "0  control: before the ruleset, the lab really connects (so a later refusal is the firewall's)"
tcpok unauth "${IP[kms]}" 9999 && P "port 9999 on the KMS host is reachable before the ruleset" || F "the lab cannot connect at all: every refusal below would prove nothing"
tcpok kms "${IP[unauth]}" 443 && P "the KMS host reaches an undeclared host before the ruleset" || F "outbound control failed"
# Every listener a negative check below relies on must answer now; a listener that failed to bind would
# otherwise make "not reachable" pass whatever the firewall does.
tcpok kms "${IP[audit]}" 7000 && P "control: audit:7000 answers before the ruleset" || F "control: audit:7000 not listening"
tcpok kms "${IP[unauth]}" 6514 && P "control: unauth:6514 answers before the ruleset" || F "control: unauth:6514 not listening"
udpok 124 && P "control: ntp:124/udp answers before the ruleset" || F "control: ntp:124/udp not listening"

hdr "4  the rendered ruleset: nft -c, then loaded in the KMS namespace only"
python3 "$BM/firewall.py" "$T/site.json" > "$T/kms.nft" && P "rendered" || F "render failed"
x kms nft -c -f "$T/kms.nft" && P "nft -c accepts it" || F "nft -c refuses it"
x kms nft -f "$T/kms.nft" && P "loaded inside the KMS namespace" || F "load failed"
pol="$(x kms nft -j list table inet regalia_kms | python3 -c '
import json, sys
d = json.load(sys.stdin)["nftables"]
print(" ".join(sorted("%s=%s" % (c["chain"]["name"], c["chain"].get("policy")) for c in d if "chain" in c)))')"
[ "$pol" = "forward=drop input=drop output=drop" ] && P "every chain defaults to drop ($pol)" || F "policies: $pol"

hdr "1  network_probe.py from each zone"
for role in client:client monitoring:mon admin:admin unauthorized:unauth; do
  r="${role%%:*}"; h="${role##*:}"
  out="$(x "$h" python3 "$BM/network_probe.py" "$T/site.json" --role "$r" --source-ip "${IP[$h]}" --timeout 1)"; rc=$?
  [ "$rc" = 0 ] && P "$r: matrix matches the config" || F "$r (rc=$rc): $out"
done
out="$(x client python3 "$BM/network_probe.py" "$T/site.json" --role admin --source-ip "${IP[client]}" 2>&1)"; rc=$?
[ "$rc" = 2 ] && P "a probe claiming a zone it is not in is refused (exit 2)" || F "role/source mismatch rc=$rc"

hdr "2  an undeclared port on the KMS host is reachable from nowhere"
for h in client mon admin unauth; do
  tcpok "$h" "${IP[kms]}" 9999 && F "$h reached port 9999" || P "$h cannot reach port 9999"
done

hdr "3  outbound: only the declared sinks"
tcpok kms "${IP[audit]}" 6514 && P "audit sink 6514/tcp reachable" || F "audit sink unreachable"
tcpok kms "${IP[audit]}" 7000 && F "the audit host on an undeclared port was reachable" || P "the audit host on another port is not"
tcpok kms "${IP[unauth]}" 6514 && F "an undeclared host was reachable" || P "an undeclared host (even on 6514) is not"
tcpok kms "${IP[unauth]}" 443 && F "an undeclared host:443 was reachable" || P "an undeclared host on 443 is not"
udpok 123 && P "NTP sink 123/udp reachable" || F "NTP sink unreachable"
udpok 124 && F "the NTP host on an undeclared UDP port was reachable" || P "the NTP host on another UDP port is not"

echo; echo "baremetal-firewall-netns: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
