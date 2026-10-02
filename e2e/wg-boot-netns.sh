#!/usr/bin/env bash
# wg-boot-netns.sh — the boot mesh, proven by behaviour: who can reach a peer's unlock port at all
# (regalia-kms#66, Phase 6: PoC 6.1, 6.4 and the firewall half of the acceptance criteria).
#
#   sudo e2e/wg-boot-netns.sh
#
# Throwaway network namespaces on one bridge; real WireGuard interfaces; every ruleset is loaded ONLY
# inside a namespace, never on the machine running the test.
#
#   lisbon    the node that boots: interface wg-boot with its WG-BOOT key, the initrd ruleset
#             (bootnet.boot_ruleset), as its initrd would have them. No root filesystem is involved.
#   porto     two running peers: interface wg-unlock with their WG-SERVICE keys (bootnet.peer_wg_conf),
#   faro      the host firewall (firewall.py) with the two boot-mesh openings, and unlock.py's serve()
#             answering on the unlock port. The handler is a stand-in that refuses every request: what
#             is under test is who gets an answer, not what the answer says.
#   outsider  a host on the same network, in no list
#   away      lisbon's own WG-BOOT key, on an address the site never declared: the stolen server,
#             powered on somewhere else (THREE-SITE-THREAT-MODEL.md, attacker case 1)
#
#   0  controls, before any ruleset: every path a later check finds closed is open now, so a refusal
#      below is the configuration's doing. That includes `away`: WireGuard itself accepts a known key
#      from any address.
#   1  the rendered rulesets pass nft -c and load; every chain defaults to drop
#   2  PoC 6.1: lisbon reaches both peers' unlock port through the tunnel
#   3  inside the tunnel there is no SSH, no KMS port, nothing but the unlock port; outside it, lisbon
#      reaches nothing but WireGuard on the peers' declared addresses
#   4  the outsider reaches the unlock port neither at the peer's address nor at its tunnel address
#   5  the stolen server away from its datacenter: a valid key, an undeclared address, no answer
#   6  a revoked node leaves the WireGuard list of the peer that took the manifest, and is still
#      answered by the peer that has not (the window #69 bounds)
#   7  PoC 6.4: packet loss and latency, an unreachable peer, a wrong key: each ends within a bound
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
NS=(lisbon porto faro outsider away)
declare -A IP=([lisbon]=192.0.2.10 [porto]=198.51.100.7 [faro]=198.51.100.9 [outsider]=203.0.113.66 [away]=203.0.113.77)
declare -A TUN=([lisbon]=10.89.0.1 [porto]=10.89.0.2 [faro]=10.89.0.3)
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

# Keys: a WG-BOOT and a WG-SERVICE pair per node, as the manifest lists them (hex), and one for the outsider.
umask 077
for h in lisbon porto faro; do for k in boot service; do wg genkey > "$T/$h.$k.key"; wg pubkey < "$T/$h.$k.key" > "$T/$h.$k.pub"; done; done
wg genkey > "$T/outsider.key"; wg genkey > "$T/wrong.key"

# The manifests (epoch 1: all ACTIVE; epoch 2: lisbon REVOKED_STOLEN), the three site configs, and
# everything rendered from them. The manifest is built here as a fixture; on a host it is the verified
# one from membership.Store.
python3 - "$T" <<'PY' || { echo "wg-boot-netns: rendering failed"; exit 2; }
import base64, json, sys
from deploy.baremetal import bootnet, firewall, sitecfg
from deploy.baremetal import membership as m
T = sys.argv[1]
IP = {"lisbon": "192.0.2.10", "porto": "198.51.100.7", "faro": "198.51.100.9"}
TUN = {"lisbon": "10.89.0.1", "porto": "10.89.0.2", "faro": "10.89.0.3"}
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
                             "outbound": [{"name": "audit", "cidr": "198.18.3.1/32", "proto": "tcp", "port": 6514},
                                          {"name": "ntp", "cidr": "198.18.3.2/32", "proto": "udp", "port": 123}],
                             "boot_mesh": {"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": TUN[node], "unlock_port": 7443,
                                           "peers": [{"node_id": p, "underlay": IP[p], "address": TUN[p]} for p in IP if p != node]}})
m1 = manifest(1, "")
m2 = manifest(2, m.digest(m1), lisbon="REVOKED_STOLEN")
def write(name, text):
    with open("%s/%s" % (T, name), "w") as f:
        f.write(text)
write("lisbon.boot.conf", bootnet.boot_wg_conf(site("lisbon"), m1))
write("lisbon.boot.nft", bootnet.boot_ruleset(site("lisbon"), m1))
write("lisbon.endpoints", json.dumps(bootnet.unlock_endpoints(site("lisbon"), m1), sort_keys=True))
for peer in ("porto", "faro"):
    write(peer + ".unlock.conf", bootnet.peer_wg_conf(site(peer), m1))
    write(peer + ".unlock.revoked.conf", bootnet.peer_wg_conf(site(peer), m2))
    write(peer + ".nft", firewall.render(site(peer)))
PY

# WireGuard. The running peers: wg-unlock, WG-SERVICE key. The booting node: wg-boot, WG-BOOT key.
# apply <namespace> <interface> <rendered configuration> <private key file>: the key is added in memory
# and the whole thing piped to wg (bootnet.with_key): a configuration applied WITHOUT its key unsets it.
apply(){ python3 -c '
import sys
from deploy.baremetal import bootnet
sys.stdout.write(bootnet.with_key(open(sys.argv[1]).read(), open(sys.argv[2]).read()))' "$3" "$4" | x "$1" wg syncconf "$2" /dev/stdin; }
for h in porto faro; do
  x "$h" ip link add wg-unlock type wireguard || { echo "wg-boot-netns: this kernel has no WireGuard"; exit 2; }
  apply "$h" wg-unlock "$T/$h.unlock.conf" "$T/$h.service.key"
  x "$h" ip addr add "${TUN[$h]}/32" dev wg-unlock; x "$h" ip link set wg-unlock up; x "$h" ip route add 10.89.0.0/24 dev wg-unlock
done
boot_up(){ # boot_up <namespace> <private key file>: lisbon's boot interface, in that namespace
  x "$1" ip link del wg-boot 2>/dev/null
  x "$1" ip link add wg-boot type wireguard; apply "$1" wg-boot "$T/lisbon.boot.conf" "$2"
  x "$1" ip addr add "${TUN[lisbon]}/32" dev wg-boot; x "$1" ip link set wg-boot up; x "$1" ip route add 10.89.0.0/24 dev wg-boot
}
boot_up lisbon "$T/lisbon.boot.key"
boot_up away "$T/lisbon.boot.key"            # the same key and configuration, at an address nobody declared
# The outsider: its own key, and a route that puts packets for a peer's tunnel address on the wire.
x outsider ip route add "${TUN[porto]}/32" via "${IP[porto]}" dev eth0 onlink

# Listeners on the peers, all bound to every address: if only the binding kept a port closed, a
# misbound service would open it. The firewall has to.
cat > "$T/serve.py" <<'PY'
import socket, sys, threading
from deploy.baremetal import unlock
class Refusing:                      # stands for unlock.Peer: every request is answered, and refused
    peer_id = "stand-in"
    def handle(self, raw): return {"v": 1, "error": "DENIED"}
    def audit(self, event): pass
def plain(port):
    s = socket.create_server(("0.0.0.0", port))
    while True:
        c, _ = s.accept(); c.close()
for port in (8443, 22, 9999):
    threading.Thread(target=plain, args=(port,), daemon=True).start()
unlock.serve(Refusing(), socket.create_server(("0.0.0.0", int(sys.argv[1]))))
PY
for h in porto faro; do x "$h" env PYTHONPATH="$HERE" python3 "$T/serve.py" "$UNLOCK" & disown; done
x outsider python3 -c "
import socket
s = socket.create_server(('0.0.0.0', 443))
while True:
    c, _ = s.accept(); c.close()" & disown
sleep 1

# asked <namespace> <address> [timeout]: an unlock request gets the peer's answer (its refusal, here).
asked(){ x "$1" env PYTHONPATH="$HERE" python3 -c "
import sys
from deploy.baremetal import unlock
unlock.IO_TIMEOUT = float(sys.argv[2])
try:
    reply = unlock.tcp_transport(sys.argv[1] + ':$UNLOCK')(b'{\"v\":1,\"op\":\"hello\",\"node_id\":\"lisbon\"}')
except OSError:
    sys.exit(1)
sys.exit(0 if reply == b'{\"error\":\"DENIED\",\"v\":1}' else 1)" "$2" "${3:-3}"; }
tcpok(){ x "$1" python3 -c "
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()
except OSError:
    sys.exit(1)" "$2" "$3"; }
shook(){ # shook <peer> <public key file>: the peer has completed a handshake with that key
  x "$1" wg show wg-unlock latest-handshakes | awk -v k="$(cat "$2")" '$1 == k && $2 > 0 { found = 1 } END { exit !found }'; }

hdr "0  controls, before any ruleset: everything a later check finds closed is open now"
asked lisbon "${TUN[porto]}" && asked lisbon "${TUN[faro]}" && P "control: lisbon reaches both peers' unlock port through the tunnel" || F "control: the tunnel does not work at all"
tcpok lisbon "${TUN[porto]}" 22 && tcpok lisbon "${TUN[porto]}" 8443 && tcpok lisbon "${TUN[porto]}" 9999 \
  && P "control: inside the tunnel, SSH, the KMS port and port 9999 of a peer answer" || F "control: the listeners inside the tunnel do not answer"
tcpok lisbon "${IP[porto]}" "$UNLOCK" && tcpok lisbon "${IP[porto]}" 22 && P "control: at the peer's own address, the unlock port and SSH answer" || F "control: the peer's own address does not answer"
tcpok lisbon "${IP[outsider]}" 443 && P "control: lisbon reaches an undeclared host" || F "control: lisbon has no path to the outsider"
tcpok outsider "${IP[porto]}" "$UNLOCK" && P "control: the outsider reaches the unlock port at the peer's address" || F "control: the outsider has no path to the peer"
tcpok outsider "${TUN[porto]}" "$UNLOCK" && P "control: the outsider reaches the peer's tunnel address from outside the tunnel" || F "control: no path to the tunnel address from outside"
asked away "${TUN[porto]}" && shook porto "$T/lisbon.boot.pub" \
  && P "control: WireGuard alone lets lisbon's key in from an address nobody declared" || F "control: the undeclared address does not work even without a firewall"

hdr "1  the rendered rulesets: nft -c, then loaded inside their namespaces only"
for h in porto faro; do
  x "$h" nft -c -f "$T/$h.nft" && x "$h" nft -f "$T/$h.nft" && P "$h: the host firewall with the boot mesh loads" || F "$h: the host firewall does not load"
done
x lisbon nft -c -f "$T/lisbon.boot.nft" && x lisbon nft -f "$T/lisbon.boot.nft" && P "lisbon: the initrd ruleset loads" || F "lisbon: the initrd ruleset does not load"
pol="$(x lisbon nft -j list table inet regalia_boot | python3 -c '
import json, sys
d = json.load(sys.stdin)["nftables"]
print(" ".join(sorted("%s=%s" % (c["chain"]["name"], c["chain"].get("policy")) for c in d if "chain" in c)))')"
[ "$pol" = "forward=drop input=drop output=drop" ] && P "lisbon: every chain defaults to drop" || F "lisbon: policies: $pol"
# A ruleset does not cut a flow that was already established: the controls above left some. A host
# loads its ruleset at boot, before any flow; here the connection tracking table is emptied instead.
for h in lisbon porto faro; do x "$h" conntrack -F >/dev/null 2>&1; done
# And lisbon boots: a new WireGuard session. The control with `away` left porto holding a session with
# that copy of the key, and a node whose session a peer has replaced waits out WireGuard's own timers
# (some 15 s) before it shakes hands again. A boot starts with a handshake.
boot_up lisbon "$T/lisbon.boot.key"
x lisbon nft -f "$T/lisbon.boot.nft"

hdr "2  PoC 6.1: the booting node reaches both peers' unlock port through the tunnel"
for h in porto faro; do
  asked lisbon "${TUN[$h]}" && P "lisbon is answered by $h on the unlock port, inside the tunnel" || F "lisbon is not answered by $h"
done
[ "$(cat "$T/lisbon.endpoints")" = "{\"faro\": \"${TUN[faro]}:$UNLOCK\", \"porto\": \"${TUN[porto]}:$UNLOCK\"}" ] \
  && P "the endpoints for the client's boot configuration are those two" || F "endpoints: $(cat "$T/lisbon.endpoints")"

hdr "3  nothing but the unlock port inside the tunnel, nothing but WireGuard outside it"
for port in 22 8443 9999; do
  tcpok lisbon "${TUN[porto]}" "$port" && F "inside the tunnel, port $port of a peer answered" || P "inside the tunnel, port $port of a peer does not answer"
done
for port in "$UNLOCK" 22 8443; do
  tcpok lisbon "${IP[porto]}" "$port" && F "at the peer's own address, port $port answered lisbon" || P "at the peer's own address, port $port does not answer lisbon"
done
tcpok lisbon "${IP[outsider]}" 443 && F "the booting node reached an undeclared host" || P "the booting node reaches no undeclared host"
tcpok outsider "${IP[lisbon]}" 22 && F "something answered on the booting node" || P "nothing answers on the booting node"

hdr "4  the outsider"
tcpok outsider "${IP[porto]}" "$UNLOCK" && F "the outsider reached the unlock port at the peer's address" || P "the outsider does not reach the unlock port at the peer's address"
tcpok outsider "${TUN[porto]}" "$UNLOCK" && F "the outsider reached the peer's tunnel address from outside the tunnel" || P "the outsider does not reach the peer's tunnel address from outside the tunnel"
x outsider ip link add wg-out type wireguard; x outsider wg set wg-out private-key "$T/outsider.key" peer "$(cat "$T/porto.service.pub")" \
  allowed-ips "${TUN[porto]}/32" endpoint "${IP[porto]}:$WG"
x outsider ip route del "${TUN[porto]}/32"; x outsider ip addr add 10.89.0.9/32 dev wg-out; x outsider ip link set wg-out up; x outsider ip route add "${TUN[porto]}/32" dev wg-out
asked outsider "${TUN[porto]}" 2 && F "a key that is in no manifest got an answer" || P "a key that is in no manifest gets no answer"

hdr "5  the stolen server away from its datacenter: lisbon's key, an undeclared address"
before="$(x porto wg show wg-unlock latest-handshakes | awk -v k="$(cat "$T/lisbon.boot.pub")" '$1 == k { print $2 }')"
sleep 1
asked away "${TUN[porto]}" 4 && F "lisbon's key was answered from an undeclared address" || P "lisbon's key gets no answer from an undeclared address"
asked away "${TUN[faro]}" 4 && F "lisbon's key was answered by the other peer from an undeclared address" || P "nor from the other peer"
asked lisbon "${TUN[porto]}" && P "and from its declared address the same key is still answered" || F "the declared address stopped working"
endpoint="$(x porto wg show wg-unlock endpoints | awk -v k="$(cat "$T/lisbon.boot.pub")" '$1 == k { print $2 }')"
[ "$endpoint" = "${IP[lisbon]}:$(x lisbon wg show wg-boot listen-port)" ] && P "the peer knows that key at its declared address only ($endpoint)" || F "the peer's endpoint for lisbon's key is $endpoint (before: $before)"

hdr "6  revocation: the peer that took the manifest drops the key; the peer that has not still answers"
apply porto wg-unlock "$T/porto.unlock.revoked.conf" "$T/porto.service.key"
x porto wg show wg-unlock peers | grep -qx "$(cat "$T/lisbon.boot.pub")" && F "porto still lists the revoked node's key" || P "porto no longer lists the revoked node's key"
# so that the refusal below is the list's doing: porto still has its own key and still lists the other node
[ "$(x porto wg show wg-unlock private-key)" = "$(cat "$T/porto.service.key")" ] && x porto wg show wg-unlock peers | grep -qx "$(cat "$T/faro.boot.pub")" \
  && P "porto keeps its own key and the other node's" || F "applying the manifest took porto's key or the other node's away"
asked lisbon "${TUN[porto]}" 4 && F "the revoked node was answered by the peer that took the manifest" || P "the revoked node gets no answer from porto"
asked lisbon "${TUN[faro]}" && P "faro, which has not taken the manifest, still answers: the window that the heartbeat bounds (#69)" || F "faro stopped answering without the manifest"
apply porto wg-unlock "$T/porto.unlock.conf" "$T/porto.service.key"
boot_up lisbon "$T/lisbon.boot.key"          # the next boot: porto dropped the old session with the key
asked lisbon "${TUN[porto]}" && P "(the manifest put back for the checks below: at its next boot lisbon is answered by porto again)" || F "porto does not answer after the peer list was restored"

hdr "7  PoC 6.4: loss and latency, an unreachable peer, a wrong key: each ends within a bound"
timed(){ local start=$SECONDS; "$@"; local rc=$?; took=$((SECONDS - start)); return $rc; }
x lisbon tc qdisc add dev eth0 root netem loss 20% delay 100ms || F "netem is not available: the loss and latency case did not run"
ok=0; worst=0
for _ in 1 2 3 4 5; do timed asked lisbon "${TUN[faro]}" 10 && ok=$((ok+1)); [ "$took" -gt "$worst" ] && worst=$took; done
[ "$ok" -ge 4 ] && [ "$worst" -le 12 ] && P "with 20% loss and 100 ms delay: $ok of 5 requests answered, the slowest in ${worst}s" || F "with loss and delay: $ok of 5 answered, the slowest in ${worst}s"
x lisbon tc qdisc del dev eth0 root
x faro ip link set eth0 down
timed asked lisbon "${TUN[faro]}" 3; rc=$?
[ "$rc" != 0 ] && [ "$took" -le 5 ] && P "an unreachable peer: refused after ${took}s, and the other peer is asked" || F "an unreachable peer: rc=$rc after ${took}s"
asked lisbon "${TUN[porto]}" && P "the other peer still answers" || F "the other peer does not answer"
x faro ip link set eth0 up; x faro ip route add default dev eth0 2>/dev/null
# what bootnet.py warns of, shown: a configuration applied without its key leaves the interface with none
x faro wg syncconf wg-unlock "$T/faro.unlock.conf"
[ "$(x faro wg show wg-unlock private-key)" = "(none)" ] && P "measured: wg syncconf with a file that has no PrivateKey unsets the interface's key" \
  || F "wg syncconf without a key did not unset it: bootnet.py's warning is out of date"
boot_up lisbon "$T/wrong.key"
timed asked lisbon "${TUN[porto]}" 3; rc=$?
[ "$rc" != 0 ] && [ "$took" -le 5 ] && P "a wrong WG-BOOT key: no answer, after ${took}s" || F "a wrong key: rc=$rc after ${took}s"
x lisbon ip link del wg-boot
x lisbon ip link show wg-boot >/dev/null 2>&1 && F "the boot interface is still there" || P "the boot interface is removed, as it is when the root filesystem takes over"

echo; echo "wg-boot-netns: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
