"""Trusted host orchestration; prints only sanitized software-lab evidence."""

import hashlib
import ipaddress
import json
import os
import subprocess
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NODES = "ABC"
PROJECT = f"regalia-bootstrap-mesh-{os.getpid()}"
COMPOSE = ["docker", "compose", "--project-name", PROJECT, "--file", str(ROOT / "compose.network.yaml")]


def command(*args, data=None, required=True, timeout=120):
    result = subprocess.run([*COMPOSE, *args], input=data, capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError(f"mesh command {args[0]} failed (exit {result.returncode})")
    return result


def control(node, op, **fields):
    result = command("exec", "-T", "--user", "10000:10000", node.lower(),
                     "python3", "/opt/network.py", "control",
                     data=json.dumps(dict(fields, op=op)).encode())
    return json.loads(result.stdout)["result"]


def admin(node, *args):
    return command("exec", "-T", "--user", "0:0", node.lower(), *args)


def probe(node, host, port, payload, raw=False, content_length=None, route="/bootstrap"):
    code = '''import http.client,json,sys
c=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=1)
try:
 if sys.argv[4]:
  c.putrequest("POST",sys.argv[5])
  c.putheader("Content-Length",sys.argv[4]); c.endheaders()
 else:
  c.request("POST",sys.argv[5],body=sys.argv[3],headers={"Content-Type":"application/json"})
 r=c.getresponse(); raw=r.read(65537)
 print(json.dumps({"reachable":True,"response":json.loads(raw)}))
except OSError:
 print(json.dumps({"reachable":False}))
finally:
 c.close()
'''
    return json.loads(command("exec", "-T", "--user", "10000:10000", node.lower(),
                              "python3", "-c", code, host, str(port), payload if raw else json.dumps(payload),
                              "" if content_length is None else str(content_length), route).stdout)


def underlay_spoof_case(plane="bootstrap"):
    """A conntracked overlay tuple must not be accepted from the physical bridge."""
    prefix = {"bootstrap": "10.77.91", "service": "10.78.91"}[plane]
    interface, subnet = "wg-" + plane, prefix + ".0/24"
    source, target = prefix + ".1", prefix + ".2"
    tag = "regalia-underlay-" + os.urandom(8).hex()
    ready, seen = "/tmp/" + tag + ".ready", "/tmp/" + tag + ".seen"
    port = 49152
    server = '''import os,pathlib,socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[3],49152));s.settimeout(.2)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
deadline=time.monotonic()+30
try:
 while time.monotonic()<deadline:
  try: data,peer=s.recvfrom(64)
  except socket.timeout: continue
  if data not in (b"encrypted-control",b"underlay-probe"): continue
  with open(sys.argv[2],"ab") as record: record.write(data+b"\\n")
  s.sendto(data,peer)
finally: s.close()
'''
    client = '''import json,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[3],int(sys.argv[1])));s.settimeout(1)
port=s.getsockname()[1];data=sys.argv[2].encode()
try:
 s.sendto(data,(sys.argv[4],49152)); ok=s.recvfrom(64)[0]==data
except OSError: ok=False
finally: s.close()
print(json.dumps({"reply":ok,"port":port}))
'''
    cleanup_process = '''import os,pathlib,signal,sys
p=pathlib.Path(sys.argv[1])
if p.exists():
 pid=int(p.read_text()); assert pid>1
 cmd=pathlib.Path(f"/proc/{pid}/cmdline")
 if cmd.exists() and sys.argv[1].encode() in cmd.read_bytes(): os.kill(pid,signal.SIGTERM)
for name in sys.argv[1:]: pathlib.Path(name).unlink(missing_ok=True)
'''
    routes = []
    attack_network = PROJECT + "-spoof"
    connected = []
    network_created = False
    try:
        # Only the temporary echo fixture gains a UDP exception. Main bootstrap
        # endpoints and service capabilities remain unchanged.
        for node in "AB":
            for chain, direction, address_side in [("input", "iifname", "saddr"), ("output", "oifname", "daddr")]:
                admin(node, "nft", "add", "rule", "inet", "lab", chain, direction, interface,
                      "ip", address_side, subnet, "udp", "dport", str(port), "accept", "comment", tag)
        command("exec", "--detach", "--user", "0:0", "b", "python3", "-c", server, ready, seen, target)
        for _ in range(30):
            if command("exec", "-T", "--user", "0:0", "b", "test", "-f", ready,
                       required=False).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError("underlay echo fixture did not start")
        control_result = json.loads(admin("A", "python3", "-c", client, "0", "encrypted-control", source, target).stdout)
        if not control_result["reply"]:
            raise RuntimeError("encrypted control failed; a dropped probe would prove nothing")
        # Docker's internal bridge can itself discard packets carrying overlay
        # addresses. A second unpublished bridge gives this fixture a controlled
        # underlay path. Every node keeps its existing default-deny firewall.
        subprocess.run(["docker", "network", "create", attack_network], check=True, capture_output=True, timeout=30)
        network_created = True
        data = json.loads(subprocess.run(["docker", "network", "inspect", attack_network],
                          check=True, capture_output=True, timeout=30).stdout)[0]
        attack_subnet = ipaddress.IPv4Network(data["IPAM"]["Config"][0]["Subnet"])
        attack_addresses = {node: str(attack_subnet.network_address + index) for index, node in enumerate("AB", 2)}
        for node in "AB":
            container = command("ps", "--quiet", node.lower()).stdout.decode().strip()
            subprocess.run(["docker", "network", "connect", "--ip", attack_addresses[node],
                            attack_network, container], check=True, capture_output=True, timeout=30)
            connected.append(container)
        for node, overlay, peer in [("A", target, "B"), ("B", source, "A")]:
            admin(node, "ip", "route", "add", overlay + "/32", "via", attack_addresses[peer], "dev", "eth1")
            routes.append((node, overlay))
        # The attacker fixture may transmit its one exact tuple in plaintext.
        # This bypasses only the sender's policy, so receiver INPUT is measured.
        admin("A", "nft", "insert", "rule", "inet", "lab", "output", "oifname", "eth1",
              "ip", "saddr", source, "ip", "daddr", target, "udp", "sport",
              str(control_result["port"]), "udp", "dport", str(port), "accept", "comment", tag)
        admin("B", "nft", "insert", "rule", "inet", "lab", "input", "iifname", "eth1",
              "ip", "daddr", target, "udp", "dport", str(port), "counter", "comment", tag)
        probe_result = json.loads(admin("A", "python3", "-c", client,
                                        str(control_result["port"]), "underlay-probe", source, target).stdout)
        table = json.loads(admin("B", "nft", "--json", "list", "table", "inet", "lab").stdout)
        arrivals = sum(expr["counter"]["packets"] for item in table["nftables"]
                       if "rule" in item and item["rule"].get("comment") == tag
                       for expr in item["rule"]["expr"] if "counter" in expr)
        delivered = b"underlay-probe" in admin("B", "cat", seen).stdout
        return {"plane": plane, "encrypted_control": True, "underlay_arrived": arrivals > 0,
                "underlay_delivered": delivered, "underlay_reply": probe_result["reply"]}
    finally:
        try:
            for node, overlay in reversed(routes):
                admin(node, "ip", "route", "del", overlay + "/32")
            for node in "AB":
                table = json.loads(admin(node, "nft", "--json", "list", "table", "inet", "lab").stdout)
                for item in table["nftables"]:
                    rule = item.get("rule", {})
                    if rule.get("comment") == tag:
                        admin(node, "nft", "delete", "rule", "inet", "lab", rule["chain"], "handle", str(rule["handle"]))
            # The fixture is root-owned, bounded, and identified by its unique argv.
            admin("B", "python3", "-c", cleanup_process, ready, seen)
        finally:
            for container in reversed(connected):
                subprocess.run(["docker", "network", "disconnect", attack_network, container],
                               check=False, capture_output=True, timeout=30)
            if network_created:
                subprocess.run(["docker", "network", "rm", attack_network], check=True, capture_output=True, timeout=30)



def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    report = {"schema_version": 1, "evidence_class": "emulated-network",
              "timestamp": datetime.now(timezone.utc).isoformat(), "status": "failed", "checks": [],
              "source_commit": os.environ.get("REGALIA_LAB_COMMIT", "unknown"),
              "platform": os.environ["REGALIA_LAB_PLATFORM"],
              "swtpm_seccomp": os.environ["REGALIA_LAB_SWTPM_SECCOMP"],
              "image_id": os.environ["REGALIA_LAB_IMAGE_ID"],
              "sources_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                 for name in ["lab.py", "peer.py", "network.py", "mesh.py", "compose.network.yaml", "Dockerfile"]}}

    def check(name, passed):
        report["checks"].append({"name": name, "status": "passed" if passed else "failed"})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise RuntimeError("mesh assertion failed")

    try:
        command("up", "--detach", "--no-build", "--pull", "never")
        identities = {}
        for node in NODES:
            for _ in range(60):
                try:
                    identities[node] = control(node, "identity")
                    break
                except RuntimeError:
                    time.sleep(0.5)
            else:
                raise RuntimeError(f"node {node} startup timed out")
            check(f"{node} service has no effective capabilities", identities[node]["uid"] == 10000
                  and int(identities[node]["caps"], 16) == 0)
        for node in NODES:
            for peer in NODES:
                if node == peer:
                    continue
                index = NODES.index(peer) + 1
                admin(node, "wg", "set", "wg-bootstrap", "peer", identities[peer]["wg_public"],
                      "allowed-ips", f"10.77.91.{index}/32", "endpoint", f"10.89.91.{index}:51820",
                      "persistent-keepalive", "1")
        signing = {}
        for node in NODES:
            targets = {peer: {field: identities[peer][field] for field in ["ak_pem", "approved_pcr"]}
                       for peer in NODES if peer != node}
            signing[node] = control(node, "enroll", targets=targets)["peer_public_key"]
        for node in NODES:
            control(node, "pins", pins={peer: signing[peer] for peer in NODES if peer != node})
        isolation = underlay_spoof_case()
        report["underlay_isolation"] = isolation
        check("spoof fixture proves encrypted connectivity and underlay arrival",
              isolation["encrypted_control"] and isolation["underlay_arrived"])
        check("established overlay tuple cannot arrive through the underlay",
              not isolation["underlay_delivered"] and not isolation["underlay_reply"])
        recovery = {node: control(node, "disk")["recovery_key"] for node in NODES}
        check("all three disposable LUKS images are commissioned over WireGuard", len(recovery) == 3)
        for node in NODES:
            for peer in NODES:
                if node == peer:
                    continue
                control(node, "lock")
                check(f"{peer} bootstraps {node} over WireGuard",
                      control(node, "bootstrap", peers=[peer]) == {"active": True, "via": peer})
        for node in NODES:
            control(node, "lock")
            result = control(node, "bootstrap", peers=[peer for peer in NODES if peer != node])
            check(f"either available peer restores {node}", result["active"] and result["via"] != node)
        for survivor in NODES:
            locked = [node for node in NODES if node != survivor]
            for node in locked:
                control(node, "lock")
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda node: control(node, "bootstrap", peers=[survivor]), locked))
            check(f"{survivor} concurrently restores both other nodes",
                  all(result == {"active": True, "via": survivor} for result in results))
        for first in NODES:
            for node in NODES:
                control(node, "lock")
            for node in NODES:
                result = control(node, "bootstrap", peers=[peer for peer in NODES if peer != node])
                check(f"total outage before manual {first}: {node} stays locked", not result["active"])
            check(f"wrong recovery credential cannot seed {first}",
                  not control(first, "manual", key=os.urandom(64).hex())["active"])
            check(f"manual LUKS recovery seeds {first}", control(first, "manual", key=recovery[first])["active"])
            for node in NODES:
                if node == first:
                    continue
                check(f"manually recovered {first} restores {node}",
                      control(node, "bootstrap", peers=[first]) == {"active": True, "via": first})
        for node in NODES:
            handshakes = admin(node, "wg", "show", "wg-bootstrap", "latest-handshakes").stdout.decode().splitlines()
            check(f"{node} has actual WireGuard handshakes with both peers", len(handshakes) == 2
                  and all(int(line.split()[1]) > 0 for line in handshakes))
        check("cleartext bootstrap is blocked on the bridge", not probe("A", "10.89.91.2", 8443,
              {"op": "challenge", "node_id": "A"})["reachable"])
        check("peer cannot access local fixture control", not probe("A", "10.77.91.2", 9444,
              {"op": "identity"})["reachable"])
        check("WireGuard identity cannot substitute another node ID", probe("A", "10.77.91.2", 8443,
              {"op": "challenge", "node_id": "C"})["response"] == {"error": {"code": "DENIED"}})
        check("bootstrap endpoint refuses remote commissioning", probe("A", "10.77.91.2", 8443,
              {"op": "init"})["response"] == {"error": {"code": "DENIED"}})
        check("network endpoint rejects malformed node identity", probe("A", "10.77.91.2", 8443,
              {"op": "challenge", "node_id": []})["response"] == {"error": {"code": "INVALID_REQUEST"}})
        admin("B", "ip", "link", "set", "wg-bootstrap", "down")
        started = time.monotonic()
        result = control("A", "bootstrap", peers=["B", "C"])
        elapsed = time.monotonic() - started
        check("reachable C restores A without waiting for unreachable B", result == {"active": True, "via": "C"}
              and elapsed < 3.5)
        admin("C", "ip", "link", "set", "wg-bootstrap", "down")
        check("both unreachable peers leave A locked", not control("A", "bootstrap", peers=["B", "C"])["active"])
        for node in "BC":
            admin(node, "ip", "link", "set", "wg-bootstrap", "up")

        def restored(node, peers):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                result = control(node, "bootstrap", peers=peers)
                if result["active"]:
                    return True
                time.sleep(0.2)
            return False

        check("healed network restores A autonomously", restored("A", ["B", "C"]))
        admin("A", "ip", "route", "add", "unreachable", "10.77.91.2/32")
        check("wrong route refuses the selected peer", not control("A", "bootstrap", peers=["B"])["active"])
        check("other peer survives a wrong route", control("A", "bootstrap", peers=["B", "C"]) == {"active": True, "via": "C"})
        admin("A", "ip", "route", "del", "10.77.91.2/32")
        admin("B", "wg", "set", "wg-bootstrap", "peer", identities["A"]["wg_public"], "remove")
        check("missing WireGuard peer identity blocks bootstrap", not control("A", "bootstrap", peers=["B"])["active"])
        admin("B", "wg", "set", "wg-bootstrap", "peer", identities["A"]["wg_public"],
              "allowed-ips", "10.77.91.1/32", "endpoint", "10.89.91.1:51820", "persistent-keepalive", "1")
        check("restored WireGuard enrollment restores A", restored("A", ["B"]))
        control("B", "drop_response")
        check("lost grant leaves target locked", not control("A", "bootstrap", peers=["B"])["active"])
        check("fresh challenge recovers after a lost grant", control("A", "bootstrap", peers=["B"])["active"])
        # Reject from headers before a body is sent. Sending unread oversized
        # bytes while the server closes can reset TCP and hide its error reply.
        check("network endpoint rejects oversized length before reading a body", probe("A", "10.77.91.2", 8443,
              {}, content_length=65537).get("response")
              == {"error": {"code": "INVALID_REQUEST"}})
        boundary = json.dumps({"op": "challenge", "node_id": "A"})
        padded = boundary + " " * (65536 - len(boundary))
        response = probe("A", "10.77.91.2", 8443, padded, raw=True).get("response", {})
        challenge = response.get("result", {})
        check("network endpoint accepts a valid body at the exact input limit",
              set(response) == {"result"} and set(challenge) == {
                  "peer_id", "peer_nonce", "manifest_epoch", "challenge_id"}
              and challenge["peer_id"] == "B")
        check("network endpoint refuses duplicate JSON fields", probe("A", "10.77.91.2", 8443,
              '{"op":"challenge","node_id":"A","node_id":"C"}', raw=True)["response"]
              == {"error": {"code": "INVALID_REQUEST"}})

        def policy(states, epoch=1, nodes=NODES):
            for node in nodes:
                control(node, "policy", nodes=states, epoch=epoch)

        active = {node: "ACTIVE" for node in NODES}
        revoked_a = dict(active, A="REVOKED_STOLEN")
        policy(revoked_a, epoch=2, nodes="BC")
        check("current peers refuse a revoked requester with a stale local view",
              not control("A", "bootstrap", peers=["B", "C"])["active"])
        # Reproduce the freshness gap; this is an observed limitation, not a security pass.
        policy(active, epoch=1, nodes="B")
        stale = control("A", "bootstrap", peers=["B"])["active"]
        report["limitations_observed"] = {"stale_target_and_authorizer_can_bootstrap": stale}
        check("stale membership authorization risk is reproduced", stale)
        policy(dict(active, B="REVOKED_STOLEN"), epoch=2, nodes="A")
        check("target refuses a locally revoked authorizer even if that peer is stale",
              not control("A", "bootstrap", peers=["B"])["active"])
        policy(active, epoch=2, nodes="C")
        check("current non-revoked peer restores target", control("A", "bootstrap", peers=["C"])["active"])
        policy(active, epoch=2, nodes="A")
        check("target refuses a known older peer epoch", not control("A", "bootstrap", peers=["B"])["active"])
        policy(active, epoch=2)
        check("matching current epochs restore target", control("A", "bootstrap", peers=["B"])["active"])
        maintenance = dict(active, A="MAINTENANCE")
        policy(maintenance, epoch=3)
        check("MAINTENANCE node can receive bootstrap", control("A", "bootstrap", peers=["B"])["active"])
        check("MAINTENANCE node cannot authorize another node", not control("B", "bootstrap", peers=["A"])["active"])
        check("ACTIVE peer recovers the remaining node", control("B", "bootstrap", peers=["C"])["active"])
        policy(active, epoch=4)
        if os.environ.get("REGALIA_LAB_GUEST") == "1":
            report["evidence_class"] = "emulated-guest-boot"
            for name in ["vm.py", "guest.py", "guest-init.sh", "root-init.sh"]:
                report["sources_sha256"][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            control("A", "lock")
            admin("A", "ip", "link", "set", "wg-bootstrap", "down")
            control("A", "guest_prepare")
            fixture = {"epoch": 4, "selected": ["B"], "peers": {
                peer: {"wg_public": identities[peer]["wg_public"], "signing_public": signing[peer]} for peer in "BC"}}
            report["guest_boots"] = []

            def boot(selected, *options, restart=True):
                if restart:
                    control("A", "tpm_restart")
                fixture["selected"] = selected
                result = command("exec", "-T", "--user", "10000:10000", "a", "python3", "/opt/vm.py", *options,
                                 data=(json.dumps(fixture) + "\n").encode(), timeout=300)
                record = json.loads(result.stdout)
                report["guest_boots"].append(dict(record, selected=selected, options=list(options)))
                if record["exit_code"] != 0 or record["diagnostics"]:
                    raise RuntimeError("guest emulator or dependency failure")
                return record

            surveyed = boot(["B"], "--survey", restart=False)
            measured = surveyed["pcr7"]
            check("guest firmware PCR survey completes with disk closed",
                  isinstance(measured, str) and len(measured) == 64 and "REGALIA_MEASUREMENT_SURVEY_COMPLETE" in surveyed["markers"]
                  and "REGALIA_UNLOCK_REFUSED_ROOT_CLOSED" in surveyed["markers"])
            control("A", "tpm_restart")
            control("A", "guest_rebind", pcr7=measured)
            for node in "BC":
                control(node, "guest_approve", pcr7=measured)
            for index, peer in enumerate("BCB"):
                record = boot([peer], *( ["--format"] if index == 0 else []))
                check(f"cold guest boot {index + 1}: {peer} opens dm-crypt and encrypted root",
                      record["pcr7"] == measured and "REGALIA_PEER_AUTHORIZED_" + peer in record["markers"]
                      and "REGALIA_DISK_OPENED" in record["markers"] and "REGALIA_ENCRYPTED_ROOT_BOOTED" in record["markers"])
            report["guest_kernel"] = record["kernel"]
            for node in "BC":
                control(node, "lock")
            record = boot(["B", "C"])
            check("cold guest cannot unlock without an active peer", "REGALIA_PEER_DENIED_B" in record["markers"]
                  and "REGALIA_PEER_DENIED_C" in record["markers"] and "REGALIA_UNLOCK_REFUSED_ROOT_CLOSED" in record["markers"]
                  and "REGALIA_DISK_OPENED" not in record["markers"])
            control("B", "manual", key=recovery["B"])
            record = boot(["B", "C"])
            check("one manual peer recovery restores an encrypted-root guest", "REGALIA_ENCRYPTED_ROOT_BOOTED" in record["markers"]
                  and "REGALIA_PEER_AUTHORIZED_B" in record["markers"])
            control("C", "manual", key=recovery["C"])
            policy(revoked_a, epoch=5, nodes="BC")
            record = boot(["B", "C"])
            check("current revoked-target policy keeps cold guest disk closed", "REGALIA_PEER_DENIED_B" in record["markers"]
                  and "REGALIA_PEER_DENIED_C" in record["markers"] and "REGALIA_UNLOCK_REFUSED_ROOT_CLOSED" in record["markers"]
                  and "REGALIA_DISK_OPENED" not in record["markers"])
            policy(active, epoch=6, nodes="BC")
            fixture["epoch"] = 6
            record = boot(["B"], "--tamper-pcr")
            check("unexpected guest PCR state blocks local release and disk unlock", "REGALIA_UNSEAL_POLICY_REFUSED" in record["markers"]
                  and "REGALIA_UNLOCK_REFUSED_ROOT_CLOSED" in record["markers"] and "REGALIA_DISK_OPENED" not in record["markers"])
            record = boot(["B"], "--modified-initramfs")
            not_bound = (record["pcr7"] == measured and "REGALIA_MODIFIED_INITRAMFS_EXECUTED" in record["markers"]
                         and "REGALIA_ENCRYPTED_ROOT_BOOTED" in record["markers"])
            report["limitations_observed"]["guest_pcr7_does_not_bind_initramfs"] = not_bound
            check("PCR 7 initramfs coverage gap is reproduced", not_bound)
        else:
            control("A", "extend_pcr")
            check("changed target PCR prevents bootstrap despite healthy reachable peers",
                  control("A", "bootstrap", peers=["B", "C"]) == {"active": False, "reason": "local_policy"})
        report["packages"] = command("exec", "-T", "a", "cat", "/opt/packages.tsv").stdout.decode().splitlines()
        report["status"] = "passed"
    finally:
        cleanup = command("down", "--volumes", "--remove-orphans", required=False)
        report["cleanup"] = "passed" if cleanup.returncode == 0 else "failed"
        if cleanup.returncode:
            report["status"] = "failed"
        filename = "vm-report.json" if os.environ.get("REGALIA_LAB_GUEST") == "1" else "network-report.json"
        (ROOT / ".artifacts" / filename).write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError("mesh run failed")


if __name__ == "__main__":
    main()
