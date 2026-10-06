#!/usr/bin/env python3
"""The fence step (G1, ADR-0002 D32, #432): the fenced servers powered off through their iLO, and the evidence the owner
signs into a "full" survivor authorization (survivor.py, owner.py sign-survivor --fence-evidence). Agreed with
regalia-kms-05 on #432:

WHERE IT RUNS. Never on a KMS host. The iLOs are on an isolated management network, or disabled (README §2, attested:
ilo_isolated_or_disabled), so no node can reach one, and none may: a node holding its peers' power would let one
stolen node turn the other two off. The owner runs it (owner.py fence) from a machine on the management network. A
disabled or unreachable iLO is no fence: the owner signs the typed fallback instead (FALLBACK_EXTRA_S more).

THE CREDENTIALS are one fence-only iLO account per server (Virtual Power and Reset, and login: nothing else), encrypted
to the owner card's decryption key and the backup owner card's, so one owner can fence during an outage. They arrive
decrypted on a descriptor, never a file (keyfd):

    owner.py fence --inventory fence-inventory.json --node b --node c --out fence.json \\
        --credentials-fd 3 3< <(gpg --decrypt fence-credentials.json.gpg)

    {"b": {"username": ..., "password": ...}, "c": {...}}

THE INVENTORY binds each node to its box, recorded at commissioning (public data, kept with the owner's records):

    {"schema": "regalia.fence-inventory/v1",
     "nodes": {"b": {"ilo": "<host name or IPv4, port 443>", "ilo_cert_sha256": "<64 hex: the iLO's TLS certificate, DER>",
                     "serial": "<the chassis serial>", "uuid": "<the system UUID>"}}}

THE CLIENT is redfish.py (regalia-kms-d9's, #501), the one the drills use too (05 on #516): its pinned TLS, its discovery
(the Reset action's target and AllowableValues, the firmware floor, the server's serial) and its ForceOff with readback.
This module is the fence's policy on top of it.

FOR EACH NODE, in order, every step refused unless the one before it held:
  1. TLS to the iLO, the certificate's SHA-256 equal to the pinned one BEFORE any byte of the credentials is sent.
  2. The account is fence-only: the iLO's own account record shows VirtualPowerAndResetPriv and no privilege beyond
     login (Oem.Hp on iLO 4, Oem.Hpe on iLO 5). An account the fence cannot see is refused. UNMEASURED (05): that an
     iLO 4 lets a login-and-power-only account read the Accounts listing at all. If it does not, every correct account is
     refused here, and the fence is the typed fallback until this check is changed to what the iLO does show.
  3. The box: /redfish/v1/Systems/1's SerialNumber and UUID equal the inventory's, so the right server goes off.
  4. ForceOff at the discovered Reset target (unless it already reads Off), read back until Off (redfish.Client).
  5. PowerState read Off, then read Off AGAIN at least REREAD_S later: the evidence carries both times.
  6. The power-restore policy is recorded as the iLO reports it: anyone with the iLO's power right can turn the server
     back on, and a policy of "always on" does it after a power cut. That server then holds an older epoch and is
     halted by its peers (G4); the evidence says what was there, it does not stop it.

WHEN. After the quarantine epoch is signed, and within the hour before the owner signs the authorization: survivor.py
refuses evidence read before the quarantine's issued_at, or whose second readback is more than FENCE_MAX_AGE_S before
the authorization's not_before (05: a drill's evidence against the same inventory does not replay). The nodes to fence
are every other node but the RETIRED and REVOKED_STOLEN ones (survivor.fenceable).

The evidence, per node: {"power_state": "Off", "read_at", "read_again_at", "serial", "uuid", "ilo_cert_sha256",
"power_restore_policy"}, under {"method": "redfish", "nodes": {...}}. survivor.validate_authorization requires that
shape, and sign-survivor checks it against the same inventory.
"""
import re
import time

from deploy.baremetal import membership, redfish

Refused, require = membership.Refused, membership.require

INVENTORY_SCHEMA = "regalia.fence-inventory/v1"
INVENTORY_KEYS = ("ilo", "ilo_cert_sha256", "serial", "uuid")
EVIDENCE_KEYS = ("power_state", "read_at", "read_again_at", "serial", "uuid", "ilo_cert_sha256", "power_restore_policy")
REREAD_S = 10
ALLOWED_PRIVILEGES = {"LoginPriv", "VirtualPowerAndResetPriv"}
HOST = redfish.HOST                          # a name or IPv4 on the management network, port 443 (the client's rule)
UUID = re.compile(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")
SERIAL = redfish.SERIAL


def inventory(doc, nodes=None):
    """The inventory, checked: {node_id: {ilo, ilo_cert_sha256, serial, uuid}}; with `nodes`, every one listed."""
    membership.exact(doc, ("schema", "nodes"), "the fence inventory")
    require(doc["schema"] == INVENTORY_SCHEMA, "the fence inventory's schema must be %s" % INVENTORY_SCHEMA)
    require(isinstance(doc["nodes"], dict) and doc["nodes"], "the fence inventory names its nodes")
    for node_id, box in doc["nodes"].items():
        require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None, "the inventory names node IDs")
        membership.exact(box, INVENTORY_KEYS, "the fence inventory's %s" % node_id)
        require(isinstance(box["ilo"], str) and HOST.fullmatch(box["ilo"]) is not None, "%s's ilo is a host name or IPv4 address" % node_id)
        membership.hex_field(box["ilo_cert_sha256"], 64, "%s's ilo_cert_sha256" % node_id)
        require(isinstance(box["serial"], str) and SERIAL.fullmatch(box["serial"]) is not None, "%s's serial is a serial number" % node_id)
        require(isinstance(box["uuid"], str) and UUID.fullmatch(box["uuid"]) is not None, "%s's uuid is a UUID" % node_id)
    for node_id in nodes or ():
        require(node_id in doc["nodes"], "the fence inventory has no box for %s" % node_id)
    return doc["nodes"]


def same_box(box, seen, node_id):
    """The evidence's serial, UUID and certificate are the inventory's (sign-survivor's check as well as the fence's)."""
    require(seen["ilo_cert_sha256"] == box["ilo_cert_sha256"], "%s's iLO certificate is not the one pinned for it" % node_id)
    require(seen["serial"] == box["serial"], "%s's box reports serial %r; the inventory's is %r" % (node_id, seen["serial"], box["serial"]))
    require(seen["uuid"].lower() == box["uuid"].lower(), "%s's box reports UUID %s; the inventory's is %s" % (node_id, seen["uuid"], box["uuid"]))


def _get(transport, path, node_id):
    status, body = transport.request("GET", path)
    require(status == 200 and isinstance(body, dict), "%s's iLO answered GET %s with HTTP %s" % (node_id, path, status))
    return body


def _privileges(account):
    for oem in ("Hp", "Hpe"):
        found = ((account.get("Oem") or {}).get(oem) or {}).get("Privileges")
        if isinstance(found, dict):
            return {k for k, v in found.items() if v is True}
    return None


def fence_only(transport, username, node_id):
    """The account the fence logs in with holds the power right and nothing beyond login (05)."""
    listing = _get(transport, "/redfish/v1/AccountService/Accounts/", node_id)
    links = [m.get("@odata.id") for m in listing.get("Members") or [] if isinstance(m, dict)]
    for link in links:
        require(isinstance(link, str) and link.startswith("/redfish/v1/AccountService/Accounts/"), "the iLO lists an account link that is not one")
        account = _get(transport, link, node_id)
        if account.get("UserName") == username:
            held = _privileges(account)
            require(held is not None, "%s's iLO shows no privileges for %s: a fence account the fence cannot check is refused" % (node_id, username))
            require("VirtualPowerAndResetPriv" in held, "%s's iLO account %s cannot power the server off" % (node_id, username))
            extra = sorted(held - ALLOWED_PRIVILEGES)
            require(not extra, "%s's iLO account %s holds %s: the fence uses a fence-only account (power and reset, nothing else)"
                    % (node_id, username, ", ".join(extra)))
            return
    raise Refused("%s's iLO does not show the account %s: a fence account the fence cannot check is refused" % (node_id, username))


def _restore_policy(transport, node_id):
    system = _get(transport, redfish.SYSTEM, node_id)
    if isinstance(system.get("PowerRestorePolicy"), str):
        return system["PowerRestorePolicy"]
    status, bios = transport.request("GET", redfish.SYSTEM + "/Bios/")
    if status == 200 and isinstance(bios, dict):
        found = (bios.get("Attributes") or {}).get("AutoPowerOn", bios.get("AutoPowerOn"))
        if isinstance(found, str):
            return found
    return "unknown (the iLO did not show it)"


def fence_one(client, transport, box, username, node_id, now, sleep, stamp):
    """Steps 2 to 6 for one node on the one Redfish client (redfish.py: step 1, the pin, is its transport's, and the
    discovered Reset action, the serial and the readback are its own). Returns its evidence."""
    fence_only(transport, username, node_id)
    found = client.discover()                        # the serial, by the client; refused before anything is sent
    seen = {"serial": found["serial"], "uuid": found["uuid"], "ilo_cert_sha256": box["ilo_cert_sha256"]}
    require(UUID.fullmatch(seen["uuid"] or "") is not None, "%s's iLO shows no system UUID" % node_id)
    same_box(box, seen, node_id)
    policy = _restore_policy(transport, node_id)
    client.force_off()                               # ForceOff (unless already Off), read back until Off, or Refused
    read_at = now()
    sleep(REREAD_S)
    again = client.power_state()
    require(again == "Off", "%s read Off, then %r %d s later: something turned it back on; not fenced" % (node_id, again, REREAD_S))
    read_again_at = now()
    require(read_again_at - read_at >= REREAD_S, "%s's two Off readbacks are less than %d s apart by this machine's clock: not fenced"
            % (node_id, REREAD_S))
    return dict(seen, power_state="Off", read_at=stamp(read_at), read_again_at=stamp(read_again_at), power_restore_policy=policy)


def fence(boxes, nodes, credentials, now=None, sleep=None, transport=None):
    """{"method": "redfish", "nodes": {id: evidence}} for `nodes`, each fenced in turn. `boxes`: inventory(); `credentials`:
    {id: {"username", "password"}}; `transport(box, username, password)`: the pinned connection (redfish.PinnedHTTPS)."""
    from deploy.baremetal import survivor
    now, sleep = now or time.time, sleep or time.sleep
    transport = transport or (lambda box, user, password: redfish.PinnedHTTPS(box["ilo"], box["ilo_cert_sha256"], user, password))
    require(nodes and len(set(nodes)) == len(nodes), "name each node to fence once")
    out = {}
    for node_id in nodes:
        box = boxes.get(node_id)
        require(box is not None, "the fence inventory has no box for %s" % node_id)
        creds = credentials.get(node_id)
        require(isinstance(creds, dict) and set(creds) == {"username", "password"} and all(isinstance(v, str) and v for v in creds.values()),
                "the credentials hold no username and password for %s" % node_id)
        pinned = transport(box, creds["username"], creds["password"])
        client = redfish.Client(pinned, box["serial"], box["ilo"], box["ilo_cert_sha256"], clock=lambda: int(now() * 1000), sleep=sleep)
        out[node_id] = fence_one(client, pinned, box, creds["username"], node_id, now, sleep, survivor._stamp)
    return {"method": "redfish", "nodes": out}
