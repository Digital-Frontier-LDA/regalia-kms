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
     "nodes": {"b": {"ilo": "<host or host:port>", "ilo_cert_sha256": "<64 hex: the iLO's TLS certificate, DER>",
                     "serial": "<the chassis serial>", "uuid": "<the system UUID>"}}}

FOR EACH NODE, in order, every step refused unless the one before it held:
  1. TLS to the iLO, the certificate's SHA-256 equal to the pinned one BEFORE any byte of the credentials is sent.
  2. The account is fence-only: the iLO's own account record shows VirtualPowerAndResetPriv and no privilege beyond
     login (Oem.Hp on iLO 4, Oem.Hpe on iLO 5). An account the fence cannot see is refused. UNMEASURED (05): that an
     iLO 4 lets a login-and-power-only account read the Accounts listing at all. If it does not, every correct account is
     refused here, and the fence is the typed fallback until this check is changed to what the iLO does show.
  3. The box: /redfish/v1/Systems/1's SerialNumber and UUID equal the inventory's, so the right server goes off.
  4. ForceOff (ComputerSystem.Reset), unless it already reads Off.
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
import base64
import hashlib
import http.client
import json
import re
import ssl
import time

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

INVENTORY_SCHEMA = "regalia.fence-inventory/v1"
INVENTORY_KEYS = ("ilo", "ilo_cert_sha256", "serial", "uuid")
EVIDENCE_KEYS = ("power_state", "read_at", "read_again_at", "serial", "uuid", "ilo_cert_sha256", "power_restore_policy")
REREAD_S = 10
OFF_WAIT_S, OFF_POLL_S = 60, 2
TIMEOUT_S = 15
MAX_BODY = 1024 * 1024
ALLOWED_PRIVILEGES = {"LoginPriv", "VirtualPowerAndResetPriv"}
HOST = re.compile(r"[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?|\[[0-9a-fA-F:]{2,39}\](:[0-9]{1,5})?")
UUID = re.compile(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")
SERIAL = re.compile(r"[\x21-\x7e]{1,64}")


def inventory(doc, nodes=None):
    """The inventory, checked: {node_id: {ilo, ilo_cert_sha256, serial, uuid}}; with `nodes`, every one listed."""
    membership.exact(doc, ("schema", "nodes"), "the fence inventory")
    require(doc["schema"] == INVENTORY_SCHEMA, "the fence inventory's schema must be %s" % INVENTORY_SCHEMA)
    require(isinstance(doc["nodes"], dict) and doc["nodes"], "the fence inventory names its nodes")
    for node_id, box in doc["nodes"].items():
        require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None, "the inventory names node IDs")
        membership.exact(box, INVENTORY_KEYS, "the fence inventory's %s" % node_id)
        require(isinstance(box["ilo"], str) and HOST.fullmatch(box["ilo"]) is not None, "%s's ilo is a host or host:port" % node_id)
        membership.hex_field(box["ilo_cert_sha256"], 64, "%s's ilo_cert_sha256" % node_id)
        require(isinstance(box["serial"], str) and SERIAL.fullmatch(box["serial"]) is not None, "%s's serial is printable, no space" % node_id)
        require(isinstance(box["uuid"], str) and UUID.fullmatch(box["uuid"]) is not None, "%s's uuid is a UUID" % node_id)
    for node_id in nodes or ():
        require(node_id in doc["nodes"], "the fence inventory has no box for %s" % node_id)
    return doc["nodes"]


def same_box(box, seen, node_id):
    """The evidence's serial, UUID and certificate are the inventory's (sign-survivor's check as well as the fence's)."""
    require(seen["ilo_cert_sha256"] == box["ilo_cert_sha256"], "%s's iLO certificate is not the one pinned for it" % node_id)
    require(seen["serial"] == box["serial"], "%s's box reports serial %r; the inventory's is %r" % (node_id, seen["serial"], box["serial"]))
    require(seen["uuid"].lower() == box["uuid"].lower(), "%s's box reports UUID %s; the inventory's is %s" % (node_id, seen["uuid"], box["uuid"]))


class Redfish:
    """One iLO's Redfish service over TLS pinned to its certificate's SHA-256 (no CA: the iLO's is self-signed)."""

    def __init__(self, ilo, pin, username, password, connect=None):
        self.ilo, self.pin = ilo, pin
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
        self.connect = connect or self._connect

    def _connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE     # the pin below is the check
        context.minimum_version = ssl.TLSVersion.TLSv1_2                         # iLO 4's best
        return http.client.HTTPSConnection(self.ilo, timeout=TIMEOUT_S, context=context)

    def request(self, method, path, body=None):
        conn = self.connect()
        try:
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True)
            require(der is not None and hashlib.sha256(der).hexdigest() == self.pin,
                    "the iLO at %s presents a certificate that is not the one pinned for it: nothing sent" % self.ilo)
            headers = {"Authorization": self.auth, "Accept": "application/json"}
            data = None
            if body is not None:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=data, headers=headers)
            response = conn.getresponse()
            raw = response.read(MAX_BODY + 1)
            require(len(raw) <= MAX_BODY, "the iLO's answer to %s %s is over %d bytes" % (method, path, MAX_BODY))
            require(200 <= response.status < 300, "the iLO answered %s %s with HTTP %d" % (method, path, response.status))
            return json.loads(raw) if raw.strip() else {}
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise Refused("the iLO at %s: %s %s failed: %s" % (self.ilo, method, path, error)) from None
        finally:
            conn.close()

    def get(self, path):
        return self.request("GET", path)


def _privileges(account):
    for oem in ("Hp", "Hpe"):
        found = ((account.get("Oem") or {}).get(oem) or {}).get("Privileges")
        if isinstance(found, dict):
            return {k for k, v in found.items() if v is True}
    return None


def fence_only(redfish, username, node_id):
    """The account the fence logs in with holds the power right and nothing beyond login (05)."""
    listing = redfish.get("/redfish/v1/AccountService/Accounts/")
    links = [m.get("@odata.id") for m in listing.get("Members") or [] if isinstance(m, dict)]
    for link in links:
        require(isinstance(link, str) and link.startswith("/redfish/v1/AccountService/Accounts/"), "the iLO lists an account link that is not one")
        account = redfish.get(link)
        if account.get("UserName") == username:
            held = _privileges(account)
            require(held is not None, "%s's iLO shows no privileges for %s: a fence account the fence cannot check is refused" % (node_id, username))
            require("VirtualPowerAndResetPriv" in held, "%s's iLO account %s cannot power the server off" % (node_id, username))
            extra = sorted(held - ALLOWED_PRIVILEGES)
            require(not extra, "%s's iLO account %s holds %s: the fence uses a fence-only account (power and reset, nothing else)"
                    % (node_id, username, ", ".join(extra)))
            return
    raise Refused("%s's iLO does not show the account %s: a fence account the fence cannot check is refused" % (node_id, username))


def _restore_policy(redfish, system):
    if isinstance(system.get("PowerRestorePolicy"), str):
        return system["PowerRestorePolicy"]
    try:
        bios = redfish.get("/redfish/v1/Systems/1/Bios/")
    except Refused:
        return "unknown (the iLO did not show it)"
    found = (bios.get("Attributes") or {}).get("AutoPowerOn", bios.get("AutoPowerOn"))
    return found if isinstance(found, str) else "unknown (the iLO did not show it)"


def fence_one(redfish, box, username, node_id, now, sleep, stamp):
    """Steps 2 to 6 for one node (step 1 is every request's). Returns its evidence."""
    fence_only(redfish, username, node_id)
    system = redfish.get("/redfish/v1/Systems/1/")
    seen = {"serial": system.get("SerialNumber"), "uuid": system.get("UUID"), "ilo_cert_sha256": redfish.pin}
    require(isinstance(seen["serial"], str) and isinstance(seen["uuid"], str), "%s's iLO shows no serial or UUID" % node_id)
    same_box(box, seen, node_id)
    policy = _restore_policy(redfish, system)
    if system.get("PowerState") != "Off":
        redfish.request("POST", "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/", {"ResetType": "ForceOff"})
    deadline = now() + OFF_WAIT_S
    while True:
        state = redfish.get("/redfish/v1/Systems/1/").get("PowerState")
        if state == "Off":
            break
        require(now() < deadline, "%s still reads %r %d s after ForceOff: not fenced" % (node_id, state, OFF_WAIT_S))
        sleep(OFF_POLL_S)
    read_at = now()
    sleep(REREAD_S)
    again = redfish.get("/redfish/v1/Systems/1/").get("PowerState")
    require(again == "Off", "%s read Off, then %r %d s later: something turned it back on; not fenced" % (node_id, again, REREAD_S))
    read_again_at = now()
    require(read_again_at - read_at >= REREAD_S, "%s's two Off readbacks are less than %d s apart by this machine's clock: not fenced"
            % (node_id, REREAD_S))
    return dict(seen, power_state="Off", read_at=stamp(read_at), read_again_at=stamp(read_again_at), power_restore_policy=policy)


def fence(boxes, nodes, credentials, now=None, sleep=None, client=Redfish):
    """{"method": "redfish", "nodes": {id: evidence}} for `nodes`, each fenced in turn. `boxes`: inventory(); `credentials`:
    {id: {"username", "password"}}."""
    from deploy.baremetal import survivor
    now, sleep = now or time.time, sleep or time.sleep
    require(nodes and len(set(nodes)) == len(nodes), "name each node to fence once")
    out = {}
    for node_id in nodes:
        box = boxes.get(node_id)
        require(box is not None, "the fence inventory has no box for %s" % node_id)
        creds = credentials.get(node_id)
        require(isinstance(creds, dict) and set(creds) == {"username", "password"} and all(isinstance(v, str) and v for v in creds.values()),
                "the credentials hold no username and password for %s" % node_id)
        redfish = client(box["ilo"], box["ilo_cert_sha256"], creds["username"], creds["password"])
        out[node_id] = fence_one(redfish, box, creds["username"], node_id, now, sleep, survivor._stamp)
    return {"method": "redfish", "nodes": out}
