#!/usr/bin/env python3
"""The servers' iLOs over Redfish: power off, power on, and the readback that proves it (#495's drills; ADR-0002 D32's
G1 fence for a full-scope survivor, #432). One client for both, so a fence that works in a drill is the fence that works
in a recovery. Run from the operator workstation on the management network, never from a KMS server.

    python3 -Es -m deploy.baremetal.redfish status --ilo HOST --serial SERIAL --cert-sha256 HEX --user USER
    python3 -Es -m deploy.baremetal.redfish off|on  --ilo HOST --serial SERIAL --cert-sha256 HEX --user USER
        [--password-fd 3 3< <(gpg --decrypt ILO-CREDENTIAL.gpg) | --password-file 0600-FILE]   (else it is typed)
    python3 -Es -m deploy.baremetal.redfish tpm-status  --ilo HOST --serial SERIAL --cert-sha256 HEX --user USER  [...]
    python3 -Es -m deploy.baremetal.redfish tpm-clear   --ilo HOST --serial SERIAL --cert-sha256 HEX --user USER  [...]
        [--dry-run (the default) | --apply --confirm-serial SERIAL]
    python3 -Es -m deploy.baremetal.redfish tpm-proof   --properties-file GETCAP-PROPERTIES   (or --properties -)
        --handles-file GETCAP-PERSISTENT  --srk SRK-HANDLE [extra-srk-handle]...

    Behind 3< <(gpg --decrypt ...) gpg's exit status is lost: a decrypt that failed reaches the command as an empty
    descriptor (refused as "empty" or "holds nothing"), so read gpg's stderr when it is.

The mainstream reference is Pacemaker's fence_redfish: reset, then poll PowerState until it reads the target. Here:
  * DISCOVERED, NEVER ASSUMED. Each action first reads the system (/redfish/v1/Systems/1/: PowerState, SerialNumber,
    Model, the Reset action's target and its ResetType@Redfish.AllowableValues) and the iLO's firmware
    (/redfish/v1/Managers/1/). A ResetType the iLO does not list is refused before anything is sent. iLO 4 (the Gen9s)
    is expected to list On, ForceOff, ForceRestart, Nmi and PushPowerButton, and no GracefulRestart (iLO 5's): a
    graceful restart is in-band (systemctl reboot over SSH), not this client's.
  * THE RIGHT BOX. The iLO's SerialNumber must be the --serial given: fencing the wrong server is the classic failure.
  * PINNED TLS. iLOs present self-signed certificates: the peer certificate's SHA-256 must be --cert-sha256, recorded at
    commissioning. There is no "insecure" switch.
  * EVIDENCE. Every action returns a record: the iLO, its serial, model and firmware, the certificate digest, the
    request (ResetType, HTTP status) and every PowerState readback with its time (integer ms). A fence or a drill
    step is done only when the readback says so; a timeout is a refusal with the readbacks it saw.
  * UNDO. undoers() gives the drill journal (drill.py, #498) its replays: "power-on" for a ForceOff, "power-cycle"
    (ForceRestart, whatever PowerState says) for a restart that did not come back, and "tpm-pending-revert" (a PATCH
    of the TPM operation back to its no-action value) for a clear that is still pending. A clear that the server has
    already consumed cannot be undone: a clear is a clear -- the record says so.
  * THE TPM CLEAR (tpm-status, tpm-clear, tpm-proof; the staging DL360, regalia-kms-dx7.40). DISCOVERED, NEVER
    ASSUMED, as the power paths are: the client reads the system's BIOS resource (/redfish/v1/Systems/1/Bios/), follows
    the AttributeRegistry it names to the registry JSON, and from THAT learns the TPM-operation attribute (HPE Gen9's
    iLO 4 is expected to list TpmOperation or Tpm2Operation -- exactly one; both or neither is refused), the values it
    offers (it must offer a Clear-type value; "Clear" is not assumed from anything but the registry) and the pending
    settings URI from @Redfish.Settings.SettingsObject (the fallback constant is used only if the iLO lists that exact
    URI). Applying is a PATCH of the pending settings, a read-back of the pending value, a ForceRestart through the
    power paths above, then polling until the live attribute reads the no-action value again -- the operation consumed.
    A timeout is a refusal carrying every readback, and the pending value stands for the undoer. The iLO account
    needs the BIOS-configuration privilege for the PATCH (the power-only account is refused; the PA decided a
    second, staging-only account holds it -- the owner's to create). The PROOF of a clear comes from the HOST, never
    the iLO: tpm-proof reads the server's tpm2_getcap (properties-variable and handles-persistent, over the
    run's dedicated forced-command SSH, or pasted by the operator) and says ownerAuthSet 0, lockoutAuthSet 0, and
    no persistent handles but the named SRK ones.

CURRENT LIMITATIONS (also in LIMITATIONS.md):
  * Built and tested against a stand-in Redfish service only; NOT YET RUN against a DL360 Gen9's iLO 4. The allowable
    ResetTypes, the firmware string's form and the timing are to be measured on the first commissioning, with the
    discovery this client records. The tpm-* verbs likewise: the attribute's name and values, whether the iLO's
    BIOS-settings PATCH asks for physical presence (a TPM-PPI-type attribute, which the first dry run's registry read
    would show, and which nothing here sets silently) and the consumption's timing are measured on the first staging
    dry run, from the discovery tpm-status prints.
  * HTTP Basic authentication over the pinned TLS (no Redfish session tokens). The account is a dedicated iLO user with
    only Login and Virtual Power and Reset; its password is read from a pipe or a sealed memfd (--password-fd, the
    owner-card-encrypted credentials decrypted straight into it, #520), a 0600 file or typed, never an argument.
  * MIN_FIRMWARE (iLO 4 2.30, where Redfish begins) is a floor, not the security minimum: commissioning pins the
    current iLO 4 release and raises it here.
"""
import argparse
import base64
import getpass
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import stat
import sys
import time

from deploy.baremetal import keyfd, membership

Refused, require = membership.Refused, membership.require


class WrongServer(Refused):
    """The iLO reports another server than the one named: never retried, never waited out."""

# WITH the trailing slash. iLO 4 (measured on 2.82) answers the slash-less form with 308 Permanent Redirect, and a
# redirect is never followed here, so without it every subcommand was refused before reading anything (#670).
SYSTEM = "/redfish/v1/Systems/1/"
MANAGER = "/redfish/v1/Managers/1/"
BIOS = "/redfish/v1/Systems/1/Bios/"
BIOS_SETTINGS = "/redfish/v1/Systems/1/Bios/Settings/"     # the fallback; only used when the iLO's Bios/ lists it
REGISTRIES = "/redfish/v1/Registries/"
RESET_ACTION = "#ComputerSystem.Reset"
MIN_FIRMWARE = (2, 30)                      # iLO 4: Redfish from 2.30
POWER_TIMEOUT_S = {"Off": 60, "On": 120}
TPM_CONSUME_TIMEOUT_S = 300                 # the server's POST to consume a BIOS setting after the restart
TPM_ATTRS = ("TpmOperation", "Tpm2Operation")   # the Gen9's two possible names (1.2 / 2.0): exactly one must be listed
POLL_S = 2
MAX_BODY = 1024 * 1024
SERIAL = re.compile(r"[A-Za-z0-9]{4,32}")
HOST = re.compile(r"[A-Za-z0-9.-]{1,253}")    # a name or IPv4 on the management network (a bare IPv6 literal fails in HTTPSConnection)


def now_ms():
    return int(time.time() * 1000)


# ---- the transport: HTTPS with the peer certificate pinned --------------------------------------------------------

class PinnedHTTPS:
    """request(method, path, body) -> (status, parsed JSON or None), over HTTPS to `host`, the peer certificate's SHA-256
    required to be `cert_sha256` before a byte of the request (its credentials included) is sent."""

    def __init__(self, host, cert_sha256, user, password, timeout=30, port=443):
        require(HOST.fullmatch(host or "") is not None, "the iLO host %r is not a host name or address" % (host,))
        require(re.fullmatch(r"[0-9a-f]{64}", cert_sha256 or "") is not None, "--cert-sha256 is the iLO certificate's 64 lowercase hex")
        self.host, self.cert_sha256, self.timeout, self.port = host, cert_sha256, timeout, port
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()

    def _connect(self):
        # the chain is not what is trusted (a self-signed iLO certificate has none): the pinned digest is
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=context)
        connection.connect()
        seen = hashlib.sha256(connection.sock.getpeercert(binary_form=True) or b"").hexdigest()
        if seen != self.cert_sha256:
            connection.close()
            raise Refused("the iLO at %s presents certificate %s, not the pinned %s: nothing was sent" % (self.host, seen, self.cert_sha256))
        return connection, seen

    def request(self, method, path, body=None):
        connection, _ = self._connect()
        try:
            headers = {"Authorization": self.auth, "Accept": "application/json", "OData-Version": "4.0"}
            data = None
            if body is not None:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_BODY + 1)
            require(len(raw) <= MAX_BODY, "the iLO's answer to %s %s is oversized" % (method, path))
            try:
                parsed = json.loads(raw) if raw.strip() else None
            except ValueError:
                parsed = None
            return response.status, parsed
        except (OSError, socket.timeout, http.client.HTTPException) as failure:
            raise Refused("the iLO at %s did not answer %s %s: %s" % (self.host, method, path, failure)) from None
        finally:
            connection.close()


# ---- the client ---------------------------------------------------------------------------------------------------

def firmware_version(text):
    """(major, minor) from an iLO FirmwareVersion such as "2.82 Feb 06 2023" or "iLO 4 v2.82", or Refused."""
    found = re.search(r"(\d+)\.(\d+)", text or "")
    require(found is not None, "the iLO firmware version %r cannot be read" % (text,))
    return int(found.group(1)), int(found.group(2))


class Client:
    """One server's iLO. `transport.request(method, path, body)` -> (status, json); `serial`: the server's serial number,
    which the iLO must report; `ilo`: its address, for the record."""

    def __init__(self, transport, serial, ilo, cert_sha256="", clock=now_ms, sleep=time.sleep):
        require(SERIAL.fullmatch(serial or "") is not None, "the server serial %r is not a serial number" % (serial,))
        self.transport, self.serial, self.ilo, self.cert_sha256 = transport, serial, ilo, cert_sha256
        self.clock, self.sleep = clock, sleep

    def _get(self, path):
        status, body = self.transport.request("GET", path)
        require(status == 200 and isinstance(body, dict), "the iLO at %s answered GET %s with HTTP %s" % (self.ilo, path, status))
        return body

    def discover(self):
        """The system as the iLO reports it, checked to be this server: {serial, uuid, model, manufacturer, power, firmware,
        reset_target, reset_types} (uuid for the fence's second binding, fence.py)."""
        system, manager = self._get(SYSTEM), self._get(MANAGER)
        serial = str(system.get("SerialNumber") or "").strip()
        require(serial == self.serial, "the iLO at %s manages server %r, not %s: nothing is done to it" % (self.ilo, serial, self.serial))
        firmware = str(manager.get("FirmwareVersion") or "")
        require(firmware_version(firmware) >= MIN_FIRMWARE, "the iLO at %s runs firmware %r, below %d.%d (Redfish): refused"
                % ((self.ilo, firmware) + MIN_FIRMWARE))
        action = (system.get("Actions") or {}).get(RESET_ACTION) or {}
        target = action.get("target")
        types = action.get("ResetType@Redfish.AllowableValues")
        require(isinstance(target, str) and target.startswith("/redfish/v1/"), "the iLO at %s lists no ComputerSystem.Reset action" % self.ilo)
        require(isinstance(types, list) and all(isinstance(t, str) for t in types),
                "the iLO at %s lists no ResetType@Redfish.AllowableValues: nothing is assumed" % self.ilo)
        power = system.get("PowerState")
        require(power in ("On", "Off", "PoweringOn", "PoweringOff"), "the iLO at %s reports PowerState %r" % (self.ilo, power))
        return {"serial": serial, "uuid": str(system.get("UUID") or "").strip(), "model": str(system.get("Model") or ""),
                "manufacturer": str(system.get("Manufacturer") or ""), "power": power, "firmware": firmware, "reset_target": target,
                "reset_types": sorted(types)}

    def power_state(self):
        state = self._get(SYSTEM)
        if str(state.get("SerialNumber") or "").strip() != self.serial:
            raise WrongServer("the iLO at %s changed servers mid-action" % self.ilo)
        return state.get("PowerState")

    def _record(self, found, action, reset_type, status, readbacks, outcome):
        return {"ilo": self.ilo, "serial": found["serial"], "model": found["model"], "firmware": found["firmware"],
                "cert_sha256": self.cert_sha256, "action": action, "reset_type": reset_type, "http_status": status,
                "power_before": found["power"], "readbacks": readbacks, "outcome": outcome}

    def _reset_and_wait(self, action, reset_type, want, always=False):
        found = self.discover()
        require(reset_type in found["reset_types"], "the iLO at %s does not offer ResetType %s (it offers %s): nothing was sent"
                % (self.ilo, reset_type, ", ".join(found["reset_types"])))
        readbacks = [{"at_ms": self.clock(), "power": found["power"]}]
        if found["power"] == want and not always:
            return self._record(found, action, None, None, readbacks, "already %s: nothing sent" % want)
        status, _ = self.transport.request("POST", found["reset_target"], {"ResetType": reset_type})
        require(status in (200, 202, 204), "the iLO at %s refused ResetType %s with HTTP %s" % (self.ilo, reset_type, status))
        deadline = self.clock() + POWER_TIMEOUT_S[want] * 1000
        while True:
            # one failed poll (an iLO timeout, a reset connection) is a readback, not the end of a fence: the next one
            # may well say Off. Only another server answering ends it at once (regalia-kms-3e on #501)
            try:
                power = self.power_state()
                readbacks.append({"at_ms": self.clock(), "power": power})
            except WrongServer:
                raise
            except Refused as failure:
                power = None
                readbacks.append({"at_ms": self.clock(), "error": str(failure)[:300]})
            if power == want:
                return self._record(found, action, reset_type, status, readbacks, want)
            if self.clock() >= deadline:
                raise Refused("server %s did not read %s within %d s after %s (last %r): readbacks %s"
                              % (self.serial, want, POWER_TIMEOUT_S[want], reset_type, power, json.dumps(readbacks)))
            self.sleep(POLL_S)

    def force_off(self):
        """The fence (G1) and the drills' power fault: ForceOff, then PowerState read back until Off. A server already
        Off is returned as "already Off: nothing sent", with reset_type None: the readback alone is the evidence, and a
        recovery authorization (G1) accepts it as fenced on that readback, not on a ResetType."""
        return self._reset_and_wait("power-off", "ForceOff", "Off")

    def power_on(self):
        """The undo of force_off: On, then PowerState read back until On. Marking a fault undone on it is right only
        when the last readback says On, which this guarantees (a timeout is a refusal)."""
        return self._reset_and_wait("power-on", "On", "On")

    def force_restart(self):
        """The undo of a restart that did not come back (regalia-kms-d9 on #504): a server hung after `systemctl reboot`
        is still powered On, so On would send nothing. ForceRestart is sent whatever PowerState says (a server found Off
        is powered On instead), then PowerState read back until On. The readback proves power, not service: the caller
        waits for the server to serve before it marks the fault undone."""
        if self.discover()["power"] == "Off":
            return self._reset_and_wait("power-cycle", "On", "On")
        return self._reset_and_wait("power-cycle", "ForceRestart", "On", always=True)

    # ---- the TPM clear (the staging DL360; regalia-kms-dx7.40) -----------------------------------------------------

    def _registry(self):
        """The BIOS attribute registry the iLO's Bios resource NAMES (never a constant's): {registry_id, uri, attrs}.
        Refused when the Bios resource names no registry, or the registry it names cannot be read."""
        bios = self._get(BIOS)
        registry_id = bios.get("AttributeRegistry")
        require(isinstance(registry_id, str) and registry_id,
                "the iLO at %s lists no attribute registry: nothing is assumed" % self.ilo)
        listing = self._get(REGISTRIES)
        entries = listing.get("Registries")
        require(isinstance(entries, list), "the iLO at %s answers its registries with no list" % self.ilo)
        uri = None
        for entry in entries:
            if isinstance(entry, dict) and entry.get("Id") == registry_id:
                location = entry.get("Location") or {}
                uri = location.get("Uri")
        require(isinstance(uri, str) and uri.startswith("/redfish/v1/"),
                "the iLO at %s names registry %r but lists no location for it" % (self.ilo, registry_id))
        registry = self._get(uri)
        attrs = registry.get("Attributes")
        require(isinstance(attrs, list), "the registry %r at %s has no attributes" % (registry_id, self.ilo))
        return {"registry_id": registry_id, "uri": uri, "attrs": attrs}

    def bios_discover(self):
        """The TPM-operation attribute as the registry lists it: {found (the power paths' discover), attribute, current,
        no_action, clear, values, settings_uri, registry_id}. Refused -- before anything is sent -- when the registry
        lists neither TPM-operation attribute, or both, or the one listed has no Clear-type value, is read-only, or
        reads a value other than its no-action value (another operation may be pending)."""
        found = self.discover()
        bios = self._get(BIOS)
        registry = self._registry()
        named = [a for a in registry["attrs"] if isinstance(a, dict) and a.get("AttributeName") in TPM_ATTRS]
        require(len(named) == 1, "the iLO at %s lists %s TPM-operation attribute (expected exactly one of %s): %s"
                % (self.ilo, "both" if len(named) == 2 else "no", ", ".join(TPM_ATTRS),
                   "refusing rather than choosing" if len(named) == 2 else "nothing is assumed"))
        attr = named[0]
        name = attr["AttributeName"]
        values = attr.get("ValueNames")
        require(isinstance(values, list) and values and all(isinstance(v, str) for v in values),
                "the iLO at %s lists no values for %s: nothing is assumed" % (self.ilo, name))
        no_action = next((v for v in values if v.lower() in ("no action", "noaction")), None)
        require(no_action is not None, "the registry %r at %s lists no no-action value for %s (it offers %s): nothing is assumed"
                % (registry["registry_id"], self.ilo, name, ", ".join(sorted(values))))
        clear = next((v for v in values if v.lower().replace(" ", "") == "clear"), None)
        require(clear is not None, "the iLO at %s lists no Clear value for %s (it offers %s): nothing is assumed"
                % (self.ilo, name, ", ".join(sorted(v for v in values if v != no_action))))
        require(not attr.get("ReadOnly"), "the iLO at %s lists %s as read-only: refused" % (self.ilo, name))
        current = None
        for live in bios.get("Attributes") or []:
            if isinstance(live, dict) and live.get("AttributeName") == name:
                current = live.get("Value")
        pending = None
        if bios.get("@Redfish.Settings.SettingsObject"):
            try:
                pending = self._bios_pending_value(name, bios["@Redfish.Settings.SettingsObject"])
            except Refused:
                pass                                              # a Settings the iLO will not answer is judged at the PATCH, not here
        # a live value that is the value standing in the pending settings is a clear in flight (this is where the
        # undoer's discovery must not refuse); any other live value is a refusal -- another operation, or a state
        # this client did not make, so nothing is sent.
        require(current in (None, no_action, pending),
                "the iLO at %s has %s %s, not %s: another operation may be pending, so nothing is sent"
                % (self.ilo, name, current, no_action))
        settings = bios.get("@Redfish.Settings.SettingsObject")
        require(settings == BIOS_SETTINGS,
                "the iLO at %s lists pending settings at %r, not the expected %s: refusing rather than following it" % (self.ilo, settings, BIOS_SETTINGS))
        return {"found": found, "attribute": name, "current": current, "no_action": no_action, "clear": clear,
                "values": sorted(values), "settings_uri": settings, "registry_id": registry["registry_id"]}

    def tpm_status(self):
        """Read-only: the system as discover() reports it, plus the TPM attribute, its current value and the plan's
        target -- the state the dry run prints, and what the first staging run measures."""
        state = self.bios_discover()
        status = {k: state["found"][k] for k in ("serial", "uuid", "model", "manufacturer", "power", "firmware")}
        status.update({"attribute": state["attribute"], "current": state["current"], "no_action": state["no_action"],
                       "clear": state["clear"], "values": state["values"], "settings_uri": state["settings_uri"],
                       "registry_id": state["registry_id"]})
        return status

    def tpm_clear_plan(self):
        """The exact PATCH a clear would be: the iLO's own settings URI and {"Attributes": {attr: the registry's Clear}}.
        Pure, built from the discovery the client refuses first."""
        state = self.bios_discover()
        return {"uri": state["settings_uri"], "body": {"Attributes": {state["attribute"]: state["clear"]}}}

    def _bios_live_value(self, name):
        """The live attribute value from the BIOS resource (what the iLO has applied), not the pending settings."""
        body = self._get(BIOS)
        for live in body.get("Attributes") or []:
            if isinstance(live, dict) and live.get("AttributeName") == name:
                return live.get("Value")
        return None

    def _bios_pending_value(self, name, uri):
        """The pending value from the settings resource the iLO named (what the iLO will apply at next restart)."""
        body = self._get(uri)
        for live in body.get("Attributes") or []:
            if isinstance(live, dict) and live.get("AttributeName") == name:
                return live.get("Value")
        return None

    def tpm_clear(self, apply=False):
        """The clear. With apply=False (the default) nothing is sent: the status and the plan are returned. With
        apply=True: the pending settings are PATCHed (HTTP 200/202/204 only) and read back until they say the Clear
        value, then the server is ForceRestart-ed, then the live attribute is polled until it reads the no-action
        value again -- the operation consumed. A timeout is a Refused carrying every readback, and the pending value
        stands for the undoer. The proof of the clear is the host's, tpm-proof, never this record."""
        state = self.bios_discover()
        plan = {"uri": state["settings_uri"], "body": {"Attributes": {state["attribute"]: state["clear"]}}}
        base = {"found": state["found"], "attribute": state["attribute"], "clear": state["clear"], "plan": plan}
        if not apply:
            return {**base, "status": self.tpm_status(), "outcome": "dry-run: nothing was sent"}
        status, _ = self.transport.request("PATCH", plan["uri"], plan["body"])
        require(status in (200, 202, 204), "the iLO at %s refused the pending TPM operation with HTTP %s" % (self.ilo, status))
        pending_readbacks = []
        deadline = self.clock() + POWER_TIMEOUT_S["On"] * 1000
        while True:
            pending = self._bios_pending_value(state["attribute"], plan["uri"])
            pending_readbacks.append({"at_ms": self.clock(), "pending": pending})
            if pending == state["clear"]:
                break
            if self.clock() >= deadline:
                raise Refused("the iLO at %s did not read back %s within %d s after the PATCH: pending readbacks %s"
                              % (self.ilo, state["clear"], POWER_TIMEOUT_S["On"], json.dumps(pending_readbacks)))
            self.sleep(POLL_S)
        restart = self.force_restart()
        deadline = self.clock() + TPM_CONSUME_TIMEOUT_S * 1000
        live_readbacks = [{"at_ms": self.clock(), "live": state["current"]}]
        while True:
            live = self._bios_live_value(state["attribute"])
            live_readbacks.append({"at_ms": self.clock(), "live": live})
            if live == state["no_action"]:
                live_readbacks[-1]["consumed_before"] = restart["outcome"]
                return {**base, "http_status": status, "pending_readbacks": pending_readbacks, "restart": restart,
                        "live_readbacks": live_readbacks, "outcome": "consumed"}
            if self.clock() >= deadline:
                raise Refused("the iLO at %s: TPM operation %s was not consumed within %d s (after the restart): "
                              "pending readbacks %s, live readbacks %s -- the pending value stands for the undoer"
                              % (self.ilo, state["clear"], TPM_CONSUME_TIMEOUT_S, json.dumps(pending_readbacks),
                                 json.dumps(live_readbacks)))
            self.sleep(POLL_S)

    def tpm_undo(self):
        """The undoer's action: if a clear is still pending, PATCH the attribute back to its no-action value; if the
        server has already consumed it, say so and do nothing (a consumed clear cannot be undone). The discovery here
        tolerates a live value that is the pending one (the clear being reverted) -- the pending-refusal is for the
        dry run and the apply, which would stack a second operation; the undo exists precisely because one stands."""
        state = self.bios_discover()
        if self._bios_pending_value(state["attribute"], state["settings_uri"]) == state["no_action"]:
            return {"ilo": self.ilo, "serial": state["found"]["serial"], "model": state["found"]["model"],
                    "firmware": state["found"]["firmware"], "action": "tpm-pending-revert", "attribute": state["attribute"],
                    "outcome": "nothing pending: nothing sent"}
        status, _ = self.transport.request("PATCH", state["settings_uri"], {"Attributes": {state["attribute"]: state["no_action"]}})
        require(status in (200, 202, 204), "the iLO at %s refused the pending revert with HTTP %s" % (self.ilo, status))
        readbacks = []
        deadline = self.clock() + POWER_TIMEOUT_S["On"] * 1000
        while self._bios_pending_value(state["attribute"], state["settings_uri"]) != state["no_action"]:
            readbacks.append({"at_ms": self.clock(), "pending": self._bios_pending_value(state["attribute"], state["settings_uri"])})
            if self.clock() >= deadline:
                raise Refused("the iLO at %s did not read back %s within %d s after the revert: readbacks %s"
                              % (self.ilo, state["no_action"], POWER_TIMEOUT_S["On"], json.dumps(readbacks)))
            self.sleep(POLL_S)
        readbacks.append({"at_ms": self.clock(), "pending": state["no_action"]})
        return {"ilo": self.ilo, "serial": state["found"]["serial"], "model": state["found"]["model"],
                "firmware": state["found"]["firmware"], "action": "tpm-pending-revert", "attribute": state["attribute"],
                "http_status": status, "readbacks": readbacks,
                "outcome": "reverted (a clear the server already consumed cannot be undone)"}


def tpm_proof(properties_text, handles_persistent_text, srk_handles):
    """The HOST's proof that a clear happened, read from the server's own tpm2_getcap (never inferred from the iLO):
    ownerAuthSet 0, lockoutAuthSet 0, and no persistent handles but the SRK's. `properties_text` is
    `tpm2_getcap properties-variable` (its TPM2_DATA row, the values in order: fixedTPM, ownerAuthSet, ...),
    `handles_persistent_text` is `tpm2_getcap handles-persistent` (one 0x-handle per line), `srk_handles` the handles
    the run expects (the SRK, at least)."""
    data = None
    for line in (properties_text or "").splitlines():
        fields = line.strip().split(":")
        if len(fields) >= 2 and fields[0].strip() == "TPM2_DATA":
            data = fields[1].strip().split(",")
            break
    require(data is not None and len(data) >= 16, "no TPM2_DATA row to read the properties from (is it tpm2_getcap properties-variable?)")
    # the TPM 2.0 properties-variable order: 0 fixedTPM, 1 ownerAuthSet, 2 disableClear, 3 lockoutAuthSet, ...
    owner = str(data[1]) == "1"
    lockout = str(data[3]) == "1"
    handles = [h.strip() for h in (handles_persistent_text or "").splitlines() if h.strip()]
    expect = [str(h).strip() for h in (srk_handles or [])]
    pass_ = not owner and not lockout and all(h in expect for h in handles)
    return {"ownerAuthSet": owner, "lockoutAuthSet": lockout, "persistent_handles": handles, "pass": pass_}


def undoers(client_for):
    """The drill journal's replay (drill.py, #498): {"power-on": node -> record, "power-cycle": node -> record,
    "tpm-pending-revert": node -> record}."""
    return {"power-on": lambda node: client_for(node).power_on(), "power-cycle": lambda node: client_for(node).force_restart(),
            "tpm-pending-revert": lambda node: client_for(node).tpm_undo()}


# ---- the command --------------------------------------------------------------------------------------------------

def read_password(path=None, fd=None):
    """The iLO account's password: from descriptor `fd` (a pipe or a sealed memfd, keyfd.read: never a file on disk),
    from a 0600 file of the caller's, or typed when neither is given."""
    if fd is not None:
        return read_password_fd(fd)
    if path is None:
        return getpass.getpass("iLO password: ")
    # opened once, never followed, and judged by that descriptor: no window between the check and the read (3e)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as failure:
        raise Refused("%s must be a regular file of yours, mode 0600: the iLO password is not read from it (%s)" % (path, failure)) from None
    with os.fdopen(fd) as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "%s must be a regular file of yours, mode 0600: the iLO password is not read from it" % path)
        password = f.readline().rstrip("\n")
    require(password, "%s is empty" % path)
    return password


def read_password_fd(fd):
    """The password on descriptor `fd`, as `gpg --decrypt` writes it into a pipe (#520): one line of UTF-8, its one
    trailing newline dropped. The descriptor is closed and the bytes read are zeroed, whatever happens; the password
    itself is a str from here on (and in the Basic header), which Python cannot zero, as with --password-file."""
    raw = keyfd.read(fd, "the iLO password")
    try:
        try:
            text = raw.decode("utf-8")                    # from the bytearray itself: no second, unzeroable bytes copy
        except UnicodeDecodeError:
            raise Refused("the iLO password on descriptor %d is not UTF-8" % fd) from None
        password = text[:-1] if text.endswith("\n") else text
        require(password, "the iLO password on descriptor %d is empty (behind 3< <(gpg --decrypt ...) that usually means gpg "
                "failed, and its exit status is lost: read its stderr)" % fd)
        require(not any(c in password for c in "\n\r\0"), "the iLO password on descriptor %d is more than one line" % fd)
        return password
    finally:
        keyfd.zero(raw)


def _read_captured(path):
    """A tpm2_getcap capture: from a file the run (the forced-command SSH, or the operator) wrote, or stdin on '-';
    refused when neither names one."""
    require(path is not None, "a capture path is required")
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, "r") as f:
            return f.read()
    except OSError as failure:
        raise Refused("the capture %s cannot be read (%s)" % (path, failure)) from None


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.redfish", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("status", "off", "on", "tpm-status", "tpm-clear", "tpm-proof"))
    parser.add_argument("--ilo", help="the iLO's address on the management network")
    parser.add_argument("--serial", help="the server's serial number, which the iLO must report")
    parser.add_argument("--cert-sha256", help="the iLO certificate's SHA-256, recorded at commissioning")
    parser.add_argument("--user", help="the iLO account (the tpm-clear apply needs the BIOS-configuration privilege)")
    secret = parser.add_mutually_exclusive_group()
    secret.add_argument("--password-fd", type=int, help="a descriptor holding the password: a pipe or a sealed memfd, as "
                        "3< <(gpg --decrypt ...) gives (#520)")
    secret.add_argument("--password-file", help="a 0600 file holding the password (else it is typed)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="tpm-clear: read the state and print the planned PATCH, send nothing (the default)")
    mode.add_argument("--apply", action="store_true", help="tpm-clear: send the PATCH, restart, wait for the operation to be consumed")
    parser.add_argument("--confirm-serial", help="tpm-clear --apply: must equal --serial: the clear is a typed confirmation")
    parser.add_argument("--properties-file", help="tpm-proof: the host's `tpm2_getcap properties-variable` capture ('-' for stdin)")
    parser.add_argument("--handles-file", help="tpm-proof: the host's `tpm2_getcap handles-persistent` capture ('-' for stdin)")
    parser.add_argument("--srk", action="append", default=[], help="tpm-proof: a persistent handle the SRK holds (repeatable)")
    args = parser.parse_args(argv)
    try:
        if args.command == "tpm-proof":
            result = tpm_proof(_read_captured(args.properties_file), _read_captured(args.handles_file), args.srk)
        else:
            for flag, name in ((args.ilo, "--ilo"), (args.serial, "--serial"), (args.cert_sha256, "--cert-sha256"), (args.user, "--user")):
                require(flag is not None, "%s is required for %s" % (name, args.command))
            if args.apply and args.confirm_serial != args.serial:
                raise Refused("--apply requires --confirm-serial equal to --serial: the clear is never sent on a mere apply")
            transport = PinnedHTTPS(args.ilo, args.cert_sha256, args.user, read_password(args.password_file, args.password_fd))
            client = Client(transport, args.serial, args.ilo, args.cert_sha256)
            if args.command == "status":
                result = client.discover()
            elif args.command == "off":
                result = client.force_off()
            elif args.command == "on":
                result = client.power_on()
            elif args.command == "tpm-status":
                result = client.tpm_status()
            else:
                result = client.tpm_clear(apply=args.apply)
    except (Refused, OSError) as refusal:
        print("redfish: %s refused: %s" % (args.command, refusal), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
