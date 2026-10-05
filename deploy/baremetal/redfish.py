#!/usr/bin/env python3
"""The servers' iLOs over Redfish: power off, power on, and the readback that proves it (#495's drills; ADR-0002 D32's
G1 fence for a full-scope survivor, #432). One client for both, so a fence that works in a drill is the fence that works
in a recovery. Run from the operator workstation on the management network, never from a KMS server.

    python3 -Es -m deploy.baremetal.redfish status --ilo HOST --serial SERIAL --cert-sha256 HEX --user USER
    python3 -Es -m deploy.baremetal.redfish off|on  --ilo HOST --serial SERIAL --cert-sha256 HEX --user USER

The mainstream reference is Pacemaker's fence_redfish: reset, then poll PowerState until it reads the target. Here:
  * DISCOVERED, NEVER ASSUMED. Each action first reads the system (/redfish/v1/Systems/1: PowerState, SerialNumber,
    Model, the Reset action's target and its ResetType@Redfish.AllowableValues) and the iLO's firmware
    (/redfish/v1/Managers/1). A ResetType the iLO does not list is refused before anything is sent. iLO 4 (the Gen9s)
    is expected to list On, ForceOff, ForceRestart, Nmi and PushPowerButton, and no GracefulRestart (iLO 5's): a
    graceful restart is in-band (systemctl reboot over SSH), not this client's.
  * THE RIGHT BOX. The iLO's SerialNumber must be the --serial given: fencing the wrong server is the classic failure.
  * PINNED TLS. iLOs present self-signed certificates: the peer certificate's SHA-256 must be --cert-sha256, recorded at
    commissioning. There is no "insecure" switch.
  * EVIDENCE. Every action returns a record: the iLO, its serial, model and firmware, the certificate digest, the
    request (ResetType, HTTP status) and every PowerState readback with its time (integer ms). A fence or a drill
    step is done only when the readback says so; a timeout is a refusal with the readbacks it saw.
  * UNDO. undoers() gives the drill journal (drill.py, #498) its {"power-on": node} replay.

CURRENT LIMITATIONS (also in LIMITATIONS.md):
  * Built and tested against a stand-in Redfish service only; NOT YET RUN against a DL360 Gen9's iLO 4. The allowable
    ResetTypes, the firmware string's form and the timing are to be measured on the first commissioning, with the
    discovery this client records.
  * HTTP Basic authentication over the pinned TLS (no Redfish session tokens). The account is a dedicated iLO user with
    only Login and Virtual Power and Reset; its password is read from a 0600 file or typed, never an argument.
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

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require


class WrongServer(Refused):
    """The iLO reports another server than the one named: never retried, never waited out."""

SYSTEM = "/redfish/v1/Systems/1"
MANAGER = "/redfish/v1/Managers/1"
RESET_ACTION = "#ComputerSystem.Reset"
MIN_FIRMWARE = (2, 30)                      # iLO 4: Redfish from 2.30
POWER_TIMEOUT_S = {"Off": 60, "On": 120}
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
        """The system as the iLO reports it, checked to be this server: {serial, model, manufacturer, power, firmware,
        reset_target, reset_types}."""
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
        return {"serial": serial, "model": str(system.get("Model") or ""), "manufacturer": str(system.get("Manufacturer") or ""),
                "power": power, "firmware": firmware, "reset_target": target, "reset_types": sorted(types)}

    def power_state(self):
        state = self._get(SYSTEM)
        if str(state.get("SerialNumber") or "").strip() != self.serial:
            raise WrongServer("the iLO at %s changed servers mid-action" % self.ilo)
        return state.get("PowerState")

    def _record(self, found, action, reset_type, status, readbacks, outcome):
        return {"ilo": self.ilo, "serial": found["serial"], "model": found["model"], "firmware": found["firmware"],
                "cert_sha256": self.cert_sha256, "action": action, "reset_type": reset_type, "http_status": status,
                "power_before": found["power"], "readbacks": readbacks, "outcome": outcome}

    def _reset_and_wait(self, action, reset_type, want):
        found = self.discover()
        require(reset_type in found["reset_types"], "the iLO at %s does not offer ResetType %s (it offers %s): nothing was sent"
                % (self.ilo, reset_type, ", ".join(found["reset_types"])))
        readbacks = [{"at_ms": self.clock(), "power": found["power"]}]
        if found["power"] == want:
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
        """The undo of force_off: On, then PowerState read back until On."""
        return self._reset_and_wait("power-on", "On", "On")


def undoers(client_for):
    """The drill journal's replay for power (drill.py, #498): {"power-on": node -> the readback record}."""
    return {"power-on": lambda node: client_for(node).power_on()}


# ---- the command --------------------------------------------------------------------------------------------------

def read_password(path):
    """The iLO account's password from a 0600 file of the caller's, or typed when no file is given."""
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.redfish", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("status", "off", "on"))
    parser.add_argument("--ilo", required=True, help="the iLO's address on the management network")
    parser.add_argument("--serial", required=True, help="the server's serial number, which the iLO must report")
    parser.add_argument("--cert-sha256", required=True, help="the iLO certificate's SHA-256, recorded at commissioning")
    parser.add_argument("--user", required=True, help="the iLO account (Login and Virtual Power and Reset only)")
    parser.add_argument("--password-file", help="a 0600 file holding the password (else it is typed)")
    args = parser.parse_args(argv)
    try:
        transport = PinnedHTTPS(args.ilo, args.cert_sha256, args.user, read_password(args.password_file))
        client = Client(transport, args.serial, args.ilo, args.cert_sha256)
        result = client.discover() if args.command == "status" else client.force_off() if args.command == "off" else client.power_on()
    except (Refused, OSError) as refusal:
        print("redfish: %s refused: %s" % (args.command, refusal), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
