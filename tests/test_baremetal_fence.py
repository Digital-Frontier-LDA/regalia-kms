"""deploy/baremetal/fence.py (G1, #432): the fenced servers powered off through their iLOs, against a local Redfish
stand-in over real TLS. Each refusal by its own message; nothing is sent before the pin holds."""
import hashlib
import json

from deploy.baremetal import fence as fe, heartbeat

INVENTORY = {"schema": fe.INVENTORY_SCHEMA, "nodes": {
    n: {"ilo": "ilo-%s.mgmt.example" % n, "ilo_cert_sha256": hashlib.sha256(b"ilo cert " + n.encode()).hexdigest(),
        "serial": "CZJ5%04dQ" % i, "uuid": "30373737-3632-435a-4a35-3%011d" % i} for i, n in enumerate("abc")}}
BOXES = fe.inventory(INVENTORY)


def redfish_evidence(nodes=("b", "c"), day="2026-10-05", state="Off"):
    """The evidence fence() makes for `nodes`, read Off at 11:59:00 and again 10 s later on `day`: the shared test shape."""
    from deploy.baremetal import survivor
    at = heartbeat.parse_time(day + "T11:59:00Z", "read_at")
    return {"method": "redfish", "nodes": {n: {"power_state": state, "read_at": survivor._stamp(at), "read_again_at": survivor._stamp(at + fe.REREAD_S),
                                               "serial": BOXES[n]["serial"], "uuid": BOXES[n]["uuid"],
                                               "ilo_cert_sha256": BOXES[n]["ilo_cert_sha256"], "power_restore_policy": "RestoreLastState"}
                                           for n in nodes}}


import base64  # noqa: E402
import contextlib  # noqa: E402
import datetime  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import ssl  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import unittest  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from deploy.baremetal import membership as m, redfish, survivor as sv  # noqa: E402


def self_signed(directory):
    """A throwaway iLO-like certificate (self-signed, P-256) and its SHA-256 pin."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ilo.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    paths = os.path.join(directory, "c.pem"), os.path.join(directory, "k.pem")
    with open(paths[0], "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(paths[1], "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return paths, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


class Ilo:
    """An iLO 4's Redfish, as much as the fence reads: accounts, Systems/1, its BIOS, the reset action."""

    def __init__(self, serial, uuid):
        self.serial, self.uuid = serial, uuid
        self.power, self.requests, self.posts = "On", [], []
        self.privileges = {"LoginPriv": True, "VirtualPowerAndResetPriv": True, "RemoteConsolePriv": False, "UserConfigPriv": False,
                           "iLOConfigPriv": False, "VirtualMediaPriv": False}
        self.username, self.off_after = "fence", 0
        self.back_on_after_reads, self.reads_after_post = None, 0

    def answer(self, method, path, body, auth):
        self.requests.append((method, path, auth))
        path = path.rstrip("/") + "/"                                  # redfish.py asks without the slash, the links have it
        if path == "/redfish/v1/Managers/1/":
            return {"FirmwareVersion": "2.82 Feb 06 2023"}
        if path == "/redfish/v1/AccountService/Accounts/":
            return {"Members": [{"@odata.id": "/redfish/v1/AccountService/Accounts/1/"}, {"@odata.id": "/redfish/v1/AccountService/Accounts/2/"}]}
        if path == "/redfish/v1/AccountService/Accounts/1/":
            return {"UserName": "Administrator", "Oem": {"Hp": {"Privileges": {k: True for k in self.privileges}}}}
        if path == "/redfish/v1/AccountService/Accounts/2/":
            return {"UserName": self.username, "Oem": {"Hp": {"Privileges": self.privileges}} if isinstance(self.privileges, dict) else {}}
        if path == "/redfish/v1/Systems/1/":
            if self.power == "PoweringOff":
                self.off_after -= 1
                if self.off_after < 0:
                    self.power = "Off"
            if self.posts and self.back_on_after_reads is not None:
                self.reads_after_post += 1
                if self.reads_after_post > self.back_on_after_reads:
                    self.power = "On"
            return {"SerialNumber": self.serial, "UUID": self.uuid, "Model": "ProLiant DL360 Gen9", "Manufacturer": "HP",
                    "PowerState": "On" if self.power == "PoweringOff" else self.power,
                    "Actions": {"#ComputerSystem.Reset": {"target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/",
                                                          "ResetType@Redfish.AllowableValues": ["On", "ForceOff", "ForceRestart", "Nmi",
                                                                                                "PushPowerButton"]}}}
        if path == "/redfish/v1/Systems/1/Bios/":
            return {"AutoPowerOn": "RestoreLastState"}
        if path == "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/" and method == "POST":
            self.posts.append(body)
            self.power = "PoweringOff" if self.off_after else "Off"
            return {}
        return None


class Stand(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fence-")
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)
        (cert, key), self.pin = self_signed(self.dir)
        self.ilos = {n: Ilo(BOXES[n]["serial"], BOXES[n]["uuid"]) for n in ("b", "c")}
        self.servers = {}
        for n, ilo in self.ilos.items():
            self.servers[n] = self.serve(ilo, cert, key)
        hosts = {"b": "localhost", "c": "127.0.0.1"}                   # the client speaks to port 443: each stand-in by its name
        self.ports = {hosts[n]: self.servers[n].server_address[1] for n in ("b", "c")}
        self.boxes = {n: dict(BOXES[n], ilo=hosts[n], ilo_cert_sha256=self.pin) for n in ("b", "c")}
        self.creds = {n: {"username": "fence", "password": "s3cret-" + n} for n in ("b", "c")}
        self.t = [1791201540.0]                      # 2026-10-05T11:59:00Z

    def serve(self, ilo, cert, key):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                got = ilo.answer(method, self.path, body, self.headers.get("Authorization"))
                raw = json.dumps(got).encode() if got is not None else b"{}"
                self.send_response(200 if got is not None else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.handle_error = lambda request, address: None         # a client that hangs up after a pin mismatch: expected
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def now(self):
        return self.t[0]

    def sleep(self, seconds):
        self.t[0] += seconds

    def fence(self, nodes=("b", "c"), boxes=None):
        return fe.fence(boxes or self.boxes, list(nodes), self.creds, now=self.now, sleep=self.sleep, transport=self.transport)

    def transport(self, box, user, password):
        return redfish.PinnedHTTPS(box["ilo"], box["ilo_cert_sha256"], user, password, timeout=5, port=self.ports[box["ilo"]])

    def refused(self, reason, **kw):
        with self.assertRaises(m.Refused) as caught:
            self.fence(**kw)
        self.assertIn(reason, str(caught.exception))


class Fence(Stand):
    def test_each_box_bound_forced_off_and_read_off_twice(self):
        self.ilos["b"].off_after = 2                                   # a few readbacks before it reads Off
        evidence = self.fence()
        self.assertEqual(set(evidence["nodes"]), {"b", "c"})
        b = evidence["nodes"]["b"]
        self.assertEqual(set(b), set(fe.EVIDENCE_KEYS))
        self.assertEqual((b["serial"], b["uuid"], b["ilo_cert_sha256"], b["power_restore_policy"]),
                         (BOXES["b"]["serial"], BOXES["b"]["uuid"], self.pin, "RestoreLastState"))
        self.assertGreaterEqual(heartbeat.parse_time(b["read_again_at"], "x") - heartbeat.parse_time(b["read_at"], "x"), fe.REREAD_S)
        self.assertEqual(self.ilos["b"].posts, [{"ResetType": "ForceOff"}])
        wanted = "Basic " + base64.b64encode(b"fence:s3cret-b").decode()
        self.assertTrue(all(r[2] == wanted for r in self.ilos["b"].requests))
        sv.validate_authorization(dict(raw_full(), fence=evidence))       # the shape survivor.py requires

    def test_nothing_is_sent_to_an_iLO_whose_certificate_is_not_the_pinned_one(self):
        boxes = dict(self.boxes, b=dict(self.boxes["b"], ilo_cert_sha256="ab" * 32))
        self.refused("not the pinned %s: nothing was sent" % ("ab" * 32), boxes=boxes)
        self.assertEqual(self.ilos["b"].requests, [])                  # not one request, so no password

    def test_only_a_fence_only_account(self):
        self.ilos["b"].privileges["UserConfigPriv"] = True
        self.refused("holds UserConfigPriv: the fence uses a fence-only account")
        self.ilos["b"].privileges["UserConfigPriv"] = False
        self.ilos["b"].privileges["VirtualPowerAndResetPriv"] = False
        self.refused("cannot power the server off")
        self.ilos["b"].privileges = "hidden"                         # the record shows no privileges at all
        self.refused("shows no privileges for fence: a fence account the fence cannot check is refused")
        self.ilos["b"].username = "someone-else"
        self.refused("does not show the account fence")
        self.assertEqual(self.ilos["b"].posts, [])

    def test_the_right_box_or_nothing(self):
        self.ilos["b"].serial = "CZJ59999Q"
        self.refused("manages server 'CZJ59999Q', not CZJ50001Q: nothing is done to it")
        self.ilos["b"].serial, self.ilos["b"].uuid = BOXES["b"]["serial"], "30373737-3632-435a-4a35-399999999999"
        self.refused("reports UUID 30373737-3632-435a-4a35-399999999999")
        self.ilos["b"].uuid = ""                                       # an iLO that shows no UUID at all
        self.refused("b's iLO shows no system UUID")
        self.assertEqual(self.ilos["b"].posts, [])

    def test_a_server_that_never_reads_off_or_comes_back_is_not_fenced(self):
        self.ilos["b"].off_after = 10 ** 6
        self.refused("did not read Off within 60 s after ForceOff")
        self.setUp()
        self.ilos["b"].back_on_after_reads = 1                         # Off at the client's readback, On at the fence's second
        self.refused("read Off, then 'On' 10 s later: something turned it back on")

    def test_two_readbacks_closer_than_the_wait_are_refused(self):
        self.sleep = lambda seconds: None                               # a clock that does not move
        self.refused("b's two Off readbacks are less than 10 s apart by this machine's clock")

    def test_already_off_is_read_twice_and_not_forced(self):
        self.ilos["c"].power = "Off"
        evidence = self.fence(("c",))
        self.assertEqual(self.ilos["c"].posts, [])
        self.assertEqual(evidence["nodes"]["c"]["power_state"], "Off")

    def test_the_inventory_is_checked(self):
        bad = json.loads(json.dumps(INVENTORY))
        bad["nodes"]["b"]["ilo_cert_sha256"] = "zz"
        with self.assertRaises(m.Refused):
            fe.inventory(bad)
        bad = json.loads(json.dumps(INVENTORY))
        bad["nodes"]["b"]["ilo"] = "ilo-b:8443"
        with self.assertRaises(m.Refused) as caught:
            fe.inventory(bad)
        self.assertIn("b's ilo is a host name or IPv4 address", str(caught.exception))
        with self.assertRaises(m.Refused) as caught:
            fe.inventory(INVENTORY, ["d"])
        self.assertIn("no box for d", str(caught.exception))


def raw_full():
    return {"schema": sv.AUTH_SCHEMA, "node_id": "a", "quarantine_epoch": 2, "quarantine_digest": "00" * 32,
            "not_before": "2026-10-05T12:00:00Z", "expires_at": "2026-10-06T12:00:00Z", "fenced": "b, c: off", "scope": "full"}


class TheEvidenceSurvivorTakes(unittest.TestCase):
    def test_two_readbacks_at_least_ten_seconds_apart(self):
        evidence = redfish_evidence()
        evidence["nodes"]["b"]["read_again_at"] = "2026-10-05T11:59:05Z"
        with self.assertRaises(m.Refused) as caught:
            sv.validate_authorization(dict(raw_full(), fence=evidence))
        self.assertIn("reads Off twice at least 10 s apart", str(caught.exception))
        evidence = redfish_evidence()
        del evidence["nodes"]["b"]["serial"]
        with self.assertRaises(m.Refused):
            sv.validate_authorization(dict(raw_full(), fence=evidence))


class OwnerFence(Stand):
    def test_owner_py_fence_reads_the_credentials_from_a_pipe_and_writes_the_evidence(self):
        from deploy.baremetal import owner
        inventory = os.path.join(self.dir, "inv.json")
        with open(inventory, "w") as f:
            json.dump({"schema": fe.INVENTORY_SCHEMA, "nodes": self.boxes}, f)
        read, write = os.pipe()
        os.write(write, json.dumps(self.creds).encode())
        os.close(write)
        fd = os.dup2(read, 9) if read != 9 else read
        if read != 9:
            os.close(read)
        out = os.path.join(self.dir, "fence.json")
        sleeps, clock = [], [1791201540.0]

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds
        real = redfish.PinnedHTTPS
        on_port = lambda host, pin, user, password: real(host, pin, user, password, timeout=5, port=self.ports[host])  # noqa: E731
        with unittest.mock.patch.object(fe.time, "sleep", sleep), unittest.mock.patch.object(fe.time, "time", lambda: clock[0]), \
                unittest.mock.patch.object(fe.redfish, "PinnedHTTPS", on_port), \
                contextlib.redirect_stdout(io.StringIO()) as said, \
                contextlib.redirect_stderr(io.StringIO()) as complained:
            got = owner.main(["fence", "--inventory", inventory, "--node", "b", "--node", "c", "--credentials-fd", str(fd), "--out", out])
        self.assertEqual(got, 0, said.getvalue() + complained.getvalue())
        evidence = json.load(open(out))
        self.assertEqual(set(evidence["nodes"]), {"b", "c"})
        self.assertIn("FENCED: b Off at", said.getvalue())
        self.assertIn(fe.REREAD_S, sleeps)
        with self.assertRaises(OSError):
            os.fstat(fd)                                               # the descriptor is closed after its read


import unittest.mock  # noqa: E402,F811

if __name__ == "__main__":
    unittest.main()
