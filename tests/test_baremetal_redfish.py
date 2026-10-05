"""deploy/baremetal/redfish.py: the iLO client the drills (#495) and D32's G1 fence (#432) share, against a stand-in
Redfish service, and its certificate pin against a real local TLS server."""
import datetime
import hashlib
import json
import os
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from deploy.baremetal import redfish
from deploy.baremetal.membership import Refused

ILO4_TYPES = ["On", "ForceOff", "ForceRestart", "Nmi", "PushPowerButton"]


class StandIn:
    """A Redfish service as iLO 4 answers: a system that turns Off (or On) `lag` polls after a reset."""

    def __init__(self, serial="CZJ1234567", power="On", firmware="2.82 Feb 06 2023", types=None, lag=2, reset_status=200):
        self.serial, self.power, self.firmware, self.lag, self.reset_status = serial, power, firmware, lag, reset_status
        self.types = ILO4_TYPES if types is None else types
        self.posts, self.pending = [], None

    def request(self, method, path, body=None):
        if method == "GET" and path == redfish.SYSTEM:
            if self.pending:
                self.pending[1] -= 1
                if self.pending[1] <= 0:
                    self.power, self.pending = self.pending[0], None
            action = {"target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/"}
            if self.types is not False:
                action["ResetType@Redfish.AllowableValues"] = self.types
            return 200, {"SerialNumber": self.serial, "Model": "ProLiant DL360 Gen9", "Manufacturer": "HPE", "PowerState": self.power,
                         "Actions": {"#ComputerSystem.Reset": action}}
        if method == "GET" and path == redfish.MANAGER:
            return 200, {"FirmwareVersion": self.firmware}
        if method == "POST" and path.endswith("ComputerSystem.Reset/"):
            self.posts.append(body)
            if self.reset_status == 200:
                self.pending = [{"ForceOff": "Off", "On": "On"}.get(body["ResetType"], self.power), self.lag]
            return self.reset_status, None
        return 404, None


class Clock:
    def __init__(self):
        self.ms = 1_000_000

    def __call__(self):
        return self.ms

    def sleep(self, seconds):
        self.ms += int(seconds * 1000)


def client(service, serial="CZJ1234567"):
    clock = Clock()
    return redfish.Client(service, serial, "ilo-b.mgmt", "ab" * 32, clock=clock, sleep=clock.sleep)


class Power(unittest.TestCase):
    def test_force_off_is_done_only_when_the_readback_says_off(self):
        service = StandIn(lag=3)
        record = client(service).force_off()
        self.assertEqual(service.posts, [{"ResetType": "ForceOff"}])
        self.assertEqual((record["outcome"], record["reset_type"], record["serial"]), ("Off", "ForceOff", "CZJ1234567"))
        self.assertEqual([r["power"] for r in record["readbacks"]], ["On", "On", "On", "Off"])     # before, then each poll
        self.assertTrue(all(isinstance(r["at_ms"], int) for r in record["readbacks"]))
        self.assertEqual((record["firmware"], record["cert_sha256"], record["power_before"]), ("2.82 Feb 06 2023", "ab" * 32, "On"))

    def test_power_on_is_force_off_s_undo_and_the_journal_s(self):
        service = StandIn(power="Off", lag=1)
        record = redfish.undoers(lambda node: client(service))["power-on"]("b")
        self.assertEqual((service.posts, record["outcome"]), ([{"ResetType": "On"}], "On"))

    def test_already_in_the_state_sends_nothing(self):
        service = StandIn(power="Off")
        record = client(service).force_off()
        self.assertEqual((service.posts, record["outcome"]), ([], "already Off: nothing sent"))

    def test_a_server_that_does_not_go_off_in_time_is_a_refusal_with_its_readbacks(self):
        service = StandIn(lag=10 ** 6)
        with self.assertRaisesRegex(Refused, r"did not read Off within 60 s after ForceOff \(last 'On'\): readbacks"):
            client(service).force_off()


class Refusals(unittest.TestCase):
    def test_the_wrong_box_is_never_touched(self):
        service = StandIn(serial="CZJ7654321")
        with self.assertRaisesRegex(Refused, r"manages server 'CZJ7654321', not CZJ1234567: nothing is done to it"):
            client(service).force_off()
        self.assertEqual(service.posts, [])

    def test_a_reset_type_the_ilo_does_not_list_is_never_sent(self):
        service = StandIn(types=["On", "ForceRestart"])
        with self.assertRaisesRegex(Refused, r"does not offer ResetType ForceOff \(it offers ForceRestart, On\): nothing was sent"):
            client(service).force_off()
        self.assertEqual(service.posts, [])

    def test_no_allowable_values_means_nothing_is_assumed(self):
        service = StandIn(types=False)
        with self.assertRaisesRegex(Refused, r"lists no ResetType@Redfish.AllowableValues: nothing is assumed"):
            client(service).force_off()
        self.assertEqual(service.posts, [])

    def test_firmware_below_redfish_is_refused(self):
        for firmware, refused in (("2.20 May 20 2015", True), ("2.30 Sep 09 2015", False), ("iLO 4 v2.82", False), ("unknown", True)):
            with self.subTest(firmware=firmware):
                service = StandIn(firmware=firmware)
                if refused:
                    with self.assertRaises(Refused):
                        client(service).discover()
                else:
                    self.assertEqual(client(service).discover()["firmware"], firmware)

    def test_a_reset_the_ilo_refuses_is_said(self):
        service = StandIn(reset_status=400)
        with self.assertRaisesRegex(Refused, r"refused ResetType ForceOff with HTTP 400"):
            client(service).force_off()

    def test_ilo_4_s_reset_types_have_no_graceful_restart(self):
        """Pinned from the design (#495): a graceful restart is in-band, never this client's. To be confirmed on our iLO
        firmware by the discovery this client records."""
        self.assertNotIn("GracefulRestart", ILO4_TYPES)
        self.assertFalse(hasattr(redfish.Client, "graceful_restart"))

    def test_the_password_file_must_be_the_caller_s_and_0600(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: [os.unlink(os.path.join(d, n)) for n in os.listdir(d)] and None or os.rmdir(d))
        path = os.path.join(d, "pw")
        with open(path, "w") as f:
            f.write("s3cret\n")
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(Refused, "mode 0600"):
            redfish.read_password(path)
        os.chmod(path, 0o600)
        self.assertEqual(redfish.read_password(path), "s3cret")
        os.symlink(path, os.path.join(d, "link"))
        with self.assertRaisesRegex(Refused, "mode 0600"):
            redfish.read_password(os.path.join(d, "link"))


def self_signed():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ILO-STANDIN")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return key, cert


class Pin(unittest.TestCase):
    """The pin against a real TLS server on loopback: a mismatched certificate refuses BEFORE the request (and the
    credentials in it) is sent; the pinned one is answered."""

    def setUp(self):
        key, cert = self_signed()
        self.digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: [os.unlink(os.path.join(d, n)) for n in os.listdir(d)] and None or os.rmdir(d))
        cert_path, key_path = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.received = []

        def serve():
            while True:
                try:
                    raw, _ = self.listener.accept()
                except OSError:
                    return
                try:
                    with context.wrap_socket(raw, server_side=True) as conn:
                        data = conn.recv(65536)
                        self.received.append(data)
                        if data:
                            body = json.dumps({"FirmwareVersion": "2.82"}).encode()
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
                except (ssl.SSLError, OSError):
                    pass
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        self.addCleanup(self.listener.close)

    def test_the_pinned_certificate_is_answered(self):
        transport = redfish.PinnedHTTPS("127.0.0.1", self.digest, "fence", "pw", timeout=5, port=self.port)
        self.assertEqual(transport.request("GET", redfish.MANAGER), (200, {"FirmwareVersion": "2.82"}))
        self.assertIn(b"Authorization: Basic ", self.received[-1])

    def test_another_certificate_is_refused_and_nothing_is_sent(self):
        transport = redfish.PinnedHTTPS("127.0.0.1", "00" * 32, "fence", "pw", timeout=5, port=self.port)
        with self.assertRaisesRegex(Refused, r"presents certificate %s, not the pinned 0{64}: nothing was sent" % self.digest):
            transport.request("GET", redfish.MANAGER)
        self.assertFalse(any(b"Authorization" in r for r in self.received))

    def test_the_pin_s_form_is_checked(self):
        with self.assertRaisesRegex(Refused, "64 lowercase hex"):
            redfish.PinnedHTTPS("127.0.0.1", "AB" * 32, "fence", "pw")


if __name__ == "__main__":
    unittest.main()
