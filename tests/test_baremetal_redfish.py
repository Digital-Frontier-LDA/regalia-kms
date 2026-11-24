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

# The Gen9's BIOS attribute registry in the iLO 4's own form (the shape the client discovers, never assumes): one
# TPM-operation attribute, its ValueNames (NoAction, Clear, Disable, Enable), the pending-settings URI the iLO
# itself names. Tpm2Operation (the TPM 2.0 module) is the alternate name the discovery must also accept -- and
# refuse when both or neither are listed.
ILO4_BIOS_ATTRS = [
    {"AttributeName": "TpmOperation", "CurrentValue": "NoAction", "ValueType": "Enum", "ValueNames":
     ["NoAction", "Clear", "Disable", "Enable"], "ReadOnly": False},
]


class StandIn:
    """A Redfish service as iLO 4 answers: a system that turns Off (or On) `lag` polls after a reset, and (for the
    tpm-* verbs) a BIOS resource whose attribute registry the client discovers. The pending settings read the value
    a PATCH stored; the live attribute stays at that value until a ForceRestart has happened and `consume_lag`
    Bios/ reads have passed (consumes=False: it never does -- the timeout case). The live value the client sees is
    'NoAction' before any PATCH, the pending value after one, the no-action value once consumed."""

    def __init__(self, serial="CZJ1234567", power="On", firmware="2.82 Feb 06 2023", types=None, lag=2, reset_status=200,
                 bios=None, registry_status=200, settings_status=200, consume_lag=2, consumes=True):
        self.serial, self.power, self.firmware, self.lag, self.reset_status = serial, power, firmware, lag, reset_status
        self.types = ILO4_TYPES if types is None else types
        self.posts, self.pending, self.settings_patches = [], None, []
        # A bios of False: the Bios resource lists no AttributeRegistry (the refusal case, "nothing is assumed").
        # True (the default for the tpm tests): the iLO 4's Gen9 form, naming the registry and the settings URI.
        self.bios = False if not bios else {
            "AttributeRegistry": "HPE_2.10.0",
            "@Redfish.Settings.SettingsObject": "/redfish/v1/Systems/1/Bios/Settings/",
        }
        self.bios_attrs = ILO4_BIOS_ATTRS
        self.bios_attr_name = "TpmOperation"
        self.bios_state = {"live": "NoAction", "pending": "NoAction", "reads_since_restart": 0, "restarted": False,
                           "restart_power_lag": None}               # set by the client's restart, cleared when the power lands
        self.registry_status, self.settings_status, self.consume_lag, self.consumes = registry_status, settings_status, consume_lag, consumes

    def _tpm_live(self):
        # 'live' is a value the client did NOT set (a foreign state): it stands whatever the pending settings say.
        # Otherwise the live value mirrors the pending one, until the server is read back On after a restart and
        # `consume_lag` Bios/ reads have passed (consumes=False: it never does -- the timeout case).
        if self.bios_state["live"] != "NoAction":
            return self.bios_state["live"]
        if self.bios_state["pending"] == "NoAction":
            return "NoAction"
        if self.bios_state["restarted"] and self.consumes and self.bios_state["reads_since_restart"] >= self.consume_lag:
            return "NoAction"                                     # consumed: the iLO has applied the setting
        return self.bios_state["pending"]                          # pending (or a restart that never consumed)

    def request(self, method, path, body=None):
        # The iLO's own spelling, NOT redfish.SYSTEM: comparing against the constant would accept whatever it says.
        # A slash-less path gets the 308 iLO 4 answers (#670).
        if not path.endswith("/"):
            return 308, None
        if method == "GET" and path == "/redfish/v1/Systems/1/":
            if self.pending:
                self.pending[1] -= 1
                if self.pending[1] <= 0:
                    self.power, self.pending = self.pending[0], None
                    if self.bios_state["restarted"] and self.power == "On":
                        # the power has landed: from now, Bios/ reads count toward the consumption
                        self.bios_state["restart_power_lag"] = None
            action = {"target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/"}
            if self.types is not False:
                action["ResetType@Redfish.AllowableValues"] = self.types
            return 200, {"SerialNumber": self.serial, "Model": "ProLiant DL360 Gen9", "Manufacturer": "HPE", "PowerState": self.power,
                         "Actions": {"#ComputerSystem.Reset": action}}
        if method == "GET" and path == "/redfish/v1/Managers/1/":
            return 200, {"FirmwareVersion": self.firmware}
        if method == "GET" and path == "/redfish/v1/Systems/1/Bios/":
            if not self.bios:
                return 200, {"Attributes": []}                     # no AttributeRegistry named: the client must refuse
            if self.bios_state["restarted"] and self.power == "On" and self.bios_state["restart_power_lag"] is None:
                # the restart's own readbacks (discover and the power polling) do not count: the consumption is
                # counted from the readbacks that come AFTER the server is read back On.
                self.bios_state["reads_since_restart"] += 1
            return 200, {**self.bios, "Attributes": [{"AttributeName": self.bios_attr_name, "Value": self._tpm_live()}]}
        if method == "GET" and path == "/redfish/v1/Systems/1/Bios/Settings/":
            return self.settings_status, {"Attributes": [{"AttributeName": self.bios_attr_name, "Value": self.bios_state["pending"]}]}
        if method == "GET" and path == "/redfish/v1/Registries/":
            return 200, {"Registries": [{"Id": "HPE_2.10.0", "Name": "HPE BIOS registry",
                                         "Location": {"Language": "en-US", "Uri": "/redfish/v1/Registries/HPE_2.10.0/"}}]}
        if method == "GET" and path == "/redfish/v1/Registries/HPE_2.10.0/":
            return self.registry_status, {"Id": "HPE_2.10.0", "Attributes": self.bios_attrs}
        if method == "POST" and path.endswith("ComputerSystem.Reset/"):
            self.posts.append(body)
            if self.reset_status == 200:
                self.pending = [{"ForceOff": "Off", "On": "On"}.get(body["ResetType"], self.power), self.lag]
                if body["ResetType"] == "ForceRestart" and self.bios_state["pending"] != "NoAction":
                    self.bios_state["restarted"] = True            # the consumption counts from the readbacks after the power lands
                    self.bios_state["reads_since_restart"] = 0
            return self.reset_status, None
        if method == "PATCH" and path == "/redfish/v1/Systems/1/Bios/Settings/":
            attrs = body["Attributes"]
            attr = attrs.get(self.bios_attr_name, next(iter(attrs.values()), None))
            self.settings_patches.append({"uri": path, "body": body})
            self.bios_state["pending"] = attr
            return self.settings_status, None
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

    def test_force_restart_is_sent_to_a_server_that_reads_on(self):
        """The undo of a restart that did not come back (d9 on #504): a hung server is still On, so On would do nothing."""
        service = StandIn(power="On", lag=1)
        record = client(service).force_restart()
        self.assertEqual(service.posts, [{"ResetType": "ForceRestart"}])
        self.assertEqual((record["action"], record["reset_type"], record["outcome"]), ("power-cycle", "ForceRestart", "On"))

    def test_force_restart_powers_on_a_server_found_off(self):
        service = StandIn(power="Off", lag=1)
        record = client(service).force_restart()
        self.assertEqual((service.posts, record["action"], record["outcome"]), ([{"ResetType": "On"}], "power-cycle", "On"))

    def test_the_journal_s_undoers_cover_the_power_faults_and_the_pending_clear(self):
        service = StandIn(power="On", lag=1, bios=True)
        undo = redfish.undoers(lambda node: client(service))
        self.assertEqual(sorted(undo), ["power-cycle", "power-on", "tpm-pending-revert"])
        self.assertEqual(undo["power-cycle"]("b")["reset_type"], "ForceRestart")
        self.assertEqual(undo["tpm-pending-revert"]("b")["outcome"], "nothing pending: nothing sent")

    def test_already_in_the_state_sends_nothing(self):
        service = StandIn(power="Off")
        record = client(service).force_off()
        self.assertEqual((service.posts, record["outcome"]), ([], "already Off: nothing sent"))

    def test_one_failed_poll_is_a_readback_and_the_fence_still_completes(self):
        """3e on #501: a single iLO timeout mid-poll must not end a fence whose next readback says Off."""
        service = StandIn(lag=3)
        real, calls = service.request, {"n": 0}

        def flaky(method, path, body=None):
            if method == "GET" and path == redfish.SYSTEM and service.posts:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise Refused("the iLO at ilo-b.mgmt did not answer GET /redfish/v1/Systems/1: timed out")
            return real(method, path, body)
        service.request = flaky
        record = client(service).force_off()
        self.assertEqual(record["outcome"], "Off")
        self.assertIn("timed out", record["readbacks"][1]["error"])
        self.assertEqual(record["readbacks"][-1]["power"], "Off")

    def test_another_server_answering_mid_poll_ends_it_at_once(self):
        service = StandIn(lag=5)
        real = service.request

        def swapped(method, path, body=None):
            status, answer = real(method, path, body)
            if method == "GET" and path == redfish.SYSTEM and service.posts:
                answer = dict(answer, SerialNumber="CZJ0000000")
            return status, answer
        service.request = swapped
        with self.assertRaisesRegex(redfish.WrongServer, "changed servers mid-action"):
            client(service).force_off()

    def test_already_off_is_fenced_on_the_readback_alone(self):
        record = client(StandIn(power="Off")).force_off()
        self.assertEqual((record["reset_type"], record["readbacks"][0]["power"]), (None, "Off"))
        self.assertIn("accepts it as fenced on that readback", redfish.Client.force_off.__doc__)

    def test_a_server_that_does_not_go_off_in_time_is_a_refusal_with_its_readbacks(self):
        service = StandIn(lag=10 ** 6)
        with self.assertRaisesRegex(Refused, r"did not read Off within 60 s after ForceOff \(last 'On'\): readbacks"):
            client(service).force_off()


class Tpm(unittest.TestCase):
    """tpm-status / tpm-clear / tpm-proof: the staging DL360's clear over the BIOS settings resource, discovered, never
    assumed, and applied only when its operator said apply. The proof comes from the HOST, never inferred from the iLO."""

    def test_a_dry_run_reads_the_state_and_sends_nothing(self):
        service = StandIn(bios=True)
        record = client(service).tpm_clear(apply=False)
        self.assertEqual((service.posts, service.settings_patches), ([], []))
        self.assertEqual((record["outcome"], record["attribute"], record["clear"]), ("dry-run: nothing was sent", "TpmOperation", "Clear"))
        self.assertEqual(record["plan"], {"uri": "/redfish/v1/Systems/1/Bios/Settings/",
                                          "body": {"Attributes": {"TpmOperation": "Clear"}}})
        self.assertEqual(record["status"]["current"], "NoAction")

    def test_apply_patches_the_pending_and_waits_until_consumed(self):
        service = StandIn(bios=True, consume_lag=2)
        try:
            record = client(service).tpm_clear(apply=True)
        except Refused as refusal:
            # a wrong request (the mutants) is refused by the readback, not sent silently: the PATCH that WAS
            # sent must still be the right one, and the refusal must say why
            self.fail("the clear was refused, not consumed: %s" % refusal)
        self.assertEqual(service.settings_patches, [{"uri": "/redfish/v1/Systems/1/Bios/Settings/",
                                                     "body": {"Attributes": {"TpmOperation": "Clear"}}}])
        self.assertEqual([p["ResetType"] for p in service.posts], ["ForceRestart"])
        self.assertEqual(record["outcome"], "consumed")
        self.assertIn("consumed_before", record["live_readbacks"][-1])
        self.assertEqual((record["attribute"], record["http_status"]), ("TpmOperation", 200))

    def test_a_pending_that_is_not_consumed_times_out_as_a_refusal_with_its_readbacks(self):
        service = StandIn(bios=True, consumes=False)
        with self.assertRaisesRegex(Refused, r"TPM operation Clear was not consumed within \d+ s \(after the restart\): pending readbacks"):
            client(service).tpm_clear(apply=True)
        self.assertEqual(service.settings_patches[0]["body"], {"Attributes": {"TpmOperation": "Clear"}})   # the PATCH stands: the undoer's to revert

    def test_tpm2_operation_is_the_alternate_name_the_discovery_accepts(self):
        service = StandIn(bios=True)
        service.bios_attr_name = "Tpm2Operation"
        service.bios_attrs = [dict(a, AttributeName="Tpm2Operation") for a in service.bios_attrs]
        record = client(service).tpm_clear(apply=False)
        self.assertEqual(record["plan"]["body"], {"Attributes": {"Tpm2Operation": "Clear"}})

    def test_the_undoer_reverts_a_still_pending_clear(self):
        service = StandIn(bios=True)
        undo = redfish.undoers(lambda node: client(service))["tpm-pending-revert"]
        self.assertEqual(undo("b")["outcome"], "nothing pending: nothing sent")
        service.bios_state["pending"] = "Clear"
        record = undo("b")
        self.assertEqual(record["outcome"], "reverted (a clear the server already consumed cannot be undone)")
        self.assertEqual(service.bios_state["pending"], "NoAction")

    # the host's capture (tpm2_getcap properties-variable, TPM 2.0 order: 0 fixedTPM, 1 ownerAuthSet, 2 disableClear,
    # 3 lockoutAuthSet, ...) and its handles-persistent: the run feeds them to tpm-proof; nothing is inferred from the iLO.
    OK_PROPS = "TPM2_DATA:0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0\n"
    OK_HANDLES = "0x81010001\n"

    def test_the_host_s_proof_is_the_verdict_not_the_ilo(self):
        self.assertEqual(redfish.tpm_proof(self.OK_PROPS, self.OK_HANDLES, ["0x81010001"]),
                         {"ownerAuthSet": False, "lockoutAuthSet": False, "persistent_handles": ["0x81010001"], "pass": True})

    def test_a_proof_the_host_fails_is_said_as_such(self):
        for i, why in ((1, "ownerAuthSet"), (3, "lockoutAuthSet")):
            props = "TPM2_DATA:%s\n" % ",".join("1" if j == i else "0" for j in range(28))
            verdict = redfish.tpm_proof(props, self.OK_HANDLES, ["0x81010001"])
            self.assertFalse(verdict["pass"])
            self.assertTrue(verdict[why])
        verdict = redfish.tpm_proof(self.OK_PROPS, "0x81010001\n0x81020003\n", ["0x81010001"])
        self.assertFalse(verdict["pass"])
        self.assertEqual(verdict["persistent_handles"], ["0x81010001", "0x81020003"])

    def test_the_cli_never_echoes_the_password(self):
        """The tpm-* verbs' main() prints only the record: a refusal on the dry run says the state, never the iLO
        password that went to it (as the power paths' --password-fd, tested in PasswordFd)."""
        import contextlib
        import io
        service = StandIn(bios=True, serial="CZJ0000000")                       # a refusal that names the OTHER server
        clock = Clock()
        given = []

        class Transport:
            def __init__(self, ilo, cert_sha256, user, password, **kw):
                given.append(password)

        real_client, real_transport = redfish.Client, redfish.PinnedHTTPS

        def make_client(*a, **kw):
            # a = (transport, serial, ilo, cert_sha256); the stand-in plays the transport
            return real_client(service, a[1], a[2], a[3], clock=clock, sleep=clock.sleep)

        redfish.PinnedHTTPS = Transport
        redfish.Client = make_client
        out, err = io.StringIO(), io.StringIO()
        r, w = os.pipe()
        os.write(w, b"iL0secret\n")
        os.close(w)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = redfish.main(["tpm-clear", "--ilo", "192.0.2.10", "--serial", "CZJ1234567",
                                     "--cert-sha256", "00" * 32, "--user", "test-user", "--password-fd", str(r)])
        finally:
            redfish.Client, redfish.PinnedHTTPS = real_client, real_transport
        text = out.getvalue() + err.getvalue()
        self.assertEqual((code, given), (1, ["iL0secret"]))
        self.assertIn("refused: the iLO at 192.0.2.10 manages server 'CZJ0000000', not CZJ1234567", err.getvalue())
        self.assertNotIn("iL0secret", text)

    def test_the_cli_s_dry_run_prints_the_plan_and_never_a_patch(self):
        import contextlib
        import io
        service = StandIn(bios=True)
        clock = Clock()

        class Transport:
            def __init__(self, *a, **kw):
                pass

        real_client, real_transport = redfish.Client, redfish.PinnedHTTPS

        def make_client(*a, **kw):
            return real_client(service, a[1], a[2], a[3], clock=clock, sleep=clock.sleep)

        redfish.PinnedHTTPS = Transport
        redfish.Client = make_client
        out, err = io.StringIO(), io.StringIO()
        r, w = os.pipe()
        os.write(w, b"pw\n")
        os.close(w)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = redfish.main(["tpm-clear", "--ilo", "192.0.2.10", "--serial", "CZJ1234567",
                                     "--cert-sha256", "00" * 32, "--user", "test-user", "--password-fd", str(r)])
        finally:
            redfish.Client, redfish.PinnedHTTPS = real_client, real_transport
        self.assertEqual((code, service.settings_patches, service.posts), (0, [], []))
        self.assertIn("dry-run: nothing was sent", out.getvalue())
        self.assertIn('"Clear"', out.getvalue())


class TpmRefusals(unittest.TestCase):
    """Every refusal happens before a PATCH or a POST is sent: the iLO is read, judged, and left untouched."""

    def test_no_registry_named_is_a_refusal_before_anything_is_sent(self):
        service = StandIn(bios=False)
        with self.assertRaisesRegex(Refused, "lists no attribute registry: nothing is assumed"):
            client(service).tpm_status()
        self.assertEqual((service.posts, service.settings_patches), ([], []))

    def test_an_attribute_the_registry_does_not_list_is_refused(self):
        service = StandIn(bios=True)
        service.bios_attrs = [a for a in service.bios_attrs if a["AttributeName"] != "TpmOperation"]
        with self.assertRaisesRegex(Refused, r"lists no TPM-operation attribute \(expected exactly one of TpmOperation, Tpm2Operation\): nothing is assumed"):
            client(service).tpm_status()
        self.assertEqual((service.posts, service.settings_patches), ([], []))

    def test_a_registry_with_neither_operation_attribute_is_refused(self):
        service = StandIn(bios=True)
        service.bios_attrs = [dict(a, AttributeName="Tpm2Operation") for a in service.bios_attrs]
        service.bios_attrs = [dict(a, AttributeName="OtherTpm") for a in service.bios_attrs]
        with self.assertRaisesRegex(Refused, "lists no TPM-operation attribute"):
            client(service).tpm_status()

    def test_both_operation_attributes_listed_is_refused(self):
        service = StandIn(bios=True)
        service.bios_attrs = service.bios_attrs + [dict(a, AttributeName="Tpm2Operation") for a in service.bios_attrs]
        with self.assertRaisesRegex(Refused, r"lists both TPM-operation attribute \(expected exactly one of TpmOperation, Tpm2Operation\): refusing rather than choosing"):
            client(service).tpm_status()

    def test_a_registry_without_a_clear_value_is_refused(self):
        service = StandIn(bios=True)
        service.bios_attrs = [dict(a, ValueNames=["NoAction", "Disable", "Enable"]) for a in service.bios_attrs]
        with self.assertRaisesRegex(Refused, r"lists no Clear value for TpmOperation \(it offers Disable, Enable\): nothing is assumed"):
            client(service).tpm_status()

    def test_a_read_only_attribute_is_refused(self):
        service = StandIn(bios=True)
        service.bios_attrs = [dict(a, ReadOnly=True) for a in service.bios_attrs]
        with self.assertRaisesRegex(Refused, r"as read-only: refused"):
            client(service).tpm_status()

    def test_a_current_value_that_is_not_the_no_action_is_refused(self):
        """A live value the client did not put there (the pending settings are NoAction): the dry run refuses, it does
        not read a foreign state as one of its own."""
        service = StandIn(bios=True)
        service.bios_state["live"] = "Clear"
        with self.assertRaisesRegex(Refused, r"has TpmOperation Clear, not NoAction: another operation may be pending"):
            client(service).tpm_status()

    def test_another_server_is_never_read_for_the_bios(self):
        service = StandIn(bios=True, serial="CZJ7654321")
        with self.assertRaisesRegex(Refused, r"manages server 'CZJ7654321', not CZJ1234567: nothing is done to it"):
            client(service).tpm_status()
        self.assertEqual((service.posts, service.settings_patches), ([], []))

    def test_a_registry_the_ilo_does_not_answer_is_refused(self):
        service = StandIn(bios=True, registry_status=404)
        with self.assertRaisesRegex(Refused, "answered GET /redfish/v1/Registries/HPE_2.10.0/ with HTTP 404"):
            client(service).tpm_status()

    def test_a_settings_the_ilo_refuses_is_refused_and_stays_so(self):
        service = StandIn(bios=True, settings_status=403)
        with self.assertRaisesRegex(Refused, r"refused the pending TPM operation with HTTP 403"):
            client(service).tpm_clear(apply=True)
        self.assertEqual(service.settings_patches[0]["body"], {"Attributes": {"TpmOperation": "Clear"}})     # the refused PATCH stands, said in the record

    def test_a_pending_that_does_not_read_back_is_a_refusal(self):
        service = StandIn(bios=True)
        original = service.request
        patched = {"done": False}

        def stubborn(method, path, body=None):
            status, answer = original(method, path, body)
            if method == "PATCH":
                patched["done"] = True
            if patched["done"] and method == "GET" and path == "/redfish/v1/Systems/1/Bios/Settings/":
                # the iLO accepted the PATCH but the pending value never reads back as Clear
                answer = {"Attributes": [{"AttributeName": "TpmOperation", "Value": "NoAction"}]}
            return status, answer
        service.request = stubborn
        with self.assertRaisesRegex(Refused, "did not read back Clear"):
            client(service).tpm_clear(apply=True)

    def test_apply_without_the_confirmed_serial_is_refused_before_anything_is_sent(self):
        """--apply is a typed confirmation: without --confirm-serial equal to --serial nothing is sent, not even a read."""
        import contextlib
        import io
        service = StandIn(bios=True)
        sent = []

        class Transport:
            def __init__(self, *a, **kw):
                pass

            def request(self, method, path, body=None):
                sent.append((method, path, body))
                return 200, {}

        real_client, real_transport = redfish.Client, redfish.PinnedHTTPS
        redfish.PinnedHTTPS = Transport
        redfish.Client = lambda *a, **kw: real_client(service, a[0], a[1], a[2])
        out, err = io.StringIO(), io.StringIO()
        r, w = os.pipe()
        os.write(w, b"pw\n")
        os.close(w)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = redfish.main(["tpm-clear", "--apply", "--ilo", "192.0.2.10", "--serial", "CZJ1234567",
                                     "--cert-sha256", "00" * 32, "--user", "test-user", "--password-fd", str(r)])
        finally:
            redfish.Client, redfish.PinnedHTTPS = real_client, real_transport
        self.assertEqual((code, sent, service.settings_patches), (1, [], []))
        self.assertIn("--apply requires --confirm-serial", err.getvalue())


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


class PasswordFd(unittest.TestCase):
    """#520: the drills' command reads the owner-card-encrypted iLO password from a pipe (3< <(gpg --decrypt ...)), as the
    fence does, so it is never decrypted to a file. Tested through main(), the argv an operator types."""

    ARGS = ["status", "--ilo", "192.0.2.10", "--serial", "CZ0001", "--cert-sha256", "00" * 32, "--user", "fence"]

    def setUp(self):
        self.given = []
        test = self

        class Transport:
            def __init__(self, ilo, cert_sha256, user, password, **kw):
                test.given.append(password)

        class Client:
            def __init__(self, *args):
                pass

            def discover(self):
                return {"serial": "CZ0001"}

        self.patch("PinnedHTTPS", Transport)
        self.patch("Client", Client)

    def patch(self, name, value):
        old = getattr(redfish, name)
        setattr(redfish, name, value)
        self.addCleanup(setattr, redfish, name, old)

    def run_main(self, *extra):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = redfish.main(self.ARGS + list(extra))
        return code, err.getvalue()

    def pipe(self, data):
        r, w = os.pipe()
        os.write(w, data)
        os.close(w)
        return r

    def closed(self, fd):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_a_password_on_a_pipe_reaches_the_transport_and_the_pipe_is_closed(self):
        fd = self.pipe(b"s3cret\n")
        self.assertEqual(self.run_main("--password-fd", str(fd)), (0, ""))
        self.assertEqual(self.given, ["s3cret"])
        self.closed(fd)

    def test_one_line_without_its_newline_is_the_same_password(self):
        self.assertEqual(self.run_main("--password-fd", str(self.pipe(b"s3cret")))[0], 0)
        self.assertEqual(self.given, ["s3cret"])

    def test_a_file_on_disk_is_never_read_as_the_descriptor(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: (os.unlink(os.path.join(d, "pw")), os.rmdir(d)))
        with open(os.path.join(d, "pw"), "w") as f:
            f.write("s3cret\n")
        os.chmod(os.path.join(d, "pw"), 0o600)
        fd = os.open(os.path.join(d, "pw"), os.O_RDONLY)
        code, err = self.run_main("--password-fd", str(fd))
        self.assertEqual(code, 1)
        self.assertIn("not a pipe or a sealed memfd", err)
        self.assertEqual(self.given, [])
        self.closed(fd)

    def test_what_is_not_one_password_is_refused_before_any_connection(self):
        for data, reason in ((b"", "holds nothing"), (b"\n", "is empty"), (b"one\ntwo\n", "more than one line"),
                             (b"cr\r\n", "more than one line"), (b"nul\0\n", "more than one line"),
                             (b"\xff\xfe\n", "not UTF-8")):
            with self.subTest(data=data):
                del self.given[:]                                  # each case judged alone, never by a leak from the last
                code, err = self.run_main("--password-fd", str(self.pipe(data)))
                self.assertEqual(code, 1)
                self.assertIn(reason, err)
                self.assertNotIn("two", err)                       # a refusal never echoes the secret
                self.assertEqual(self.given, [])

    def test_a_descriptor_that_is_not_open_or_is_stdin_is_refused(self):
        r = self.pipe(b"x")
        os.close(r)
        for fd, reason in ((r, "is not open"), (0, "above 2")):
            with self.subTest(fd=fd):
                del self.given[:]
                code, err = self.run_main("--password-fd", str(fd))
                self.assertEqual((code, self.given), (1, []))
                self.assertIn(reason, err)

    def test_the_descriptor_and_the_file_are_one_or_the_other(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            redfish.main(self.ARGS + ["--password-fd", "3", "--password-file", "/nonexistent"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.given, [])

    def test_the_bytes_read_are_zeroed(self):
        held = []
        read = redfish.keyfd.read
        self.patch("keyfd", type("K", (), {"read": staticmethod(lambda fd, what: held.append(read(fd, what)) or held[-1]),
                                           "zero": staticmethod(redfish.keyfd.zero)}))
        self.assertEqual(self.run_main("--password-fd", str(self.pipe(b"s3cret\n")))[0], 0)
        self.assertEqual(bytes(held[0]), bytes(7))


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
        context.minimum_version = ssl.TLSVersion.TLSv1_2                # as the client requires (CodeQL on #516)
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

    def test_every_path_the_drills_and_the_fence_use_goes_through_the_pin(self):
        """05 on #516: the pin-before-credentials guarantee is the client's, so every caller has it: discover, the
        fence's force_off, and the drills' power_on, force_restart and undoers, each refused with nothing sent."""
        client = redfish.Client(redfish.PinnedHTTPS("127.0.0.1", "00" * 32, "fence", "pw", timeout=5, port=self.port), "CZJ1234567",
                                "127.0.0.1")
        undo = redfish.undoers(lambda node: client)
        for name, call in (("discover", client.discover), ("force_off", client.force_off), ("power_on", client.power_on),
                           ("force_restart", client.force_restart), ("undo power-on", lambda: undo["power-on"]("b")),
                           ("undo power-cycle", lambda: undo["power-cycle"]("b"))):
            with self.subTest(path=name), self.assertRaisesRegex(Refused, "not the pinned 0{64}: nothing was sent"):
                call()
        self.assertFalse(any(b"Authorization" in r for r in self.received))

    def test_the_pin_s_form_is_checked(self):
        with self.assertRaisesRegex(Refused, "64 lowercase hex"):
            redfish.PinnedHTTPS("127.0.0.1", "AB" * 32, "fence", "pw")

    def test_a_bare_ipv6_literal_is_refused(self):
        """HTTPSConnection takes no bare IPv6 literal: the iLOs are named or IPv4 on the management network (3e)."""
        with self.assertRaisesRegex(Refused, "not a host name or address"):
            redfish.PinnedHTTPS("fd00::1", "ab" * 32, "fence", "pw")


if __name__ == "__main__":
    unittest.main()
