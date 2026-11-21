"""dx7.3's self-attester (Node.self_attester), made by the admission service under the single-node profile: its state file
is in admission's own directory, never in sync's state directory, which regalia-admission cannot write on a host
(regalia-admission.service: ProtectSystem=strict, ReadWritePaths without /var/lib/regalia-sync). Found by the one-node
scenario's first run (regalia-kms-dx7.10): EACCES on attest-self.json.lock under the state directory."""
import configparser
import pathlib
import unittest
from unittest import mock

from deploy.baremetal import node

UNITS = pathlib.Path(__file__).resolve().parent.parent / "deploy" / "baremetal" / "units"


def unit(name):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(UNITS / name)
    return parser["Service"]


class SelfAttesterState(unittest.TestCase):
    def made(self):
        host = object.__new__(node.Node)
        host.cfg = {"admission_dir": "/var/lib/regalia-admission"}
        host.state, host.run, host.node_id, host.tcti = "/var/lib/regalia-sync", None, "a", "device:/dev/tpmrm0"
        host.documents = mock.Mock()
        with mock.patch.object(node.measurements, "held"), mock.patch.object(node.measurements, "self_attest_policy", return_value="policy"), \
                mock.patch.object(node.attest, "Verifier") as verifier, mock.patch.object(node.enrolpeer, "tpm_identity"), \
                mock.patch.object(node.enrolpeer, "challenge", return_value=None):
            host.self_attester({"epoch": 1})
        return verifier.call_args

    def test_its_state_is_in_admission_s_own_directory(self):
        args = self.made()
        self.assertEqual(args.args[1], "/var/lib/regalia-admission/attest-self.json")

    def test_the_shipped_admission_unit_cannot_write_sync_s_state_directory(self):
        """The premise of the above, read from the shipped units: admission's user, sandbox and writable paths."""
        admission, sync = unit("regalia-admission.service"), unit("regalia-sync.service")
        self.assertEqual((admission["User"], sync["User"]), ("regalia-admission", "regalia-sync"))
        self.assertEqual(admission["ProtectSystem"], "strict")
        self.assertEqual(admission["StateDirectory"], "regalia-admission")
        self.assertNotIn("regalia-sync", admission["ReadWritePaths"])


if __name__ == "__main__":
    unittest.main()
