"""deploy/baremetal/apparmor/usr.local.sbin.regalia-kms: the profile the bare-metal unit asks for by name
(regalia-kms#61). It must parse, carry the name the unit asks for and the binary os_probe expects,
allow every path the daemon's documented configuration names, and allow nothing a KMS daemon has no
business doing: no execution, no capability, no socket but inet stream and a pathname unix stream.

What this cannot show is the profile confining a running daemon: that needs an AppArmor kernel, on the
DL360 (os_probe's kms_apparmor_enforced measures it there)."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from deploy.baremetal import os_probe

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/baremetal/apparmor/usr.local.sbin.regalia-kms"
VARIABLES = {"@{multiarch}": "x86_64-linux-gnu", "@{PROC}": "/proc", "@{pid}": "4242", "@{sys}": "/sys"}
FILE_RULE = re.compile(r"(?P<audit>audit )?(?P<deny>deny )?(?P<owner>owner )?(?P<path>[/@]\S*) (?P<perms>[rwmklaix]+),")


def parser():
    return shutil.which("apparmor_parser") or shutil.which("apparmor_parser", path="/usr/sbin:/sbin")


def body():
    """The rules: the profile block without comments, one rule per item."""
    text = re.sub(r"(?m)#.*$", "", PROFILE.read_text())
    inside = re.search(r"profile regalia-kms \{(.*)\}\s*\Z", text, re.S)
    assert inside, "the profile block was not found"
    return [" ".join(line.split()) for line in inside.group(1).splitlines() if line.strip()]


def to_regex(glob):
    for name, value in VARIABLES.items():
        glob = glob.replace(name, value)
    assert "@{" not in glob, "a variable this test does not know: " + glob
    out, i = "", 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**", i):
            out, i = out + ".*", i + 1
        elif c == "*":
            out += "[^/]*"
        elif c == "{":
            end = glob.index("}", i)
            out, i = out + "(?:" + "|".join(re.escape(a) for a in glob[i + 1:end].split(",")) + ")", end
        else:
            out += re.escape(c)
        i += 1
    return re.compile(out)


def file_rules():
    rules = []
    for line in body():
        found = FILE_RULE.fullmatch(line)
        if found:
            rules.append((bool(found["deny"]), to_regex(found["path"]), set(found["perms"]), line))
    return rules


def allowed(path, perms):
    """Whether every permission in `perms` is granted on `path` by an allow rule and none is denied."""
    rules = file_rules()
    if any(deny and rx.fullmatch(path) and have & set(perms) for deny, rx, have, _ in rules):
        return False
    granted = set()
    for deny, rx, have, _ in rules:
        if not deny and rx.fullmatch(path):
            granted |= have
    return set(perms) <= granted


class Profile(unittest.TestCase):
    def test_it_has_the_name_the_unit_asks_for_and_no_attachment_path(self):
        drop_in = (ROOT / "deploy/baremetal/regalia-kms-hardening.conf.example").read_text()
        asked = re.search(r"(?m)^AppArmorProfile=(\S+)$", drop_in).group(1)
        self.assertEqual(asked, "regalia-kms")
        text = PROFILE.read_text()
        # `profile NAME {`: named, attached to no path, so an operator's own run of the binary is not confined
        self.assertEqual(re.findall(r"(?m)^profile .*$", text), ["profile %s {" % asked])
        self.assertNotRegex(text, r"flags=\([^)]*(complain|unconfined|kill)")

    def test_it_maps_the_binary_os_probe_and_the_unit_expect(self):
        binary = os_probe.ALLOWED_TOKEN_CLIENT_EXES[0]
        unit = (ROOT / "deploy/systemd/regalia-kms.service").read_text()
        self.assertEqual(re.search(r"(?m)^ExecStart=(\S+)", unit).group(1), binary)
        self.assertIn("%s mr," % binary, body())
        self.assertEqual(PROFILE.name, binary.strip("/").replace("/", "."))

    def test_every_path_in_the_documented_configuration_is_allowed_with_what_the_code_does_to_it(self):
        config = json.loads((ROOT / "config/daemon.example.json").read_text())
        journals = ("audit_journal_path", "policy_state_path", "fencing_state_path")
        checked = 0
        for setting, value in config.items():
            for path in (value.values() if isinstance(value, dict) else [value]):
                if not (isinstance(path, str) and path.startswith("/")):
                    continue
                checked += 1
                with self.subTest(setting=setting, path=path):
                    if setting in journals:
                        self.assertTrue(allowed(path, "rw"))
                        self.assertTrue(allowed(path + ".high-water", "rw"))
                        self.assertTrue(allowed(path + ".high-water.tmp", "rw"))
                    elif setting == "pkcs11_module_path":
                        self.assertTrue(allowed(path, "mr"))
                    else:
                        self.assertTrue(allowed(path, "r"))
                        self.assertFalse(allowed(path, "w"))
        self.assertGreaterEqual(checked, 11)
        self.assertTrue(allowed(config["policy_state_path"], "k"))   # the exclusive flock
        self.assertTrue(allowed("/etc/regalia-kms/config.json", "r"))
        self.assertTrue(allowed("/run/pcscd/pcscd.comm", "rw"))
        for name in ("hsm-site-a.pin", "yubi-site-a.pin"):   # regalia-kms-credentials.conf.example
            self.assertTrue(allowed("/run/credentials/regalia-kms.service/" + name, "r"))

    def test_what_a_kms_daemon_has_no_business_touching_is_refused(self):
        for path, perms in (
                ("/dev/tpm0", "r"), ("/dev/tpmrm0", "rw"), ("/etc/credstore.encrypted/regalia-kms-hsm-site-a.pin", "r"),
                ("/etc/regalia-kms/config.json", "w"), ("/etc/regalia-kms/tls/server.key", "w"),
                ("/usr/local/sbin/regalia-kms", "w"), ("/usr/local/sbin/regalia-kms", "x"),
                ("/etc/shadow", "r"), ("/root/.ssh/authorized_keys", "r"), ("/home/operator/.bash_history", "r"),
                ("/var/lib/regalia-kms/audit.jsonl", "x"), ("/var/lib/regalia-kms/sub/audit.jsonl", "w"),
                ("/var/lib/regalia-kms/authorized_keys", "w"), ("/var/lib/other/audit.jsonl", "r"),
                ("/run/credentials/regalia-sops-kms.service/workload-key.pem", "r"),
                ("/run/credentials/regalia-kms.service/hsm-site-a.pin", "w"),
                ("/run/regalia-kms/site-lease.json", "w"), ("/run/pcscd/pcscd.pid", "r"),
                ("/bin/sh", "x"), ("/usr/bin/pkcs11-tool", "x"), ("/tmp/x", "w"), ("/proc/1/environ", "r")):
            with self.subTest(path=path, perms=perms):
                self.assertFalse(allowed(path, perms))

    def test_nothing_is_executed_and_writes_stay_in_the_state_directory(self):
        for deny, rx, perms, line in file_rules():
            with self.subTest(rule=line):
                if deny:
                    continue
                self.assertFalse(perms & set("xil"), "an allow rule executes or links")
                if "w" in perms or "a" in perms:
                    self.assertRegex(line, r"^(owner /var/lib/regalia-kms/\*\.jsonl|/run/pcscd/pcscd\.comm)")
                self.assertNotRegex(line, r"^(owner )?/\*\* |^(owner )?/\*\*$| /\*\* ")

    def test_every_rule_is_of_a_kind_this_test_understands(self):
        """A rule this test cannot classify fails here, so a capability, a mount or a bare `network,` cannot
        arrive unnoticed."""
        other = [line for line in body() if not FILE_RULE.fullmatch(line)]
        self.assertEqual(sorted(other), sorted([
            "include <abstractions/base>",
            "unix (connect, send, receive) type=stream peer=(addr=none),",
            "network inet stream,",
            "network inet6 stream,",
        ]))
        self.assertEqual(re.findall(r"(?m)^(?:abi|include) .*$", PROFILE.read_text()), ["abi <abi/4.0>,", "include <tunables/global>"])

    def test_every_code_path_a_rule_cites_exists(self):
        cited = set(re.findall(r"\b((?:internal|cmd|deploy)/[A-Za-z0-9_./-]+\.(?:go|py|service|example))", PROFILE.read_text()))
        self.assertGreaterEqual(len(cited), 15)
        for path in sorted(cited):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
        # and every path setting of the daemon is accounted for in a comment
        settings = re.findall(r'json:"([a-z0-9_]+_paths?)"', (ROOT / "internal/config/config.go").read_text())
        self.assertGreaterEqual(len(settings), 14)
        for setting in settings:
            with self.subTest(setting=setting):
                self.assertIn(setting, PROFILE.read_text())


class Parses(unittest.TestCase):
    """apparmor_parser compiles the profile without loading it. No AppArmor kernel is needed, so none is proven."""

    def setUp(self):
        if not parser():
            if os.environ.get("REGALIA_EXPECT_APPARMOR_PARSER") == "1":
                self.fail("apparmor_parser is expected here and was not found")
            self.skipTest("needs apparmor_parser (package apparmor)")

    def compile(self, path):
        return subprocess.run([parser(), "--skip-kernel-load", "-Q", "-K", str(path)], capture_output=True, text=True)

    def test_the_profile_compiles_and_declares_exactly_its_name(self):
        done = self.compile(PROFILE)
        self.assertEqual(done.returncode, 0, done.stderr)
        names = subprocess.run([parser(), "-N", str(PROFILE)], capture_output=True, text=True)
        self.assertEqual(names.stdout.split(), ["regalia-kms"])

    def test_the_parser_refuses_a_broken_profile(self):
        """The control: this check can fail."""
        text = PROFILE.read_text()
        for label, broken in (("an unknown permission", text.replace("/usr/local/sbin/regalia-kms mr,", "/usr/local/sbin/regalia-kms mq,")),
                              ("an unknown abstraction", text.replace("<abstractions/base>", "<abstractions/no-such>")),
                              ("an unclosed block", text.rstrip().rstrip("}"))):
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                self.assertNotEqual(broken, text)
                path = Path(d) / "broken"
                path.write_text(broken)
                self.assertNotEqual(self.compile(path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
