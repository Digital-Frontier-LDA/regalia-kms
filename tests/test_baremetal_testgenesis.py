"""deploy/baremetal/testgenesis.py (regalia-kms-223): every output of the staging TEST genesis tool verifies with the
EXISTING verifiers (manifest.card_record_keys, cardrecord.verify, manifest.offline_keys_record, ownerauth.verify and
check, sitecfg.load, measurements.load), every file is private, and the guard refuses every root that is not TEST.

Each test makes its own throwaway root and adds it to the allow-list through the tests' hook (generate's `allow`, or
TEST_ROOTS patched for the command line): the staging TEST root's private key is never read here."""
import base64
import glob
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from deploy.baremetal import (attest, cardrecord, espcreds, manifest, measurements, membership, ownerauth, sitecfg,
                              testgenesis, uki, wgsvc)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGING_ROOT = "6df81ed70ee55731c409a4c8c676203f69c55bb8c2d0b394f76919d77bb88c30"
USRHASH = hashlib.sha256(b"the TEST /usr image").hexdigest()
VAR_MOUNT = "systemd.mount-extra=/dev/mapper/root:/var:ext4:x-initrd.mount,x-systemd.device-timeout=0,nodev,nosuid"
CMDLINE = ("quiet systemd.import_credentials=no init_on_free=1 init_on_alloc=1 rd.shell=0 rd.emergency=reboot "
           "rootflags=x-systemd.device-timeout=0 root=tmpfs usrhash=%s systemd.verity_usr_options=panic-on-corruption %s"
           % (USRHASH, VAR_MOUNT))
PCRS = {str(i): ("%02x" % (0x10 + i)) * 32 for i in range(8)}
NODE = "alder"
DEVICE = "/dev/disk/by-partlabel/regalia-root"


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def signed_record(root):
    """A signed build record of the form uki.load_record(signed=True) reads, its image pinning `root`."""
    return {"schema": uki.SCHEMA, "name": "image-7", "uname": "6.12.57-amd64",
            "inputs": {"linux": {"sha256": h("linux"), "size": 5}, "usr_record": {"sha256": h("usr"), "size": 3}},
            "sections": {".cmdline": hashlib.sha256(CMDLINE.encode()).hexdigest(), ".linux": h("linux")},
            "unsigned_sha256": h("unsigned"), "stub_sections": {".text": h("stub")}, "cmdline": CMDLINE, "usr_roothash": USRHASH,
            "phase_paths": dict(uki.PHASE_PATHS), "pcr11": {"initrd": h("pcr11 initrd"), "system": h("pcr11 system")},
            "pcrpkey_pkfp": h("pcrpkey"),
            "initrd_review": {"schema": uki.INITRD_REVIEW, "passed": True, "findings": [], "crypttab": None, "units": {}, "clients": {},
                              "root_key": hashlib.sha256(membership.canonical(root)).hexdigest(), "inventory_sha256": None},
            "tools": {"ukify": "ukify 257 (stand-in)"},
            "signed": {"image_sha256": h("image"), "secure_boot_cert_sha256": h("sb cert"),
                       "pcr_signatures": {"initrd": {"pkfp": h("initrd key"), "pol": h("initrd pol")},
                                          "system": {"pkfp": h("system key"), "pol": h("system pol")}}}}


def site():
    return {"schema": sitecfg.SCHEMA, "site": "staging", "host_ipv4": "192.0.2.10", "kms_port": 8443, "ssh_port": 22,
            "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["203.0.113.128/32"], "admin_cidrs": ["203.0.113.0/28"],
            "outbound": [{"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514}],
            "time": {"nts": [{"name": "nts.netnod.se", "cidrs": ["194.58.200.0/24"]}, {"name": "ptbtime1.ptb.de", "cidrs": ["192.53.103.0/24"]}]},
            "boot_mesh": {"node_id": NODE, "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443,
                          "nic_mac": "52:54:00:12:34:56", "prefix": 24, "gateway": "192.0.2.1", "peers": [],
                          "owner": {"underlay": "203.0.113.50", "address": "10.89.0.9"}},
            "service_mesh": None}


class Case(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.d = tempfile.mkdtemp(prefix="testgenesis-")
        self.addCleanup(shutil.rmtree, self.d)
        key = Ed25519PrivateKey.generate()                      # a throwaway TEST root, this test's alone
        self.root = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.pk8 = os.path.join(self.d, "TEST-root.pk8.pem")
        fd = os.open(self.pk8, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.out = os.path.join(self.d, "out")

    def generate(self, out=None, allow=None, **kw):
        args = dict(root=self.root, root_pk8=self.pk8, out=out or self.out, node_id=NODE, site=site(), build_record=signed_record(self.root),
                    pcrs=dict(PCRS), tpm_firmware_version="2019102300163636", device=DEVICE, allow={self.root} if allow is None else allow,
                    say=lambda *_: None)
        args.update(kw)
        return testgenesis.generate(**args)

    def load(self, name):
        with open(os.path.join(self.out, name), "rb") as f:
            return membership.load(f.read())

    def refused(self, pattern, fn, *args, **kw):
        with self.assertRaises(membership.Refused) as caught:
            fn(*args, **kw)
        self.assertRegex(str(caught.exception), pattern)


class Outputs(Case):
    """Every output, read back from disk, verified by the verifier that consumes it."""

    def setUp(self):
        super().setUp()
        self.summary = self.generate()

    def test_the_card_record_and_the_signing_state_verify_as_manifest_and_cardrecord_read_them(self):
        envelope = self.load("TEST-cards.record.json")
        state = os.path.join(self.out, "TEST-signing-state")
        got = manifest.card_record_keys(envelope, self.root, state)
        self.assertEqual((got["sequence"], got["of"], got["supersedes"]), (1, 1, ""))
        self.assertEqual(got["owners"], {v["serial"]: v["key"] for v in self.summary["owner_keys"].values()})
        self.assertEqual(got["roles"], {role: v["serial"] for role, v in self.summary["owner_keys"].items()})
        self.assertEqual(got["release_key"], self.summary["release_key"])
        self.assertEqual(got["digest"], self.summary["card_record"]["digest"])
        lines = cardrecord.read_signing_state(state, self.root)
        self.assertEqual(cardrecord.verify(envelope, self.root, lines)["digest"], got["digest"])
        self.assertEqual([line["kind"] for line in lines], ["card-record"])
        # signed under the card record's own domain and no other (regalia-avz)
        record, signature = envelope["record"], bytes.fromhex(envelope["signature"])
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.root)).verify(signature, cardrecord.RECORD_DOMAIN + membership.canonical(record))
        # under another root it is refused
        self.refused("another root than the pinned one", cardrecord.verify, envelope, "ab" * 32, lines)

    def test_the_offline_keys_record_gives_k_a_as_the_genesis_takes_it(self):
        typed, record = manifest.offline_keys_record(self.load("TEST-offline-keys.record.json"), self.root)
        self.assertEqual(typed, self.summary["anchor_policy_key"])
        self.assertEqual(record["operation_proof"]["anchor-policy"], "verified")
        from cryptography.hazmat.primitives import serialization
        with open(os.path.join(self.out, "TEST-anchor-policy.p256.pk8.pem"), "rb") as f:
            k_a = serialization.load_pem_private_key(f.read(), None)
        self.assertEqual(k_a.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex(), typed["key"])

    def test_the_ownerauth_record_and_the_value_verify_and_check(self):
        envelope = self.load("TEST-ownerauth.record.json")
        entry = ownerauth.verify(envelope, self.root, NODE)
        with open(os.path.join(self.out, "TEST-ownerauth-%s.value" % NODE), "rb") as f:
            raw = f.read()
        self.assertRegex(raw.decode(), r"\A[0-9a-f]{64}\n\Z")
        auth = ownerauth.read_value(io.BytesIO(raw))
        self.assertEqual(auth.check(NODE), entry["check"])
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(ownerauth.main(["check", "--node-id", NODE, "--root-key", self.root, "--record",
                                             os.path.join(self.out, "TEST-ownerauth.record.json")], stdin=io.BytesIO(raw)), 0)
        self.assertIn("the value is %s's" % NODE, out.getvalue())
        self.refused("has no entry for other", ownerauth.verify, envelope, self.root, "other")
        # the recipients are the card record's ownerauth_recipients, and owner.py contribute's --recipient values
        cards = self.load("TEST-cards.record.json")["record"]["ownerauth_recipients"]
        self.assertEqual(envelope["record"]["yk_recipients"], [{"primary": r["primary"], "subkey": r["subkey"]} for r in cards])
        with open(os.path.join(self.out, "TEST-owner-recipients.txt")) as f:
            self.assertEqual(f.read().split(), [r["subkey"] for r in cards])

    def test_the_owner_key_files_are_the_card_records_keys(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        record = self.load("TEST-cards.record.json")["record"]
        raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        for entry in record["owner_keys"]:
            with open(os.path.join(self.out, "TEST-%s.ed25519.pk8.pem" % entry["role"]), "rb") as f:
                key = serialization.load_pem_private_key(f.read(), None)
            self.assertIsInstance(key, Ed25519PrivateKey)
            self.assertEqual(raw(key), entry["key"])
        with open(os.path.join(self.out, "TEST-release.ed25519.pk8.pem"), "rb") as f:
            self.assertEqual(raw(serialization.load_pem_private_key(f.read(), None)), record["release_key"]["key"])
        for i, role in enumerate(cardrecord.ROLES):
            with open(os.path.join(self.out, "TEST-ssh-%s.key" % role), "rb") as f:
                key = serialization.load_ssh_private_key(f.read(), None)
            with open(os.path.join(self.out, "TEST-ssh-%s.pub" % role)) as f:
                self.assertEqual(f.read().strip(), record["ssh_signers"][i]["key"])
            self.assertEqual(key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(),
                             record["ssh_signers"][i]["key"])

    def test_the_owner_wireguard_pair_is_one_pair_and_its_hex_is_what_the_genesis_pins(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        read = lambda n: open(os.path.join(self.out, n)).read()
        private = base64.b64decode(read("TEST-owner-wg.key").strip(), validate=True)
        self.assertEqual(len(private), 32)
        self.assertEqual((private[0] & 7, private[31] & 0xC0), (0, 0x40))          # clamped, as `wg genkey` writes it
        public = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(read("TEST-owner-wg.pub").strip(), base64.b64encode(public).decode())
        self.assertEqual(read("TEST-owner-wg.pub.hex").strip(), public.hex())
        self.assertEqual(wgsvc.hex_key(read("TEST-owner-wg.pub").strip()), self.summary["owner_wg_pub"])
        self.assertRegex(self.summary["owner_wg_pub"], r"\A[0-9a-f]{64}\Z")     # propose_genesis's --owner-wg-pub form

    def test_the_site_loads_with_sitecfg_as_a_single_node_host(self):
        cfg = sitecfg.load(os.path.join(self.out, "TEST-site.json"))
        self.assertEqual(sitecfg.profile(cfg), sitecfg.SINGLE_NODE)
        self.assertEqual(cfg["boot_mesh"]["owner"], {"underlay": "203.0.113.50", "address": "10.89.0.9"})
        self.assertEqual((cfg["boot_mesh"]["node_id"], cfg["boot_mesh"]["nic_mac"], cfg["boot_mesh"]["prefix"], cfg["boot_mesh"]["gateway"]),
                         (NODE, "52:54:00:12:34:56", 24, "192.0.2.1"))
        sitecfg.require_profile(cfg, membership.SINGLE_NODE)

    def test_the_measurements_load_and_hold_the_records_set_and_the_operators_pcrs(self):
        with open(os.path.join(self.out, "TEST-measurements.json"), "rb") as f:
            document = measurements.load(f.read())
        self.assertEqual(measurements.version(document), self.summary["measurements"]["policy_version"])
        record = signed_record(self.root)
        (entry,) = document["nodes"][NODE]["accepted"]
        with open(os.path.join(self.out, "TEST-regalia.site.cred"), "rb") as f:
            cred = f.read()
        self.assertEqual(entry, uki.measurement_set(record, "image-7", "2019102300163636", PCRS, {"regalia.site.cred": cred}))
        self.assertEqual(entry["pcrs"], dict(PCRS, **{"12": espcreds.pcr12({"regalia.site.cred": cred})}))
        self.assertEqual(entry["phases"], {"initrd": {"11": record["pcr11"]["initrd"]}, "system": {"11": record["pcr11"]["system"]}})
        self.assertEqual(attest.selection(entry), list(range(8)) + [11, 12])
        self.assertTrue(document["name"].startswith("TEST-"))
        self.assertEqual(json.loads(cred)["device"], DEVICE)

    def test_the_lockout_value_is_what_tpm_lockout_takes(self):
        with open(os.path.join(self.out, "TEST-lockout.value"), "rb") as f:
            self.assertRegex(f.read(), rb"\A[!-~]{16,32}\n\Z")

    def test_every_output_is_marked_test_and_summed(self):
        names = sorted(os.path.relpath(p, self.out) for p in glob.glob(os.path.join(self.out, "**"), recursive=True) if os.path.isfile(p))
        for name in names:
            self.assertTrue(name.startswith("TEST-"), name)
        summary = self.load("TEST-genesis.json")
        self.assertIs(summary["TEST"], True)
        self.assertIn("TEST ONLY", open(os.path.join(self.out, "TEST-README.txt")).read())
        with open(os.path.join(self.out, "TEST-SHA256SUMS")) as f:
            sums = dict(reversed(line.rstrip("\n").split("  ", 1)) for line in f)
        self.assertEqual(sorted(sums), [n for n in names if n != "TEST-SHA256SUMS"])
        for name, digest in sums.items():
            with open(os.path.join(self.out, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, name)
        self.assertIn("ownerauth recipients", " ".join(summary["stand_ins"]))

    def test_the_directory_is_0700_and_every_file_0600(self):
        for path in [self.out, os.path.join(self.out, "TEST-signing-state")]:
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o700, path)
        files = [p for p in glob.glob(os.path.join(self.out, "**"), recursive=True) if os.path.isfile(p)]
        self.assertGreaterEqual(len(files), 20)
        for path in files:
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600, path)
        for secret in ("TEST-ownerauth-%s.value" % NODE, "TEST-lockout.value", "TEST-owner-wg.key", "TEST-owner-main.ed25519.pk8.pem",
                       "TEST-anchor-policy.p256.pk8.pem"):
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(self.out, secret)).st_mode), 0o600, secret)

    def test_the_root_private_key_is_nowhere_in_the_output(self):
        with open(self.pk8, "rb") as f:
            pem = f.read()
        from cryptography.hazmat.primitives import serialization
        raw = serialization.load_pem_private_key(pem, None).private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                                          serialization.NoEncryption())
        for path in glob.glob(os.path.join(self.out, "**"), recursive=True):
            if os.path.isfile(path):
                data = open(path, "rb").read()
                for needle in (pem, raw, raw.hex().encode(), base64.b64encode(raw)):
                    self.assertNotIn(needle, data, path)


class Guard(Case):
    """The root guard: deny first, then allow; refused before the private key is read or a file is written."""

    def test_the_staging_test_root_is_on_the_allow_list(self):
        with open(os.path.join(ROOT_DIR, "deploy", "baremetal", "testgenesis.py")) as f:
            self.assertIn(STAGING_ROOT, f.read())
        self.assertIn(STAGING_ROOT, testgenesis.TEST_ROOTS)
        self.assertEqual(testgenesis.check_root(STAGING_ROOT), STAGING_ROOT)

    def test_every_real_root_is_refused_even_on_the_allow_list(self):
        self.assertTrue(testgenesis.REAL_ROOTS)
        for real in testgenesis.REAL_ROOTS:
            with self.subTest(root=real):
                self.refused("is a real or ceremony root", testgenesis.check_root, real)
                self.refused("is a real or ceremony root", testgenesis.check_root, real, allow={real})
                with mock.patch.object(testgenesis, "TEST_ROOTS", testgenesis.TEST_ROOTS | {real}):
                    self.refused("is a real or ceremony root", testgenesis.check_root, real)
                out = os.path.join(self.d, "real-" + real[:8])
                self.refused("is a real or ceremony root", self.generate, out=out, root=real, allow={real})
                self.assertFalse(os.path.lexists(out))

    def test_every_ceremony_root_in_the_vectors_is_on_the_deny_list(self):
        """regalia-ceremony's writers made the roots of these vectors: a new one added there is denied here too."""
        found = set()
        vectors = os.path.join(ROOT_DIR, "tests", "vectors")
        for path in glob.glob(os.path.join(vectors, "card-ceremony-record", "**", "*"), recursive=True) + \
                glob.glob(os.path.join(vectors, "offline-keys-record", "*")) + [os.path.join(vectors, "ownerauth-v1.json")]:
            if not os.path.isfile(path):
                continue
            text = open(path).read()
            if path.endswith(".hex"):
                found.add(text.strip())
            found.update(re.findall(r'"root_entry":\s*\{"alg":\s*"ed25519",\s*"key":\s*"([0-9a-f]{64})"', text))
            found.update(re.findall(r'"root":\s*"([0-9a-f]{64})"', text))
        self.assertGreaterEqual(len(found), 7)
        self.assertEqual(sorted(found - set(testgenesis.REAL_ROOTS)), [])
        self.assertFalse(set(testgenesis.REAL_ROOTS) & testgenesis.TEST_ROOTS)

    def test_an_unknown_root_is_refused(self):
        self.refused("is not on the TEST allow-list", testgenesis.check_root, self.root)
        self.refused("is not on the TEST allow-list", self.generate, allow=testgenesis.TEST_ROOTS)
        self.assertFalse(os.path.lexists(self.out))
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(testgenesis.main(self.argv()), 1)
        self.assertIn("is not on the TEST allow-list", err.getvalue())
        self.assertFalse(os.path.lexists(self.out))

    def test_the_private_key_must_be_the_named_roots_and_private(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        other = os.path.join(self.d, "other.pk8.pem")
        fd = os.open(other, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption()))
        self.refused("is not the private key of --root-key", self.generate, root_pk8=other)
        os.chmod(self.pk8, 0o644)
        self.refused("mode 0600", self.generate)
        os.chmod(self.pk8, 0o600)
        link = os.path.join(self.d, "link.pem")
        os.symlink(self.pk8, link)
        self.refused("never read through a link", self.generate, root_pk8=link)
        self.assertFalse(os.path.lexists(self.out))

    def test_an_image_that_pins_another_root_is_refused(self):
        record = signed_record(self.root)
        record["initrd_review"]["root_key"] = hashlib.sha256(membership.canonical("ab" * 32)).hexdigest()
        self.refused("pins another membership root", self.generate, build_record=record)
        self.assertFalse(os.path.lexists(self.out))


class Directory(Case):
    def test_an_existing_directory_must_be_empty_and_is_made_private(self):
        os.mkdir(self.out, 0o755)
        with open(os.path.join(self.out, "x"), "w") as f:
            f.write("x")
        self.refused("is not empty", self.generate)
        self.assertEqual(os.listdir(self.out), ["x"])
        os.unlink(os.path.join(self.out, "x"))
        self.generate()
        self.assertEqual(stat.S_IMODE(os.lstat(self.out).st_mode), 0o700)

    def test_a_link_is_refused(self):
        target = os.path.join(self.d, "elsewhere")
        os.mkdir(target)
        os.symlink(target, self.out)
        self.refused("not a directory of this user's", self.generate)
        self.assertEqual(os.listdir(target), [])

    def test_names_never_leave_the_directory(self):
        os.mkdir(self.out)
        output = testgenesis.Output(self.out)
        self.addCleanup(output.close)
        for name in ("../TEST-x", "/tmp/TEST-x", "TEST-a/../../x", "TEST-a/b/c", "x", ".", ".."):
            with self.subTest(name=name):
                self.refused("is not a plain name|is not marked TEST", output.write, name, b"x")
        self.assertEqual(os.listdir(self.out), [])


class CommandLine(Case):
    def argv(self, out=None):
        record = os.path.join(self.d, "record.json")
        with open(record, "w") as f:
            json.dump(signed_record(self.root), f)
        pcrs = os.path.join(self.d, "pcrs.json")
        with open(pcrs, "w") as f:
            json.dump(PCRS, f)
        return ["--root-key", self.root, "--root-pk8", self.pk8, "--out", out or self.out, "--node-id", NODE, "--site", "staging",
                "--host-ipv4", "192.0.2.10", "--prefix", "24", "--gateway", "192.0.2.1", "--nic-mac", "52:54:00:12:34:56",
                "--boot-address", "10.89.0.1", "--owner-underlay", "203.0.113.50", "--owner-address", "10.89.0.9",
                "--client-cidr", "198.51.100.0/24", "--monitoring-cidr", "203.0.113.128/32", "--admin-cidr", "203.0.113.0/28",
                "--audit", "203.0.113.192/32:tcp:6514", "--nts", "nts.netnod.se=194.58.200.0/24", "--nts", "ptbtime1.ptb.de=192.53.103.0/24",
                "--build-record", record, "--pcrs", pcrs, "--tpm-firmware-version", "2019102300163636", "--device", DEVICE]

    def test_the_command_writes_what_generate_writes(self):
        out = io.StringIO()
        with mock.patch.object(testgenesis, "TEST_ROOTS", frozenset({self.root})), redirect_stdout(out):
            self.assertEqual(testgenesis.main(self.argv()), 0)
        self.assertIn("verified by the existing verifiers", out.getvalue())
        self.assertEqual(sitecfg.load(os.path.join(self.out, "TEST-site.json")), sitecfg.validate(site()))
        testgenesis.verify_outputs(self.out, self.root, NODE)

    def test_the_pcrs_are_exactly_0_to_7(self):
        argv = self.argv()
        pcrs = argv[argv.index("--pcrs") + 1]
        for bad in (dict(PCRS, **{"11": "00" * 32}), {k: v for k, v in PCRS.items() if k != "7"}, dict(PCRS, **{"0": "XY" * 32})):
            with open(pcrs, "w") as f:
                json.dump(bad, f)
            err = io.StringIO()
            with mock.patch.object(testgenesis, "TEST_ROOTS", frozenset({self.root})), redirect_stderr(err):
                self.assertEqual(testgenesis.main(argv), 1)
            self.assertRegex(err.getvalue(), "PCRs 0-7|64 lowercase hex")
            self.assertFalse(os.path.lexists(self.out))

    def test_real_recipients_replace_the_stand_ins(self):
        argv = self.argv() + ["--owner-recipient", "A" * 40 + ":" + "B" * 40, "--owner-recipient", "C" * 40 + ":" + "D" * 40]
        with mock.patch.object(testgenesis, "TEST_ROOTS", frozenset({self.root})), redirect_stdout(io.StringIO()):
            self.assertEqual(testgenesis.main(argv), 0)
        record = self.load("TEST-ownerauth.record.json")["record"]
        self.assertEqual(record["yk_recipients"], [{"primary": "A" * 40, "subkey": "B" * 40}, {"primary": "C" * 40, "subkey": "D" * 40}])
        self.assertNotIn("ownerauth recipients", " ".join(self.load("TEST-genesis.json")["stand_ins"]))


Guard.argv = CommandLine.argv


if __name__ == "__main__":
    unittest.main()
