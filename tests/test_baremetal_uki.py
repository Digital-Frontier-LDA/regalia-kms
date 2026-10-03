"""deploy/baremetal/uki.py: the boot image's build record and its signatures (#57).

ukify, systemd-measure and sbsign are stand-ins here (FakeTools): they build a PE file with the same
sections, predict PCR 11 by this file's own arithmetic, and sign with the real OpenSSL. The parser, the
PCR 11 and policy arithmetic, the signature check and every refusal are the module's own, and the PCR 11
vectors below come from the real systemd-measure. e2e/uki-build.sh runs the same paths with the real tools.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from deploy.baremetal import attest, espcreds, measurements, uki
from deploy.baremetal import membership as m

# `systemd-measure calculate` (257.13-1~deb13u1) over sections whose content is their own name
# ("linux", "osrel", ...), SHA-256 bank: with a .ucode section and without.
VECTOR = {True: {"initrd": "7b5976f87e32c892f7cae4109e05bd6208f55c2fa5b080ebbbb43eeadd073b4f",
                 "system": "b7fa42712c1e4cb9d8223d8d89831ba4537537a259b9edb710a3012715fd6f8d"},
          False: {"initrd": "ac463d575d224c58bb363afdf453f02b4d34af072eb207d4bc77c1ae569559b5",
                  "system": "68e287b94b30ed915281094bd86aa925d2d74b8ff9bcc52aaca026d91d860770"}}
# a "pol" that systemd-measure 257.13 wrote for this PCR 11 value
POLICY = ("132ab7e17a991bf12b108008052ca9c0c876f8a8c542f2d22eac1590a72105f4", "755f8cc34513bda797481e72388e539a2e83746b27d8186844fcf544fe9d8c0d")
TRAILER = b"\0SECURE-BOOT-SIGNATURE"


def pe(sections, virtual=None):
    """A PE file with these sections, as ukify lays them out: raw data padded to 512 bytes."""
    header = bytearray(0x40)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3c, 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 0, 0)
    table, body, offset = b"", b"", (0x40 + len(coff) + 40 * len(sections) + 511) // 512 * 512
    for name, data in sections:
        raw = data + bytes(-len(data) % 512)
        size = (virtual or {}).get(name, len(data))
        table += name.encode().ljust(8, b"\0") + struct.pack("<IIII", size, 0, len(raw), offset + len(body)) + bytes(16)
        body += raw
    head = bytes(header) + coff + table
    return head + bytes(offset - len(head)) + body


def predicted(parts, path):
    """PCR 11, by this test's own arithmetic (not the module's function)."""
    value = bytes(32)
    for name in ("linux", "osrel", "cmdline", "initrd", "ucode", "uname", "sbat", "pcrpkey"):
        if name in parts:
            for item in (b"." + name.encode() + b"\0", parts[name]):
                value = hashlib.sha256(value + hashlib.sha256(item).digest()).digest()
    for phase in path.split(":"):
        value = hashlib.sha256(value + hashlib.sha256(phase.encode()).digest()).digest()
    return value.hex()


class FakeTools:
    """ukify, systemd-measure, sbsign and sbverify as uki.py calls them; OpenSSL is the real one."""

    def __init__(self):
        self.calls, self.tamper = [], {}

    def __call__(self, argv, capture_output=True, input=None):
        self.calls.append(list(argv))
        tool = os.path.basename(argv[0])
        if tool == "openssl":
            return subprocess.run(argv, capture_output=True, input=input)
        ok = lambda out=b"": subprocess.CompletedProcess(argv, 0, out, b"")
        if "--version" in argv:
            return ok(("%s 257 (stand-in)\nmore" % tool).encode())
        return getattr(self, tool.replace("-", "_"))(argv, ok)

    @staticmethod
    def options(argv):
        out, i = {}, 0
        while i < len(argv):
            if argv[i].startswith("--") and "=" in argv[i]:
                key, value = argv[i].split("=", 1)
                out.setdefault(key, []).append(value)
            elif argv[i].startswith("--") and i + 1 < len(argv):
                out.setdefault(argv[i], []).append(argv[i + 1])
                i += 1
            i += 1
        return out

    def ukify(self, argv, ok):
        o = self.options(argv[2:])
        slurp = uki.read
        sections = [(".text", b"stub code"), (".sbat", b"sbat,1,stand-in"), (".sdmagic", b"magic"),
                    (".osrel", slurp(o["--os-release"][0][1:])), (".cmdline", o["--cmdline"][0].encode() + self.tamper.get("cmdline", b"")),
                    (".uname", o["--uname"][0].encode()), (".pcrpkey", slurp(o["--pcrpkey"][0])),
                    (".linux", slurp(o["--linux"][0])), (".initrd", slurp(o["--initrd"][0]) + self.tamper.get("initrd", b""))]
        if "--microcode" in o:
            sections.append((".ucode", slurp(o["--microcode"][0])))
        sections += self.tamper.get("extra", [])
        if "--section" in o:
            name, path = o["--section"][0].split(":@")
            sections.append((name, slurp(path)))
            if "attach" in self.tamper:
                sections = [(n, d + self.tamper["attach"] if n == ".initrd" else d) for n, d in sections]
        with open(o["--output"][0], "wb") as f:
            f.write(pe(sections) + self.tamper.get("trailing", b""))
        return ok()

    def systemd_measure(self, argv, ok):
        o = self.options(argv[2:])
        names = {"--linux": "linux", "--osrel": "osrel", "--cmdline": "cmdline", "--initrd": "initrd", "--ucode": "ucode", "--uname": "uname",
                 "--sbat": "sbat", "--pcrpkey": "pcrpkey"}
        parts = {names[k]: uki.read(v[0]) for k, v in o.items() if k in names}
        if argv[1] == "calculate":
            return ok(json.dumps({"sha256": [{"phase": p, "pcr": 11, "hash": self.tamper.get("calculate", predicted(parts, p))} for p in o["--phase"]]}).encode())
        value = self.tamper.get("sign-value", predicted(parts, o["--phase"][0]))
        policy = uki.policy_digest(value)
        key = self.tamper.get("sign-key", o["--private-key"][0])
        fingerprint, _ = uki.public_key(uki.read(self.tamper.get("sign-cert", o["--certificate"][0])), "a certificate")
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=bytes.fromhex(policy), capture_output=True, check=True).stdout
        document = json.loads(uki.read(o["--append"][0])) if "--append" in o else {"sha256": []}
        document["sha256"].append({"pcrs": [11], "pkfp": fingerprint, "pol": policy, "sig": base64.b64encode(signature).decode()})
        return ok(json.dumps(document).encode())

    def sbsign(self, argv, ok):
        o = self.options(argv[1:-1])
        data = uki.read(argv[-1])
        if "sbsign" in self.tamper:
            data = data.replace(b"an initrd", self.tamper["sbsign"])
        with open(o["--output"][0], "wb") as f:
            f.write(data + TRAILER)
        return ok()

    def sbverify(self, argv, ok):
        good = uki.read(argv[-1]).endswith(TRAILER)
        return ok() if good else subprocess.CompletedProcess(argv, 1, b"", b"Signature verification failed")


KEYS = None


def setUpModule():
    """The TEST keys, once for the module: three signing keys, a fourth, one too large and one that is not RSA."""
    global KEYS
    KEYS = tempfile.mkdtemp()
    unittest.addModuleCleanup(shutil.rmtree, KEYS, True)
    run = lambda *argv: subprocess.run(["openssl", *argv], check=True, capture_output=True)
    for name, bits in (("initrd", 2048), ("system", 2048), ("secure_boot", 2048), ("other", 2048), ("big", 3072)):
        key = os.path.join(KEYS, name)
        run("genrsa", "-out", key + ".key", str(bits))
        run("rsa", "-in", key + ".key", "-pubout", "-out", key + ".pub")
        run("req", "-new", "-x509", "-key", key + ".key", "-out", key + ".crt", "-subj", "/CN=TEST %s key, not for production/" % name, "-days", "30")
    run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", os.path.join(KEYS, "ec.key"))
    run("pkey", "-in", os.path.join(KEYS, "ec.key"), "-pubout", "-out", os.path.join(KEYS, "ec.pub"))


class Case(unittest.TestCase):
    @staticmethod
    def key(name, kind):
        return os.path.join(KEYS, "%s.%s" % (name, kind))

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tools = FakeTools()
        self.inputs = {}
        for name, content in (("linux", b"a kernel"), ("initrd", b"an initrd"), ("cmdline", b"root=/dev/mapper/root ro quiet\n"),
                              ("os_release", b"ID=debian\n"), ("stub", b"a stub")):
            self.inputs[name] = self.write(name, content)
        self.inputs["pcrpkey"] = self.key("system", "pub")
        self.out = os.path.join(self.d, "out")

    def write(self, name, content):
        path = os.path.join(self.d, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def build(self, **kw):
        return uki.build(dict(self.inputs, **kw.pop("inputs", {})), kw.pop("uname", "6.12.41+deb13-amd64"), kw.pop("name", "image-7"), self.out,
                         run=self.tools, **kw)

    def signing_keys(self, **change):
        keys = {role: (self.key(role, "key"), self.key(role, "crt")) for role in ("initrd", "system", "secure_boot")}
        keys.update(change)
        return keys

    def sign(self, record=None, keys=None, source="file", inputs=None):
        return uki.sign(inputs or self.inputs, record or self.build(), keys or self.signing_keys(), source, self.out, run=self.tools)

    def public(self):
        return {phase: uki.read(self.key(phase, "pub")) for phase in attest.PHASES}

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Arithmetic(unittest.TestCase):
    def test_pcr_11_is_what_systemd_measure_says(self):
        parts = {n: n.encode() for n in ("linux", "osrel", "cmdline", "initrd", "ucode", "uname", "sbat", "pcrpkey")}
        for with_ucode in (True, False):
            if not with_ucode:
                del parts["ucode"]
            for phase, path in uki.PHASE_PATHS.items():
                self.assertEqual(uki.pcr11(parts, path), VECTOR[with_ucode][phase])
                self.assertEqual(predicted(parts, path), VECTOR[with_ucode][phase])     # and the stand-in's arithmetic is right too
        self.assertEqual(uki.PHASE_PATHS, {"initrd": "enter-initrd", "system": "enter-initrd:leave-initrd:sysinit:ready"})

    def test_the_policy_digest_is_what_systemd_measure_signs(self):
        self.assertEqual(uki.policy_digest(POLICY[0]), POLICY[1])

    def test_sections_are_read_as_the_stub_measures_them(self):
        image = pe([(".text", b"code"), (".linux", b"kernel"), (".initrd", b"")])
        self.assertEqual(uki.sections(image), [(".text", b"code"), (".linux", b"kernel"), (".initrd", b"")])
        # the content ends at the virtual size, not at the padding
        self.assertEqual(dict(uki.sections(pe([(".linux", b"kernel" + bytes(20))], virtual={".linux": 6})))[".linux"], b"kernel")

    def test_a_file_the_parser_would_have_to_guess_about_is_refused(self):
        good = pe([(".linux", b"kernel")])
        cases = (("no MZ header", b"XX" + good[2:], "no MZ header"), ("too short", b"MZ", "no MZ header"),
                 ("no PE signature", good[:0x40] + b"NOPE" + good[0x44:], "no PE signature"),
                 ("the PE header beyond the file", good[:0x3c] + struct.pack("<I", len(good)) + good[0x40:], "no PE signature"),
                 ("more sections than the file holds", good[:0x46] + struct.pack("<H", 90) + good[0x48:], "not inside the file"),
                 ("no section", good[:0x46] + struct.pack("<H", 0) + good[0x48:], "not inside the file"),
                 ("two sections of one name", pe([(".linux", b"a"), (".linux", b"b")]), "two .linux sections"),
                 ("a name with a capital", pe([(".Linux", b"a")]), "has the name"),
                 ("a name with no dot", pe([("linux", b"a")]), "has the name"),
                 ("a virtual size above the raw size", pe([(".linux", b"a")], virtual={".linux": 4096}), "section .linux is not inside the file"),
                 ("raw data beyond the file", good[:-512], "section .linux is not inside the file"))
        for label, image, reason in cases:
            with self.subTest(label), self.assertRaises(m.Refused) as caught:
                uki.sections(image)
            self.assertIn(reason, str(caught.exception), label)

    def test_only_the_sections_a_kms_image_holds_are_measured(self):
        base = [(".text", b"c"), (".sbat", b"s"), (".osrel", b"o"), (".cmdline", b"c"), (".uname", b"u"), (".linux", b"l"), (".initrd", b"i")]
        self.assertEqual(list(uki.measured(pe(base + [(".pcrsig", b"{}")]))), ["linux", "osrel", "cmdline", "initrd", "uname", "sbat"])
        for extra in (".splash", ".dtb", ".profile", ".dtbauto", ".hwids", ".evil"):
            with self.subTest(extra), self.assertRaises(m.Refused) as caught:
                uki.measured(pe(base + [(extra, b"x")]))
            self.assertIn("sections a KMS host's image does not hold: %s" % extra, str(caught.exception))
        for missing in (".linux", ".initrd", ".cmdline", ".osrel", ".uname", ".sbat"):
            with self.subTest(missing=missing), self.assertRaises(m.Refused) as caught:
                uki.measured(pe([s for s in base if s[0] != missing]))
            self.assertIn("the image has no %s section" % missing, str(caught.exception))

    def test_the_command_line(self):
        self.assertEqual(uki.cmdline_text(b"root=/dev/mapper/root ro quiet console=ttyS0,115200\n"), "root=/dev/mapper/root ro quiet console=ttyS0,115200")
        # the forms that turn a shell OFF are what an image should carry (the unlock test boots with them)
        hardened = "root=/dev/mapper/root ro rd.shell=0 rd.emergency=poweroff systemd.debug_shell=0 rd.systemd.debug-shell=off"
        self.assertEqual(uki.cmdline_text(hardened.encode()), hardened)
        for raw, reason in ((b"", "one line of printable ASCII"), (b"\n", "one line of printable ASCII"), (b"a\nb\n", "one line of printable ASCII"),
                            (b"root=x\tro", "one line of printable ASCII"), ("root=é".encode(), "not ASCII")):
            with self.subTest(raw=raw), self.assertRaises(m.Refused) as caught:
                uki.cmdline_text(raw)
            self.assertIn(reason, str(caught.exception))
        for word in ("rd.luks.uuid=abcd", "rd.luks=0", "luks=no", "luks.key=/x", "rd.shell", "rd.shell=1", "rd.shell=yes", "rd.break=0",
                     "root=UUID=0b6c3d34-1e0a-4b1e-9c2e-8a1f8c9f0a11", "root=PARTUUID=abcd", "root=PARTLABEL=regalia-root", "rd.luks.options=tpm2-device=auto", "rd.break", "rd.break=pre-mount", "rd.shell",
                     "systemd.debug_shell", "systemd.debug-shell=1", "rd.systemd.debug_shell", "init=/bin/sh", "rdinit=/bin/sh",
                     "systemd.unit=emergency.target", "rd.systemd.unit=rescue.target", "emergency", "rescue", "single", "S", "s", "1", "-b"):
            with self.subTest(word=word), self.assertRaises(m.Refused) as caught:
                uki.cmdline_text(("root=/dev/mapper/root %s ro" % word).encode())
            self.assertIn("holds %r, which a KMS host's image does not carry" % word, str(caught.exception))


class Build(Case):
    def test_the_record_says_what_was_built_and_what_it_will_measure(self):
        record = self.build()
        image = uki.read(os.path.join(self.out, "image-7.unsigned.efi"))
        parts = uki.measured(image)
        self.assertEqual(record["unsigned_sha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(record["pcr11"], {phase: predicted(parts, path) for phase, path in uki.PHASE_PATHS.items()})
        self.assertNotEqual(record["pcr11"]["initrd"], record["pcr11"]["system"])
        self.assertEqual(record["sections"], {"." + n: hashlib.sha256(c).hexdigest() for n, c in parts.items()})
        self.assertEqual(parts["cmdline"], b"root=/dev/mapper/root ro quiet")            # the file's newline is not in the image
        self.assertEqual(record["inputs"]["linux"], {"sha256": hashlib.sha256(b"a kernel").hexdigest(), "size": 8})
        self.assertEqual(sorted(record["inputs"]), ["cmdline", "initrd", "linux", "os_release", "pcrpkey", "stub"])
        self.assertEqual(record["pcrpkey_pkfp"], uki.public_key(self.public()["system"], "k")[0])
        self.assertEqual(record["tools"], {"ukify": "ukify 257 (stand-in)", "systemd_measure": "systemd-measure 257 (stand-in)"})
        with open(os.path.join(self.out, "image-7.record.json"), "rb") as f:
            self.assertEqual(uki.load_record(f.read(), signed=False), record)
        self.assertEqual(sorted(os.listdir(self.out)), ["image-7.record.json", "image-7.unsigned.efi"])   # no work directory left
        # ukify was given no configuration file of the machine, and no key
        build = next(c for c in self.tools.calls if c[:2] == ["ukify", "build"])
        self.assertEqual(build[2:4], ["--config", "/dev/null"])
        self.assertFalse([a for a in build if "private" in a or "secureboot" in a])
        # the same inputs give the same record
        self.out = os.path.join(self.d, "again")
        self.assertEqual(self.build(), record)

    def test_microcode_is_its_own_measured_section(self):
        plain = self.build()
        self.out = os.path.join(self.d, "ucode")
        record = self.build(inputs={"microcode": self.write("microcode.bin", b"microcode")})
        self.assertIn(".ucode", record["sections"])
        self.assertIn("microcode", record["inputs"])
        self.assertNotEqual(record["pcr11"], plain["pcr11"])

    def test_nothing_is_written_when_this_machine_measures_differently(self):
        self.tools.tamper["calculate"] = "00" * 32
        self.refused("they measure differently, and nothing is written", self.build)
        self.assertEqual(os.listdir(self.out), [])

    def test_an_image_that_is_not_its_inputs_is_refused(self):
        for label, tamper, reason in (
                ("ukify changed the command line", {"cmdline": b" rd.break"}, "the image's .cmdline section is not the input it was built from"),
                ("ukify added to the initrd", {"initrd": b"more"}, "the image's .initrd section is not the input it was built from"),
                ("a section nobody asked for", {"extra": [(".ucode", b"x")]}, "measures sections no input accounts for: .ucode"),
                ("a section this tool does not measure", {"extra": [(".splash", b"x")]}, "sections a KMS host's image does not hold: .splash"),
                ("a signature in an unsigned build", {"extra": [(".pcrsig", b"{}")]}, "an unsigned image must have no .pcrsig section")):
            with self.subTest(label):
                self.tools.tamper = tamper
                self.refused(reason, self.build)
                self.assertEqual(os.listdir(self.out), [])

    def test_the_key_in_the_image_is_rsa_2048(self):
        self.refused("--pcrpkey is RSA-3072; the keys are RSA-2048", self.build, inputs={"pcrpkey": self.key("big", "pub")})
        self.refused("--pcrpkey is not an RSA public key: systemd seals only to RSA", self.build, inputs={"pcrpkey": self.key("ec", "pub")})
        self.refused("reading --pcrpkey failed", self.build, inputs={"pcrpkey": self.write("junk", b"not a key")})

    def test_names_and_the_command_line_are_checked_before_anything_runs(self):
        for kw, reason in (({"name": "an image"}, "short plain name"), ({"name": "../x"}, "short plain name"), ({"uname": "6.12; rm"}, "--uname must be a kernel version"),
                           ({"inputs": {"cmdline": self.write("c", b"root=x rd.luks.uuid=1\n")}}, "holds 'rd.luks.uuid=1'")):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.tools.calls.clear()
                self.refused(reason, self.build, **kw)
                self.assertFalse([c for c in self.tools.calls if c[0] == "ukify" and c[1] == "build"])

    def test_a_tool_that_is_missing_or_fails_is_a_refusal(self):
        def absent(argv, **kw):
            if argv[0] == "ukify":
                raise FileNotFoundError(2, "No such file or directory", "ukify")
            return self.tools(argv, **kw)
        self.refused("ukify build: cannot run ukify", uki.build, self.inputs, "6.12", "x", self.out, run=absent)
        failing = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b"", b"boom") if argv[0] == "ukify" else self.tools(argv, **kw)
        self.refused("ukify build failed: boom", uki.build, self.inputs, "6.12", "x", self.out, run=failing)


class Sign(Case):
    def test_a_signed_image_carries_one_signature_per_phase_by_two_keys_and_verifies(self):
        record = self.build()
        signed = self.sign(record)
        self.assertEqual({k: v for k, v in signed.items() if k != "signed"}, record)
        image = uki.read(os.path.join(self.out, "image-7.efi"))
        self.assertEqual(signed["signed"]["image_sha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(uki.measured(image), uki.measured(uki.read(os.path.join(self.out, "image-7.unsigned.efi"))))
        sigs = signed["signed"]["pcr_signatures"]
        self.assertEqual({p: sigs[p]["pol"] for p in sigs}, {p: uki.policy_digest(record["pcr11"][p]) for p in attest.PHASES})
        self.assertEqual({p: sigs[p]["pkfp"] for p in sigs}, {p: uki.public_key(self.public()[p], "k")[0] for p in attest.PHASES})
        self.assertNotEqual(sigs["initrd"]["pkfp"], sigs["system"]["pkfp"])
        self.assertEqual(len(json.loads(dict(uki.sections(image))[".pcrsig"])["sha256"]), 2)
        # each signature was asked of its own key, for its own phase, with a certificate; the second appended to the first
        asked = [FakeTools.options(c[2:]) for c in self.tools.calls if c[:2] == [uki.TOOLS["measure"], "sign"]]
        self.assertEqual([(o["--phase"], o["--private-key"], o["--certificate"]) for o in asked],
                         [([uki.PHASE_PATHS[p]], [self.key(p, "key")], [self.key(p, "crt")]) for p in attest.PHASES])
        self.assertEqual(["--append" in o for o in asked], [False, True])
        self.assertFalse([o for o in asked if "--private-key-source" in o])
        with open(os.path.join(self.out, "image-7.signed.json"), "rb") as f:
            self.assertEqual(uki.load_record(f.read(), signed=True), signed)
        self.assertEqual(uki.verify(os.path.join(self.out, "image-7.efi"), signed, self.public(), self.key("secure_boot", "crt"), run=self.tools), record["pcr11"])
        self.assertEqual(sorted(os.listdir(self.out)), ["image-7.efi", "image-7.record.json", "image-7.signed.json", "image-7.unsigned.efi"])

    def test_keys_in_a_token_are_named_by_uri_and_no_pin_travels_on_a_command_line(self):
        record = self.build()
        uri = {role: "pkcs11:token=IMAGE;object=%s;type=private" % role for role in ("initrd", "system", "secure_boot")}
        # the stand-in signer needs a key file: it is told which one, as the engine would resolve the URI
        keys = {role: (uri[role], self.key(role, "crt")) for role in uri}
        original = self.tools.systemd_measure

        def by_uri(argv, ok):
            o = FakeTools.options(argv[2:])
            if argv[1] == "sign":
                self.assertEqual(o["--private-key-source"], ["engine:pkcs11"])
                role = o["--private-key"][0].split("object=")[1].split(";")[0]
                self.tools.tamper["sign-key"] = self.key(role, "key")
            return original(argv, ok)
        self.tools.systemd_measure = by_uri
        signed = uki.sign(self.inputs, record, keys, "engine:pkcs11", self.out, run=self.tools)
        self.assertIn("signed", signed)
        sbsign = next(c for c in self.tools.calls if c[0] == "sbsign")
        self.assertEqual(sbsign[1:5], ["--engine", "pkcs11", "--key", uri["secure_boot"]])
        # the PIN's forms, not the letters: a random temporary directory can be called tmpindgrcel
        pin_forms = re.compile(r"(^|[;?&])pin-(value|source)=|^--?pin\b|^-p$|(^|_)PIN=", re.IGNORECASE)
        self.assertFalse([a for c in self.tools.calls for a in c if pin_forms.search(a)])
        for form in ("pkcs11:token=X;pin-value=1", "pkcs11:token=X?pin-source=file:/p", "--pin", "--pin=1", "--pin-value=1", "--pin-source=f", "-p", "REGALIA_PIN=1"):
            self.assertTrue(pin_forms.search(form), form)
        self.assertFalse(pin_forms.search("/tmp/tmpindgrcel/key"))
        for bad, reason in (("pkcs11:token=IMAGE;object=initrd;pin-value=648219", "carries a PIN or a PIN file in the URI"),
                            ("pkcs11:token=IMAGE;object=initrd?pin-source=file:/tmp/pin", "carries a PIN or a PIN file in the URI"),
                            (self.key("initrd", "key"), "the initrd key must be a PKCS#11 URI"), ("pkcs11:token=a b", "must be a PKCS#11 URI")):
            with self.subTest(bad=bad):
                self.tools.calls.clear()
                self.refused(reason, uki.sign, self.inputs, record, dict(keys, initrd=(bad, self.key("initrd", "crt"))), "engine:pkcs11", self.out, run=self.tools)
                self.assertEqual(self.tools.calls, [])                       # refused before any tool saw it
        self.refused("is not a file (with a token, pass --key-source engine:pkcs11", self.sign, record, dict(keys))
        self.refused("--key-source is one of file, engine:pkcs11", uki.sign, self.inputs, record, keys, "provider:pkcs11", self.out, run=self.tools)

    def test_three_different_rsa_2048_keys_and_the_system_key_is_the_one_in_the_image(self):
        record = self.build()
        pair = lambda name: (self.key(name, "key"), self.key(name, "crt"))
        for label, keys, reason in (
                ("one key for both phases", self.signing_keys(initrd=pair("system")), "must be three different keys"),
                ("the Secure Boot key is a PCR key", self.signing_keys(secure_boot=pair("initrd")), "must be three different keys"),
                ("the system key is not the image's", self.signing_keys(system=pair("other")), "the system-phase certificate is not for the key the image carries"),
                ("a larger key", self.signing_keys(initrd=pair("big")), "the initrd certificate is RSA-3072")):
            with self.subTest(label):
                self.refused(reason, self.sign, record, keys)
        self.assertFalse(os.path.exists(os.path.join(self.out, "image-7.efi")))

    def test_the_signing_machine_must_build_the_image_the_record_names(self):
        record = self.build()
        other = dict(self.inputs, initrd=self.write("initrd-2", b"an initrd, changed"))
        self.refused("the input --initrd is not the one the record was built from", self.sign, record, inputs=other)
        self.refused("the input --os-release is not the one the record was built from", self.sign, record,
                     inputs=dict(self.inputs, os_release=self.write("osrel-2", b"ID=other\n")))
        self.refused("the inputs given are not the record's set of inputs", self.sign, record, inputs=dict(self.inputs, microcode=self.write("u", b"ucode")))
        # the same inputs, and this machine's ukify produces other bytes (another version, another stub layout)
        self.tools.tamper = {"trailing": b"built elsewhere"}
        self.refused("this machine built another image than the record's", self.sign, record)
        self.tools.tamper = {}
        for label, change in (("a changed PCR 11", lambda r: r["pcr11"].update(system="00" * 32)), ("an already signed record", lambda r: r.update(signed={}))):
            with self.subTest(label):
                changed = json.loads(json.dumps(record))
                change(changed)
                with self.assertRaises(m.Refused):
                    self.sign(changed)
        self.assertFalse(os.path.exists(os.path.join(self.out, "image-7.efi")))

    def test_a_signature_that_is_not_what_was_asked_for_is_refused_before_it_is_attached(self):
        record = self.build()
        for label, tamper, reason in (
                ("the signer signed another PCR 11", {"sign-value": "ab" * 32}, "signed something other than the PCR 11 the record predicts"),
                ("the signature is by another key than the certificate's", {"sign-key": self.key("other", "key")}, "PCR signature does not verify under its key"),
                ("the signer used another certificate", {"sign-cert": self.key("other", "crt")}, "carries 0 signatures by the initrd-phase key")):
            with self.subTest(label):
                self.tools.tamper = tamper
                self.refused(reason, self.sign, record)
                self.assertFalse(os.path.exists(os.path.join(self.out, "image-7.efi")))

    def test_no_signature_may_change_what_is_measured(self):
        record = self.build()
        self.tools.tamper = {"attach": b" and more"}
        self.refused("attaching the PCR signatures changed a measured section", self.sign, record)
        self.tools.tamper = {"sbsign": b"AN INITRD"}
        self.refused("the Secure Boot signature changed a measured section", self.sign, record)
        self.tools.tamper = {}
        self.tools.sbverify = lambda argv, ok: subprocess.CompletedProcess(argv, 1, b"", b"Signature verification failed")
        self.refused("checking the Secure Boot signature failed", self.sign, record)
        self.assertFalse(os.path.exists(os.path.join(self.out, "image-7.efi")))


class Verify(Case):
    def setUp(self):
        super().setUp()
        self.record = self.sign()
        self.image = os.path.join(self.out, "image-7.efi")

    def check(self, record=None, image=None, keys=None, cert=None):
        return uki.verify(image or self.image, record or self.record, keys or self.public(), cert, run=self.tools)

    def repointed(self, data, **change):
        """A changed image, and the record made to name it (so the checks behind the file hash are reached)."""
        path = self.write("changed.efi", data)
        record = json.loads(json.dumps(self.record))
        record["signed"]["image_sha256"] = hashlib.sha256(data).hexdigest()
        record.update(change)
        return {"image": path, "record": record}

    def test_another_file_is_not_the_image(self):
        self.check()
        data = uki.read(self.image)
        self.refused("the image is not the file the record names", self.check, image=self.write("x.efi", data + b"x"))
        self.refused("the record is of an unsigned image", self.check, record={k: v for k, v in self.record.items() if k != "signed"})

    def test_a_record_cannot_vouch_for_an_image_with_other_content(self):
        data = uki.read(self.image)
        self.refused("the image's measured sections are not the record's", self.check, **self.repointed(data.replace(b"an initrd", b"AN INITRD")))
        # the sections' hashes rewritten to match: the PCR 11 the record states is still the old image's
        changed = data.replace(b"an initrd", b"AN INITRD")
        sections = {"." + n: hashlib.sha256(c).hexdigest() for n, c in uki.measured(changed).items()}
        self.refused("the image does not measure what its record says", self.check, **self.repointed(changed, sections=sections))
        # ... and with PCR 11 rewritten too, the signatures are for the old one
        pcr11 = {phase: uki.pcr11(uki.measured(changed), path) for phase, path in uki.PHASE_PATHS.items()}
        self.refused("signed something other than the PCR 11 the record predicts", self.check, **self.repointed(changed, sections=sections, pcr11=pcr11))

    def test_the_signatures_must_be_by_the_keys_the_record_names(self):
        swapped = {"initrd": self.public()["system"], "system": self.public()["initrd"]}
        self.refused("the initrd-phase key given is not the one the record names", self.check, keys=swapped)
        self.refused("the initrd-phase key given is not the one the record names", self.check,
                     keys=dict(self.public(), initrd=uki.read(self.key("other", "pub"))))
        # a certificate is accepted where a public key is
        self.check(keys={phase: uki.read(self.key(phase, "crt")) for phase in attest.PHASES})
        # an image with no signatures, or one too few
        unsigned = uki.read(os.path.join(self.out, "image-7.unsigned.efi"))
        self.refused("the image carries no PCR signatures", self.check, **self.repointed(unsigned))
        document = json.loads(dict(uki.sections(uki.read(self.image)))[".pcrsig"])
        one = self.write("one.json", json.dumps({"sha256": document["sha256"][:1]}).encode())
        fewer = uki._ukify(self.inputs, self.record["uname"], os.path.join(self.d, "fewer.efi"), self.tools, uki.TOOLS, pcrsig=one)
        self.refused("the image carries 1 PCR signatures, not one per phase", self.check, **self.repointed(fewer))
        twice = self.write("twice.json", json.dumps({"sha256": document["sha256"][:1] * 2}).encode())
        doubled = uki._ukify(self.inputs, self.record["uname"], os.path.join(self.d, "twice.efi"), self.tools, uki.TOOLS, pcrsig=twice)
        self.refused("carries 2 signatures by the initrd-phase key, not one", self.check, **self.repointed(doubled))
        other_bank = self.write("bank.json", json.dumps({"sha256": document["sha256"], "sha1": []}).encode())
        banked = uki._ukify(self.inputs, self.record["uname"], os.path.join(self.d, "bank.efi"), self.tools, uki.TOOLS, pcrsig=other_bank)
        self.refused("the PCR signatures cover a bank other than SHA-256", self.check, **self.repointed(banked))
        junk = uki._ukify(self.inputs, self.record["uname"], os.path.join(self.d, "junk.efi"), self.tools, uki.TOOLS, pcrsig=self.write("junk.json", b"not json"))
        self.refused("is not a PCR signature document", self.check, **self.repointed(junk))

    def test_the_secure_boot_signature_is_checked_against_the_recorded_certificate(self):
        self.check(cert=self.key("secure_boot", "crt"))
        self.refused("the Secure Boot certificate given is not the one the record names", self.check, cert=self.key("other", "crt"))
        self.tools.sbverify = lambda argv, ok: subprocess.CompletedProcess(argv, 1, b"", b"Signature verification failed")
        self.refused("checking the Secure Boot signature failed: Signature verification failed", self.check, cert=self.key("secure_boot", "crt"))


class Records(Case):
    def test_the_measurement_set_of_an_image_on_one_host(self):
        record = self.build()
        pcrs = {"0": "11" * 32, "7": "77" * 32}
        creds = {"regalia.node-id.cred": b"node-a\n"}
        entry = uki.measurement_set(record, "image-7", "2019102300163636", pcrs, creds)
        self.assertEqual(entry, {"label": "image-7", "tpm_firmware_version": "2019102300163636", "pcrs": dict(pcrs, **{"12": espcreds.pcr12(creds)}),
                                 "phases": {"initrd": {"11": record["pcr11"]["initrd"]}, "system": {"11": record["pcr11"]["system"]}}})
        document = {"schema": measurements.SCHEMA, "name": "v1", "nodes": {n: {"accepted": [entry]} for n in "abc"}}
        self.assertTrue(measurements.version(document).startswith("m1-"))               # it is a set the document accepts
        self.assertEqual(attest.selection(entry), [0, 7, 11, 12])
        self.refused("must not give PCR 11: it comes from the image's record, per phase", uki.measurement_set, record, "x", "0" * 16, dict(pcrs, **{"11": "00" * 32}), creds)
        self.refused("tpm_firmware_version must be 16 hex", uki.measurement_set, record, "x", "nope", pcrs, creds)
        self.refused("short plain name", uki.measurement_set, record, "an image", "0" * 16, pcrs, creds)
        self.refused("the node's credential files are required", uki.measurement_set, record, "x", "0" * 16, pcrs, None)

    def test_pcr_12_comes_from_the_nodes_credential_files_and_never_by_hand(self):
        record = self.build()
        pcrs = {"7": "77" * 32}
        files = {"regalia.node-id.cred": b"node-a\n", "regalia.boot-mesh.cred": b"mesh", "regalia.unlock-local.cred": b"sealed"}
        entry = uki.measurement_set(record, "image-7", "0" * 16, pcrs, files)
        self.assertEqual(entry["pcrs"], {"7": "77" * 32, "12": espcreds.pcr12(files)})
        self.assertNotIn("12", entry["phases"]["initrd"])                         # one value for both phases, beside PCR 7
        self.assertEqual(attest.selection(entry), [7, 11, 12])
        # another file, a changed one, or one missing: another PCR 12
        for label, other in (("one more (a unit drop-in)", dict(files, **{"x.conf.cred": b"[Service]"})),
                             ("one changed", dict(files, **{"regalia.boot-mesh.cred": b"mesh2"})),
                             ("one missing", {k: v for k, v in files.items() if k != "regalia.unlock-local.cred"})):
            with self.subTest(label):
                self.assertNotEqual(uki.measurement_set(record, "image-7", "0" * 16, pcrs, other)["pcrs"]["12"], entry["pcrs"]["12"])
        self.refused("must not give PCR 12: it is computed from the node's credential files", uki.measurement_set, record, "x", "0" * 16,
                     dict(pcrs, **{"12": "12" * 32}), files)
        self.refused("holds no credential the stub measures", uki.measurement_set, record, "x", "0" * 16, pcrs, {".hidden.cred": b"x", "notes.txt": b"y"})
        # the directory as the stub reads it: files only, no link, bounded
        esp = os.path.join(self.d, "esp"); d = os.path.join(esp, "loader", "credentials"); os.makedirs(d)
        os.makedirs(os.path.join(esp, "EFI", "Linux"))
        for name, data in files.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        self.assertEqual(uki.credential_files(esp), files)
        os.symlink(os.path.join(d, "regalia.node-id.cred"), os.path.join(d, "link.cred"))
        self.refused("link.cred is a link", uki.credential_files, esp)
        os.remove(os.path.join(d, "link.cred"))
        os.mkdir(os.path.join(d, "sub"))
        self.refused("is not a regular file", uki.credential_files, esp)            # stricter than the stub, on purpose
        os.rmdir(os.path.join(d, "sub"))
        # per-image credentials are measured into PCR 12 too: refused
        os.makedirs(os.path.join(esp, "EFI", "Linux", "regalia.efi.extra.d"))
        self.refused("the ESP holds per-image credentials or addons (EFI/Linux/regalia.efi.extra.d)", uki.credential_files, esp)
        os.rmdir(os.path.join(esp, "EFI", "Linux", "regalia.efi.extra.d"))
        self.refused("has no loader/credentials directory", uki.credential_files, os.path.join(self.d, "no-esp"))
        # global addons are measured into PCR 12 too: refused; an empty addons directory is fine
        os.makedirs(os.path.join(esp, "loader", "addons"))
        self.assertEqual(uki.credential_files(esp), files)
        open(os.path.join(esp, "loader", "addons", "x.addon.efi"), "wb").close()
        self.refused("the ESP holds global addons", uki.credential_files, esp)
        os.remove(os.path.join(esp, "loader", "addons", "x.addon.efi"))
        # FAT is case-insensitive, and so is the reader: the same checks in other cases, and twins refused
        for path, reason in ((os.path.join(esp, "EFI", "Linux", "A.EFI.EXTRA.D"), "per-image credentials or addons"),
                             (os.path.join(esp, "regalia.efi.extra.d"), "per-image credentials or addons")):
            with self.subTest(path=path):
                os.makedirs(path)
                self.refused(reason, uki.credential_files, esp)
                os.rmdir(path)
        open(os.path.join(d, "REGALIA.NODE-ID.CRED"), "wb").close()
        self.refused("holds names FAT would take for one (regalia.node-id.cred)", uki.credential_files, esp)
        os.remove(os.path.join(d, "REGALIA.NODE-ID.CRED"))
        os.symlink(esp, os.path.join(self.d, "esp-link"))
        self.refused("esp-link is a link: give the ESP itself", uki.credential_files, os.path.join(self.d, "esp-link"))
        # a link anywhere in the tree, not only on the way to the credentials
        os.symlink(os.path.join(self.d), os.path.join(esp, "EFI", "Linux", "elsewhere"))
        self.refused("is a link", uki.credential_files, esp)
        os.remove(os.path.join(esp, "EFI", "Linux", "elsewhere"))
        # the bounds: at most 32 files, each at most 1 MiB
        many = os.path.join(self.d, "many"); os.makedirs(os.path.join(many, "loader", "credentials"))
        for i in range(33):
            open(os.path.join(many, "loader", "credentials", "c%02d.cred" % i), "wb").close()
        self.refused("holds 33 files", uki.credential_files, many)
        big = os.path.join(self.d, "big"); os.makedirs(os.path.join(big, "loader", "credentials"))
        with open(os.path.join(big, "loader", "credentials", "big.cred"), "wb") as f:
            f.write(bytes(uki.MAX_CREDENTIAL_BYTES + 1))
        self.refused("is larger than", uki.credential_files, big)
        # the stub's order is the byte order of the names (strcmp16), not a case-folded one: pinned here
        # without a boot, with a pair that sorts differently under case folding
        self.assertEqual([c["file"] for c in espcreds.record({"a.cred": b"1", "B.cred": b"2"})["credentials"]], ["B.cred", "a.cred"])
        # a link on the way (loader/ pointing elsewhere) is refused
        elsewhere = os.path.join(self.d, "elsewhere"); os.rename(os.path.join(esp, "loader"), elsewhere)
        os.symlink(elsewhere, os.path.join(esp, "loader"))
        self.refused("is a link: the ESP is read as it will be installed", uki.credential_files, esp)
        self.assertFalse(os.path.islink(os.path.join(self.d, "elsewhere")))
        os.remove(os.path.join(esp, "loader")); os.rename(elsewhere, os.path.join(esp, "loader"))
        # through the command, with the record of what it was computed from
        with open(os.path.join(self.d, "host-pcrs.json"), "w") as f:
            json.dump(pcrs, f)
        rec = os.path.join(self.out, "image-7.record.json")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(uki.main(["set", "--record", rec, "--label", "image-7", "--tpm-firmware-version", "0" * 16, "--pcrs",
                                       os.path.join(self.d, "host-pcrs.json"), "--esp", esp, "--credentials-record", os.path.join(self.d, "creds.json")]), 0)
        self.assertEqual(json.loads(out.getvalue())["pcrs"]["12"], espcreds.pcr12(files))
        with open(os.path.join(self.d, "creds.json")) as f:
            self.assertEqual(json.load(f), espcreds.record(files))
        # --esp is required: a set without PCR 12 is not made at all
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as usage:
            uki.main(["set", "--record", rec, "--label", "image-7", "--tpm-firmware-version", "0" * 16, "--pcrs", os.path.join(self.d, "host-pcrs.json")])
        self.assertEqual(usage.exception.code, 2)

    def test_a_record_is_checked_when_it_is_read(self):
        record = self.build()
        for label, change, reason in (
                ("another schema", lambda r: r.update(schema="regalia.uki-build/v2"), "record schema must be"),
                ("an extra field", lambda r: r.update(note="x"), "fields mismatch"),
                ("a missing field", lambda r: r.pop("pcr11"), "fields mismatch"),
                ("one phase only", lambda r: r["pcr11"].pop("initrd"), "record.pcr11 fields mismatch"),
                ("a PCR 11 that is not a digest", lambda r: r["pcr11"].update(initrd="zz"), "not a SHA-256 in lowercase hex"),
                ("other phase paths", lambda r: r["phase_paths"].update(system="enter-initrd"), "phase paths are not this tool's"),
                ("a section this tool does not measure", lambda r: r["sections"].update({".splash": "00" * 32}), "record.sections"),
                ("an input this tool does not take", lambda r: r["inputs"].update(extra={"sha256": "00" * 32, "size": 1}), "record.inputs names an input"),
                ("a malformed signing part", lambda r: r.update(signed={"image_sha256": "00" * 32}), "record.signed fields mismatch")):
            with self.subTest(label):
                changed = json.loads(json.dumps(record))
                change(changed)
                self.refused(reason, uki.load_record, json.dumps(changed).encode())
        self.refused("a build record is one JSON object", uki.load_record, b"[]")
        self.refused("the record is of an unsigned image", uki.load_record, json.dumps(record).encode(), signed=True)

    def test_the_command_refuses_with_a_reason_and_no_traceback(self):
        argv = ["build", "--linux", self.inputs["linux"], "--initrd", self.inputs["initrd"], "--cmdline", self.write("bad", b"root=x init=/bin/sh\n"),
                "--os-release", self.inputs["os_release"], "--uname", "6.12", "--stub", self.inputs["stub"], "--pcrpkey", self.inputs["pcrpkey"],
                "--name", "x", "--out", self.out]
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(uki.main(argv), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("REFUSED: the command line holds 'init=/bin/sh'", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(uki.main(["verify", "--image", "/nonexistent", "--record", "/nonexistent", "--initrd-pub", "x", "--system-pub", "y"]), 1)
        self.assertIn("REFUSED: ", err.getvalue())


if __name__ == "__main__":
    unittest.main()
