"""deploy/baremetal/debverify.py (#246): every "package" entry of the initrd inventory, checked against its .deb along
the archive's signed chain (InRelease by signature, Packages by its hash, the .deb by its hash, the file by its bytes).
A throwaway archive here: its own signing key (gpg), Release, Packages and .deb, served from memory."""
import contextlib
import hashlib
import io
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from deploy.baremetal import debverify as dv

BASE = "https://snapshot.example/archive/debian/20261003T121500Z"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def deb(files, compress="xz"):
    """A .deb: debian-binary, control.tar.xz, data.tar.<compress> holding `files` ({path: bytes | ("link", target)})."""
    tarbuf = io.BytesIO()
    with tarfile.open(fileobj=tarbuf, mode="w") as tar:
        made = set()
        for path, content in sorted(files.items()):
            parts = path.split("/")
            for i in range(1, len(parts)):
                d = "./" + "/".join(parts[:i])
                if d not in made:
                    info = tarfile.TarInfo(d)
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                    made.add(d)
            info = tarfile.TarInfo("./" + path)
            if isinstance(content, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, content[1]
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    raw = tarbuf.getvalue()
    data = lzma.compress(raw) if compress == "xz" else raw
    members = [(b"debian-binary", b"2.0\n"), (b"control.tar.xz", lzma.compress(b"")), (b"data.tar." + compress.encode() if compress != "tar" else b"data.tar", data)]
    out = b"!<arch>\n"
    for name, body in members:
        out += name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8) + str(len(body)).encode().ljust(10) + b"`\n"
        out += body + (b"\n" if len(body) % 2 else b"")
    return out


class Paths(unittest.TestCase):
    def test_a_deb_s_paths_lose_only_a_leading_dot_slash(self):
        files = dv.deb_files(deb({".hidden/x": b"a", "usr/lib/y": b"b"}))
        self.assertIn(".hidden/x", files)
        self.assertNotIn("hidden/x", files)


class Archive(unittest.TestCase):
    def setUp(self):
        if not (shutil.which("gpg") and shutil.which("gpgv")):
            self.skipTest("needs gpg and gpgv")
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.home = os.path.join(self.d, "gnupg")
        os.mkdir(self.home, 0o700)
        self.gpg("--quick-gen-key", "--passphrase", "", "test archive <archive@example>", "ed25519", "sign", "never")
        self.keyring = os.path.join(self.d, "keyring.gpg")
        with open(self.keyring, "wb") as f:
            f.write(self.gpg("--export").stdout)
        self.signers = {self.fingerprint(): "test archive"}
        self.served = {}
        self.packages = []

    def fingerprint(self, home=None):
        colons = subprocess.run(["gpg", "--homedir", home or self.home, "--with-colons", "--fingerprint"], capture_output=True, check=True).stdout
        return next(l.split(":")[9] for l in colons.decode().splitlines() if l.startswith("fpr:"))

    def gpg(self, *args, data=None):
        return subprocess.run(["gpg", "--homedir", self.home, "--batch", "--pinentry-mode", "loopback", *args],
                              input=data, capture_output=True, check=True)

    def publish(self, name, version, files, base=BASE, suite="trixie", tamper_deb=False):
        body = deb(files)
        filename = "pool/main/%s/%s/%s_%s_amd64.deb" % (name[0], name, name, version)
        self.served["%s/%s" % (base, filename)] = body + (b"x" if tamper_deb else b"")
        self.packages.append("Package: %s\nVersion: %s\nArchitecture: amd64\nFilename: %s\nSize: %d\nSHA256: %s\n"
                             % (name, version, filename, len(body), sha(body)))

    def release(self, base=BASE, suite="trixie", tamper_packages=False, unsigned=False):
        packages = lzma.compress("\n".join(self.packages).encode())
        self.served["%s/dists/%s/main/binary-amd64/Packages.xz" % (base, suite)] = packages + (b"!" if tamper_packages else b"")
        text = "Origin: Debian\nSuite: %s\nSHA256:\n %s %d main/binary-amd64/Packages.xz\n" % (suite, sha(packages), len(packages))
        signed = text.encode() if unsigned else self.gpg("--clearsign", data=text.encode()).stdout
        self.served["%s/dists/%s/InRelease" % (base, suite)] = signed

    def opener(self, url, timeout=None):
        if url not in self.served:
            raise OSError("404 %s" % url)
        return io.BytesIO(self.served[url])

    def run_verify(self, inventory, signers=None):
        cache = os.path.join(self.d, "cache-%d" % len(os.listdir(self.d)))
        index = dv.source_index(BASE, "trixie", self.keyring, cache, self.opener, signers=signers or self.signers)
        return dv.verify(dv.inventory_packages(inventory), index, cache, self.opener)

    def line(self, origin, kind, path, value):
        return "package %s %s 0644 0:0 %s %s" % (origin, kind, path, value)

    def test_a_package_whose_files_match_is_verified(self):
        lib = b"\x7fELF libz"
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/x86_64-linux-gnu/libz.so.1.3": lib, "usr/lib/x86_64-linux-gnu/libz.so.1": ("link", "libz.so.1.3")})
        self.publish("udev", "257.13-1", {"lib/udev/rules.d/60-block.rules": b"rules"})      # shipped under /lib (merged /usr)
        self.release()
        findings, verified = self.run_verify([
            self.line("zlib1g=1:1.3-1", "f", "usr/lib/x86_64-linux-gnu/libz.so.1.3", sha(lib)),
            self.line("zlib1g=1:1.3-1", "l", "usr/lib/x86_64-linux-gnu/libz.so.1", "libz.so.1.3"),
            self.line("zlib1g=1:1.3-1", "d", "usr/lib/x86_64-linux-gnu", "-"),
            self.line("udev=257.13-1", "f", "usr/lib/udev/rules.d/60-block.rules", sha(b"rules")),
            "generated dracut f 0644 0:0 etc/initrd-release " + "0" * 64])
        self.assertEqual(findings, [])
        self.assertEqual({k: v["version"] for k, v in verified.items()}, {"zlib1g": "1:1.3-1", "udev": "257.13-1"})
        self.assertTrue(all(len(v["deb_sha256"]) == 64 for v in verified.values()))

    def test_a_file_that_is_not_the_package_s_is_refused(self):
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/libz.so.1.3": b"genuine"})
        self.release()
        findings, verified = self.run_verify([self.line("zlib1g=1:1.3-1", "f", "usr/lib/libz.so.1.3", sha(b"planted"))])
        self.assertEqual(verified, {})
        self.assertIn("zlib1g 1:1.3-1: usr/lib/libz.so.1.3 is not the file the package ships", findings[0])

    def test_a_file_the_package_does_not_ship_a_link_elsewhere_and_another_version_are_refused(self):
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/libz.so.1.3": b"genuine", "usr/lib/libz.so.1": ("link", "libz.so.1.3")})
        self.release()
        for line, reason in ((self.line("zlib1g=1:1.3-1", "f", "usr/lib/evil.so", sha(b"x")), "ships no usr/lib/evil.so"),
                             (self.line("zlib1g=1:1.3-1", "l", "usr/lib/libz.so.1", "/tmp/evil.so"), "the link usr/lib/libz.so.1 points at /tmp/evil.so"),
                             (self.line("zlib1g=1:1.3-2", "f", "usr/lib/libz.so.1.3", sha(b"genuine")), "not in the signed Packages of any source")):
            with self.subTest(reason):
                findings, _ = self.run_verify([line])
                self.assertTrue(any(reason in f for f in findings), findings)

    def test_every_link_of_the_chain_is_checked(self):
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/libz.so.1.3": b"genuine"}, tamper_deb=True)
        self.release()
        findings, _ = self.run_verify([self.line("zlib1g=1:1.3-1", "f", "usr/lib/libz.so.1.3", sha(b"genuine"))])
        self.assertIn("is not the .deb its signed Packages states", findings[0])
        # Packages that is not the one the signed Release states
        self.served.clear()
        self.packages.clear()
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/libz.so.1.3": b"genuine"})
        self.release(tamper_packages=True)
        with self.assertRaisesRegex(dv.Refused, "is not the one its signed Release states"):
            self.run_verify([])
        # a Release no key of the keyring signed, or none at all
        self.release(unsigned=True)
        with self.assertRaisesRegex(dv.Refused, "signature does not verify"):
            self.run_verify([])
        other = os.path.join(self.d, "other")
        os.mkdir(other, 0o700)
        subprocess.run(["gpg", "--homedir", other, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                        "intruder <x@example>", "ed25519", "sign", "never"], capture_output=True, check=True)
        text = b"Origin: Debian\nSHA256:\n"
        forged = subprocess.run(["gpg", "--homedir", other, "--batch", "--clearsign"], input=text, capture_output=True, check=True).stdout
        self.served["%s/dists/trixie/InRelease" % BASE] = forged
        with self.assertRaisesRegex(dv.Refused, "signature does not verify"):
            self.run_verify([])

    def test_only_a_good_signature_by_a_pinned_key_is_trusted(self):
        """gpgv's exit status says a key of the keyring signed; the status lines say which, and whether it has expired."""
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/libz.so.1.3": b"genuine"})
        self.release()
        self.assertEqual(self.run_verify([])[0], [])
        # a key in the keyring that is not pinned: refused, though gpgv exits 0
        with self.assertRaisesRegex(dv.Refused, "no good signature by a pinned key"):
            self.run_verify([], signers={"A" * 40: "another"})
        # the pinned key, expired: refused (a key made and used in 2020, expired a day later)
        old = os.path.join(self.d, "old")
        os.mkdir(old, 0o700)
        past = ["gpg", "--homedir", old, "--batch", "--pinentry-mode", "loopback", "--faked-system-time", "20200101T000000"]
        subprocess.run(past + ["--passphrase", "", "--quick-gen-key", "old archive <old@example>", "ed25519", "sign", "1d"], capture_output=True, check=True)
        text = b"Origin: Debian\nSHA256:\n"
        self.served["%s/dists/trixie/InRelease" % BASE] = subprocess.run(past + ["--clearsign"], input=text, capture_output=True, check=True).stdout
        with open(self.keyring, "wb") as f:
            f.write(subprocess.run(["gpg", "--homedir", old, "--export"], capture_output=True, check=True).stdout)
        with self.assertRaisesRegex(dv.Refused, "signature by the pinned key [0-9A-F]{40} is EXPKEYSIG"):
            self.run_verify([], signers={self.fingerprint(old): "old"})

    def test_dracut_s_overwrites_are_held_to_the_pinned_list_and_dracut_core(self):
        unit = b"[Unit]\nDescription=dracut mount hook\n"
        self.publish("dracut-core", "106-6", {"usr/lib/dracut/modules.d/98dracut-systemd/dracut-mount.service": unit,
                                              "usr/lib/systemd/system/dracut-mount.service": b"the host's copy"})
        self.release()
        cache = os.path.join(self.d, "cache-over")
        index = dv.source_index(BASE, "trixie", self.keyring, cache, self.opener, signers=self.signers)
        pinned = {"usr/lib/systemd/system/dracut-mount.service": ("dracut-core", ("dracut-core", "usr/lib/dracut/modules.d/98dracut-systemd/dracut-mount.service")),
                  "var/run": ("base-files", ("link", "../run"))}

        def check(*over):
            owned, entries = dv.inventory_entries(list(over))
            return dv.verify_dracut_over(entries, dv.inventory_versions(owned, entries), pinned, index, cache, self.opener)
        unit_line = "generated dracut-over:dracut-core=106-6 f 0644 0:0 usr/lib/systemd/system/dracut-mount.service "
        self.assertEqual(check(unit_line + sha(unit), "generated dracut-over:base-files=13.8 l 0777 0:0 var/run ../run"), [])
        for over, reason in ((unit_line + sha(b"planted"), "not dracut-core's usr/lib/dracut/modules.d/98dracut-systemd/dracut-mount.service"),
                             ("generated dracut-over:base-files=13.8 l 0777 0:0 var/run /tmp", "dracut's link points at /tmp"),
                             ("generated dracut-over:udev=1 f 0644 0:0 usr/lib/udev/x.rules " + sha(b"x"), "is not on the pinned list"),
                             ("generated dracut-over:systemd=1 l 0777 0:0 var/run ../run", "is not on the pinned list")):
            with self.subTest(reason):
                self.assertTrue(any(reason in f for f in check(over)), check(over))
        with self.assertRaisesRegex(dv.Refused, "names dracut-core at two versions"):
            check(unit_line + sha(unit), "package dracut-core=106-7 f 0644 0:0 usr/bin/dracut " + sha(b"d"))

    def test_the_keyring_must_be_the_pinned_one(self):
        inventory = os.path.join(self.d, "inventory.txt")
        with open(inventory, "w") as f:
            f.write("# nothing\n")
        out = os.path.join(self.d, "out.json")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = dv.main(["--inventory", inventory, "--keyring", self.keyring, "--source", BASE, "trixie",
                            "--cache", os.path.join(self.d, "c"), "--out", out])
        self.assertEqual(code, 1)
        self.assertIn("is not the pinned Debian archive keyring", err.getvalue())
        self.assertFalse(os.path.exists(out))

    def test_a_package_that_cannot_be_fetched_is_refused(self):
        self.publish("zlib1g", "1:1.3-1", {"usr/lib/libz.so.1.3": b"genuine"})
        self.release()
        self.served = {k: v for k, v in self.served.items() if not k.endswith(".deb")}
        findings, verified = self.run_verify([self.line("zlib1g=1:1.3-1", "f", "usr/lib/libz.so.1.3", sha(b"genuine"))])
        self.assertEqual(verified, {})
        self.assertIn("cannot be fetched", findings[0])


if __name__ == "__main__":
    unittest.main()
