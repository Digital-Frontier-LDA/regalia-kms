"""#620's run 40636249776: deploy/baremetal/elfclosure.py refuses an unpacked initrd whose dynamic ELF files lack
their loader or a library, and passes one that has them. The ELF files are made here, byte by byte (one PT_LOAD, a
PT_INTERP and a PT_DYNAMIC with DT_STRTAB, DT_NEEDED and DT_RUNPATH), so the test runs on any machine; the builder
runs the module on the real initrd, where test_build_initrd_inventory_out.py's guards hold it to that."""
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deploy.baremetal import elfclosure  # noqa: E402

BUILDER = (ROOT / "deploy/baremetal/initrd/build-initrd.sh").read_text()
LOADER = "/lib64/ld-linux-x86-64.so.2"


def elf(interp=None, needed=(), runpath=None, e_type=3):
    """An ELF64 LE file: one PT_LOAD covering the whole file at vaddr 0x1000, and the given PT_INTERP and dynamic
    section (a static file when there is neither)."""
    strings = b"\0"
    offsets = {}
    for s in list(needed) + ([runpath] if runpath else []):
        offsets[s] = len(strings)
        strings += s.encode() + b"\0"
    phnum = 1 + (interp is not None) + 1
    header_size, ph_size = 64, 56
    interp_off = header_size + phnum * ph_size
    interp_bytes = (interp.encode() + b"\0") if interp else b""
    strtab_off = interp_off + len(interp_bytes)
    dyn_off = strtab_off + len(strings)
    dyn_off += (-dyn_off) % 8
    vaddr = 0x1000
    dynamic = b"".join(struct.pack("<qQ", 1, offsets[n]) for n in needed)
    if runpath:
        dynamic += struct.pack("<qQ", 29, offsets[runpath])
    dynamic += struct.pack("<qQ", 5, vaddr + strtab_off) + struct.pack("<qQ", 0, 0)
    total = dyn_off + len(dynamic)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack("<HHIQQQIHHHHHH", e_type, 62, 1, 0, header_size, 0, 0, header_size, ph_size, phnum, 64, 0, 0)
    phs = struct.pack("<IIQQQQQQ", 1, 5, 0, vaddr, vaddr, total, total, 0x1000)
    if interp is not None:
        phs += struct.pack("<IIQQQQQQ", 3, 4, interp_off, vaddr + interp_off, vaddr + interp_off, len(interp_bytes), len(interp_bytes), 1)
    phs += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, vaddr + dyn_off, vaddr + dyn_off, len(dynamic), len(dynamic), 8)
    body = header + phs + interp_bytes + strings
    body += b"\0" * (dyn_off - len(body))
    return body + dynamic


class Tree:
    """An unpacked initrd laid out as Debian's merged /usr: lib, lib64 and bin are links into usr."""

    def __init__(self, test):
        self.root = tempfile.mkdtemp()
        test.addCleanup(shutil.rmtree, self.root)
        for d in ("usr/lib/x86_64-linux-gnu", "usr/lib64", "usr/bin", "usr/lib/systemd"):
            os.makedirs(os.path.join(self.root, d))
        for link, target in (("lib", "usr/lib"), ("lib64", "usr/lib64"), ("bin", "usr/bin")):
            os.symlink(target, os.path.join(self.root, link))
        # the loader as Debian ships it: lib64's name an ABSOLUTE link into the multiarch directory
        self.put("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", elf())
        os.symlink("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", os.path.join(self.root, "usr/lib64/ld-linux-x86-64.so.2"))

    def put(self, path, data):
        with open(os.path.join(self.root, path), "wb") as f:
            f.write(data)

    def whole(self):
        self.put("usr/lib/x86_64-linux-gnu/libc.so.6", elf(needed=["ld-linux-x86-64.so.2"]))
        self.put("usr/lib/x86_64-linux-gnu/libcrypto.so.3", elf(needed=["libc.so.6"]))
        self.put("usr/lib/systemd/libsystemd-shared-257.so", elf(needed=["libc.so.6"]))
        self.put("usr/bin/tpm2_unseal", elf(interp=LOADER, needed=["libc.so.6", "libcrypto.so.3"]))
        self.put("usr/lib/systemd/systemd", elf(interp=LOADER, needed=["libsystemd-shared-257.so", "libc.so.6"],
                                                runpath="$ORIGIN"))
        self.put("usr/bin/busybox", elf(e_type=2))                          # static: needs nothing
        self.put("usr/lib/x86_64-linux-gnu/thing.ko", b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9 + struct.pack("<H", 1))
        return self

    def run(self):
        done = subprocess.run([sys.executable, "-BEs", "-m", "deploy.baremetal.elfclosure", "--root", self.root],
                              capture_output=True, text=True, cwd=ROOT)
        return done.returncode, done.stdout, done.stderr


class ElfClosure(unittest.TestCase):
    def test_a_whole_initrd_passes(self):
        rc, out, err = Tree(self).whole().run()
        self.assertEqual((rc, err), (0, ""), out)
        self.assertIn("5 dynamic ELF file(s)", out)  # tpm2_unseal, systemd and the 3 libraries with a NEEDED; not ld, busybox, .ko

    def test_the_620_initrd_is_refused_by_what_it_lacks(self):
        """The libraries ldd finds are gone; the ones dracut installs by name stay, as in run 40636249776."""
        tree = Tree(self).whole()
        os.remove(os.path.join(tree.root, "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
        os.remove(os.path.join(tree.root, "usr/lib/x86_64-linux-gnu/libc.so.6"))
        rc, out, err = tree.run()
        self.assertEqual(rc, 1, out + err)
        first = out.splitlines()[0]
        self.assertRegex(first, r"^elfclosure: \d+ of \d+ dynamic ELF file\(s\) lack what they need")
        self.assertIn("the loader %s, needed by 2 file(s)" % LOADER, out)
        self.assertRegex(out, r"libc\.so\.6, needed by 4 file\(s\)")

    def test_a_library_found_only_through_runpath_needs_the_runpath(self):
        tree = Tree(self).whole()
        tree.put("usr/lib/systemd/systemd", elf(interp=LOADER, needed=["libsystemd-shared-257.so", "libc.so.6"]))
        rc, out, _ = tree.run()
        self.assertEqual(rc, 1)
        self.assertIn("libsystemd-shared-257.so, needed by 1 file(s), e.g. /usr/lib/systemd/systemd", out)

    def test_a_link_out_of_the_tree_is_not_followed(self):
        """An absolute link restarts at the initrd's root, never the builder's: the builder's own libc must not count."""
        tree = Tree(self).whole()
        os.remove(os.path.join(tree.root, "usr/lib/x86_64-linux-gnu/libcrypto.so.3"))
        os.symlink("/../../../../../../usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                   os.path.join(tree.root, "usr/lib/x86_64-linux-gnu/libcrypto.so.3"))
        rc, out, _ = tree.run()
        self.assertEqual(rc, 1)
        self.assertIn("libcrypto.so.3, needed by 1 file(s)", out)

    def test_a_malformed_elf_is_its_own_failure(self):
        tree = Tree(self).whole()
        tree.put("usr/bin/broken", elf(interp=LOADER, needed=["libc.so.6"])[:120])
        rc, _, err = tree.run()
        self.assertEqual(rc, 2)
        self.assertIn("/usr/bin/broken", err)

    def test_another_machines_elf_is_skipped_not_refused(self):
        """A device's firmware may be ELF32, big-endian or another e_machine: not this loader's, so neither judged nor
        Unreadable (which would fail the build)."""
        tree = Tree(self).whole()
        arm = bytearray(elf(interp="/lib/ld-linux-aarch64.so.1", needed=["libnothere.so"]))
        arm[18:20] = struct.pack("<H", 183)                                 # EM_AARCH64
        os.makedirs(os.path.join(tree.root, "usr/lib/firmware"))
        tree.put("usr/lib/firmware/arm.elf", bytes(arm))
        tree.put("usr/lib/firmware/elf32.bin", b"\x7fELF" + bytes([1, 1, 1]) + b"\0" * 40)
        tree.put("usr/lib/firmware/be.bin", b"\x7fELF" + bytes([2, 2, 1]) + b"\0" * 40)
        rc, out, err = tree.run()
        self.assertEqual((rc, err), (0, ""), out)
        self.assertIn("5 dynamic ELF file(s)", out)

    def test_a_directory_ld_so_conf_names_is_searched(self):
        tree = Tree(self).whole()
        os.makedirs(os.path.join(tree.root, "usr/lib/extra"))
        os.makedirs(os.path.join(tree.root, "etc/ld.so.conf.d"))
        tree.put("usr/lib/extra/libextra.so.1", elf(needed=["libc.so.6"]))
        tree.put("usr/bin/uses-extra", elf(interp=LOADER, needed=["libextra.so.1"]))
        self.assertEqual(tree.run()[0], 1, "without the configuration the library is not found")
        tree.put("etc/ld.so.conf", b"include /etc/ld.so.conf.d/*.conf\n")
        tree.put("etc/ld.so.conf.d/extra.conf", b"# a comment\n/usr/lib/extra\n")
        rc, out, _ = tree.run()
        self.assertEqual(rc, 0, out)

    def test_a_tree_with_no_dynamic_elf_judges_nothing_and_fails(self):
        """A check that judged nothing must not pass: a wrong --root, or an unpack that left nothing."""
        tree = Tree(self)
        os.remove(os.path.join(tree.root, "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
        tree.put("usr/bin/script", b"#!/bin/sh\n")
        rc, _, err = tree.run()
        self.assertEqual(rc, 2)
        self.assertIn("holds no dynamic ELF file", err)

    def test_the_module_reads_the_loader_interp_of_a_fixture_as_written(self):
        self.assertEqual(elfclosure.elf_needs(elf(interp=LOADER, needed=["a.so"], runpath="$ORIGIN/x")),
                         (LOADER, ["a.so"], ["$ORIGIN/x"]))


class BuilderRunsIt(unittest.TestCase):
    def test_build_initrd_runs_it_on_the_unpacked_initrd_records_it_and_keeps_dracuts_log(self):
        repo_files = re.search(r"^REPO_FILES=\(([^)]*)\)", BUILDER, re.M).group(1).split()
        self.assertIn("deploy/baremetal/elfclosure.py", repo_files, "its hash goes in the build record (#266)")
        self.assertRegex(BUILDER, r'python3 -BEs -m deploy\.baremetal\.elfclosure --root "\$ROOT/tmp/unpacked" \\\n'
                                  r'  \|\| \{ keep_dracut_log; die ')
        self.assertIn('keep_dracut_log(){ cp -- "$W/dracut.log" "$OUT/initrd-dracut.log"; }', BUILDER)
        # before the inventory: the cause is named before the 51-line symptom
        self.assertLess(BUILDER.index("deploy.baremetal.elfclosure --root"), BUILDER.index('inventory_check "$INVENTORY"'))


if __name__ == "__main__":
    unittest.main()
