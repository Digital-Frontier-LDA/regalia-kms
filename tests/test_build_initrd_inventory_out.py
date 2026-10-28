"""#330, #620's run 40636249776: a builder whose initrd does not match the committed inventory leaves, in its --out
directory, the inventory it BUILT, the committed lines it was compared with and their whole difference, and says the
difference's size before any excerpt. A snapshot move (KERNEL-UPDATE.md) reads the whole new inventory there, and a
failed CI run keeps all three (ci.yml initrd-reproducible's every-build artifact; unlock-boot-qemu's diagnostics), so
a mismatch's cause can still be read. inventory_check (deploy/baremetal/initrd/inventory-check.sh) is run here on
fixture inventories, as build-initrd.sh runs it."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "deploy/baremetal/initrd/inventory-check.sh"
BUILDER = (ROOT / "deploy/baremetal/initrd/build-initrd.sh").read_text()
UNLOCK = (ROOT / "e2e/unlock-boot-qemu.sh").read_text()
KEPT = ["initrd-inventory.built.txt", "initrd-inventory.committed.txt", "initrd-inventory.diff"]


def lines(n, prefix="package libc6=2.41-12+deb13u4 f 0644 0:0 usr/lib/x86_64-linux-gnu/lib"):
    return ["%s%04d.so %s" % (prefix, i, "%064x" % i) for i in range(n)]


@unittest.skipUnless(shutil.which("bash") and shutil.which("diff") and shutil.which("cmp"), "bash, diff and cmp are required")
class InventoryCheck(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.work, self.out = os.path.join(self.d, "w"), os.path.join(self.d, "out")
        os.mkdir(self.work)
        os.mkdir(self.out)

    def check(self, committed, built):
        c, b = os.path.join(self.d, "committed.txt"), os.path.join(self.work, "inventory.txt")
        with open(c, "w") as f:
            f.write("".join(line + "\n" for line in committed))
        if built is not None:
            with open(b, "w") as f:
                f.write("".join(line + "\n" for line in built))
        # SIGPIPE ignored, as on the CI runner whose log showed "grep: write error: Broken pipe": a writer into a
        # reader that stops early then lives to say so, instead of dying silently
        done = subprocess.run(["bash", "-c", "trap '' PIPE; set -euo pipefail; . \"$1\"; inventory_check \"$2\" \"$3\" \"$4\" \"$5\"", "check",
                               str(LIB), c, b, self.work, self.out], capture_output=True, text=True)
        return done.returncode, done.stdout, done.stderr

    def test_an_equal_inventory_passes_and_keeps_nothing(self):
        body = lines(5)
        rc, out, err = self.check(["# a comment line, not compared", *body, "# another"], body)
        self.assertEqual((rc, os.listdir(self.out), err), (0, [], ""))

    def test_a_mismatch_keeps_both_inventories_and_the_whole_difference(self):
        body = lines(10)
        built = body[:2] + body[5:] + ["generated dracut f 0644 0:0 etc/ld.so.cache " + "f" * 64]
        rc, out, err = self.check(body, built)
        self.assertEqual(rc, 1)
        self.assertEqual(sorted(os.listdir(self.out)), KEPT, "only the three text files: never the initrd")
        with open(os.path.join(self.out, "initrd-inventory.built.txt")) as f:
            self.assertEqual(f.read().splitlines(), built)
        with open(os.path.join(self.out, "initrd-inventory.committed.txt")) as f:
            self.assertEqual(f.read().splitlines(), body)
        with open(os.path.join(self.out, "initrd-inventory.diff")) as f:
            diff = f.read().splitlines()
        self.assertEqual([line[2:] for line in diff if line.startswith("< ")], body[2:5])
        self.assertEqual(len([line for line in diff if line.startswith("> ")]), 1)
        self.assertNotIn("Broken pipe", err)

    def test_the_size_is_said_before_the_excerpt_however_large(self):
        """#620's run: the excerpt was cut at 60 lines and read as the difference's size. 2400 lines are missing here,
        a diff far larger than a pipe's buffer, so an excerpt taken through a pipe would make diff's write fail."""
        body = lines(3000)
        rc, out, err = self.check(body, body[:300] + body[2700:])
        self.assertEqual(rc, 1)
        said = out.splitlines()
        self.assertIn("2400 committed line(s) the built initrd lacks, 0 built line(s) not committed", said[0])
        self.assertEqual(len(said), 2 + 60, "the counts, where the whole diff is, then 60 lines of it")
        with open(os.path.join(self.out, "initrd-inventory.diff")) as f:
            self.assertEqual(sum(1 for line in f if line.startswith("< ")), 2400, "the kept diff is whole")
        self.assertEqual(err, "", "no writer dies of SIGPIPE")

    def test_an_unreadable_side_is_its_own_failure(self):
        rc, out, err = self.check(lines(3), None)
        self.assertEqual(rc, 2)
        self.assertIn("is missing", err)


class BuilderUsesIt(unittest.TestCase):
    def test_build_initrd_sources_it_records_it_and_dies_on_its_answer(self):
        self.assertIn('. "$REPO/deploy/baremetal/initrd/inventory-check.sh"', BUILDER)
        repo_files = re.search(r"^REPO_FILES=\(([^)]*)\)", BUILDER, re.M).group(1).split()
        self.assertIn("deploy/baremetal/initrd/inventory-check.sh", repo_files, "its hash goes in the build record (#266)")
        self.assertRegex(BUILDER, r'inventory_check "\$INVENTORY" "\$W/inventory\.txt" "\$W" "\$OUT" \\\n  \|\| \{ keep_dracut_log; die ')

    def test_no_inventory_is_compared_through_a_pipe(self):
        self.assertNotRegex(BUILDER, r"\|\s*cmp\b")
        self.assertNotRegex(BUILDER, r'"\$INVENTORY"\)?\s*[^\n]*\|\s*head\b')

    def test_unlock_boot_qemu_keeps_the_three_files_with_its_diagnostics(self):
        self.assertIn('cp -- "$W"/initrd-build/initrd-inventory.* "$W"/initrd-build/initrd-dracut.log "$REGALIA_DIAG_DIR"/', UNLOCK)


if __name__ == "__main__":
    unittest.main()
