"""#330: a builder whose initrd does not match the committed inventory leaves the inventory it BUILT in its --out
directory, so a snapshot move (KERNEL-UPDATE.md, "The initrd's inventory and the archive snapshot") can read and
review the whole new inventory: the mismatch message shows only the first 60 differing lines, and a kernel move
changes every module path. CI uploads --out on a failure (ci.yml initrd-reproducible's every-build artifact)."""
import pathlib
import re
import unittest

SCRIPT = (pathlib.Path(__file__).resolve().parents[1] / "deploy/baremetal/initrd/build-initrd.sh").read_text()


class BuiltInventoryKept(unittest.TestCase):
    def mismatch_block(self):
        m = re.search(r'^if ! grep -v \'\^#\' "\$INVENTORY" \| cmp -s - "\$W/inventory\.txt"; then\n(.*?)^fi$', SCRIPT, re.M | re.S)
        self.assertIsNotNone(m, "the committed-inventory comparison is not where this test expects it")
        return m.group(1)

    def test_the_built_inventory_is_written_to_out_before_the_build_dies(self):
        block = self.mismatch_block()
        keep = block.find('cp "$W/inventory.txt" "$OUT/initrd-inventory.built.txt"')
        self.assertNotEqual(keep, -1, "on a mismatch the built inventory is not copied to $OUT")
        self.assertLess(keep, block.find("die "), "the copy must come before the build dies")

    def test_nothing_else_is_kept_on_a_mismatch(self):
        """Only the inventory text: the initrd itself is not output from a build that failed its review."""
        self.assertEqual(len(re.findall(r'"\$OUT/', self.mismatch_block())), 1)

    def test_a_matching_build_writes_no_built_inventory(self):
        self.assertEqual(SCRIPT.count("initrd-inventory.built.txt"), 1)


if __name__ == "__main__":
    unittest.main()
