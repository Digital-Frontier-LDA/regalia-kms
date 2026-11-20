"""The initrd's exact always-loaded module set (r1s.15, r1s.19).

The verity /usr carries no modules. The initrd preloads the firewall's three modules and the ESP/codepage/binfmt
modules needed after switch-root, including before genesis. Every .ko was already in the reviewed initrd. Keep
both preload files, their producer bytes, inventory hashes and module sets exact; an unrelated addition must fail.
"""
import hashlib
import pathlib
import re
import unittest

from deploy.baremetal import uki

REPO = pathlib.Path(__file__).resolve().parent.parent
INVENTORY = REPO / "deploy" / "baremetal" / "initrd" / "initrd-inventory.txt"
SETUP = REPO / "deploy" / "baremetal" / "initrd" / "dracut" / "90regalia-unlock" / "module-setup.sh"

LOADED_BEFORE = frozenset()                                  # 6c1e6a12: no modules-load.d file in the initrd
ADDED = frozenset({"nf_tables", "nft_ct", "nf_conntrack"})   # r1s.15: unchanged firewall set
FILESYSTEM_ADDED = frozenset({"vfat", "nls_cp437", "nls_ascii", "nls_iso8859-1", "nls_utf8", "binfmt_misc"})


def inventory():
    """{path: (class, type, value)} of the committed (reviewed) initrd inventory."""
    entries = {}
    for line in INVENTORY.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cls, _, kind, _, _, path, value = line.split(" ")
        entries[path] = (cls, kind, value)
    return entries


def loads(body):
    """The modules a modules-load.d file names (modules-load.d(5): one per line, # and ; comments)."""
    return [l.strip() for l in body.decode().splitlines() if l.strip() and not l.lstrip().startswith(("#", ";"))]


class TheFirewallModules(unittest.TestCase):
    def test_the_initrd_loads_exactly_the_reviewed_firewall_and_filesystem_sets(self):
        path, body = uki.FIREWALL_MODULES_LOAD
        named = loads(body)
        self.assertEqual(len(named), len(set(named)), named)
        self.assertEqual(frozenset(named), LOADED_BEFORE | ADDED)
        self.assertEqual(frozenset(uki.FIREWALL_MODULES), LOADED_BEFORE | ADDED)
        filesystem_path, filesystem_body = uki.FILESYSTEM_MODULES_LOAD
        self.assertEqual(frozenset(uki.FILESYSTEM_MODULES), FILESYSTEM_ADDED)
        filesystem_named = loads(filesystem_body)
        self.assertEqual(len(filesystem_named), len(set(filesystem_named)), filesystem_named)
        self.assertEqual(frozenset(filesystem_named), FILESYSTEM_ADDED)
        files = sorted(p for p, (_, kind, _) in inventory().items()
                       if kind != "d" and re.search(r"(^|/)modules-load\.d/", p))
        self.assertEqual(files, sorted((path, filesystem_path)), "the initrd's exact modules-load.d files")
        for name, content in ((path, body), (filesystem_path, filesystem_body)):
            self.assertEqual(inventory()[name], ("ours", "f", hashlib.sha256(content).hexdigest()))

    def test_module_setup_writes_exactly_the_pinned_bytes(self):
        text = SETUP.read_text()
        writes = re.findall(r"printf '([^']*)'\s*(?:\\\n\s*)?> \"\$\{initdir:\?\}/usr/lib/modules-load\.d/([^\"]+)\"", text)
        self.assertEqual(len(writes), 2, writes)
        written = {"usr/lib/modules-load.d/" + name: fmt.replace("\\n", "\n").encode() for fmt, name in writes}
        self.assertEqual(written, dict((uki.FIREWALL_MODULES_LOAD, uki.FILESYSTEM_MODULES_LOAD)))

    def test_each_module_is_one_the_initrd_carries(self):
        kos = {p.rsplit("/", 1)[1] for p in inventory() if p.startswith("usr/lib/modules/") and p.endswith(".ko.xz")}
        for name in sorted(ADDED | FILESYSTEM_ADDED | {"fat"}):
            with self.subTest(module=name):
                self.assertIn(name + ".ko.xz", kos)
        self.assertRegex(SETUP.read_text(), r"instmods wireguard nf_tables nft_ct nf_conntrack ")


if __name__ == "__main__":
    unittest.main()
