"""regalia-kms-r1s.15: the initrd loads the firewall's kernel modules on every boot, and exactly those.

The image's /usr holds no kernel modules (the dm-verity design, #61), so the host's ruleset (nftables.service, after
switch-root) loads only with modules that are loaded already. Before this the initrd loaded nf_tables only for the boot
mesh (wg-boot, after the renderer), and a boot whose mesh did not run (every boot before genesis: found on the staging
DL360, regalia-kms-dx7.14) came up with no firewall, and the KMS refused for want of it. The fix is fail-closed and
adds nothing else: the initrd's always-loaded set is the previous one (none: origin/main 6c1e6a12's inventory has no
modules-load.d file) plus exactly nf_tables, nft_ct and nf_conntrack, whose .ko files the initrd already carried."""
import hashlib
import pathlib
import re
import unittest

from deploy.baremetal import uki

REPO = pathlib.Path(__file__).resolve().parent.parent
INVENTORY = REPO / "deploy" / "baremetal" / "initrd" / "initrd-inventory.txt"
SETUP = REPO / "deploy" / "baremetal" / "initrd" / "dracut" / "90regalia-unlock" / "module-setup.sh"

LOADED_BEFORE = frozenset()                                  # 6c1e6a12: no modules-load.d file in the initrd
ADDED = frozenset({"nf_tables", "nft_ct", "nf_conntrack"})   # the PA's decision of 2026-11-19, and nothing else


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
    def test_the_initrd_loads_the_previous_set_plus_exactly_these_three(self):
        path, body = uki.FIREWALL_MODULES_LOAD
        named = loads(body)
        self.assertEqual(len(named), len(set(named)), named)
        self.assertEqual(frozenset(named), LOADED_BEFORE | ADDED)
        self.assertEqual(frozenset(uki.FIREWALL_MODULES), LOADED_BEFORE | ADDED)
        files = sorted(p for p, (_, kind, _) in inventory().items()
                       if kind != "d" and re.search(r"(^|/)modules-load\.d/", p))
        self.assertEqual(files, [path], "the initrd's modules-load.d files")
        self.assertEqual(inventory()[path], ("ours", "f", hashlib.sha256(body).hexdigest()))

    def test_module_setup_writes_exactly_the_pinned_bytes(self):
        text = SETUP.read_text()
        writes = re.findall(r"printf '([^']*)' > \"\$\{initdir:\?\}/usr/lib/modules-load\.d/([^\"]+)\"", text)
        self.assertEqual(len(writes), 1, writes)
        fmt, name = writes[0]
        self.assertEqual("usr/lib/modules-load.d/" + name, uki.FIREWALL_MODULES_LOAD[0])
        self.assertEqual(fmt.replace("\\n", "\n").encode(), uki.FIREWALL_MODULES_LOAD[1])

    def test_each_module_is_one_the_initrd_carries(self):
        kos = {p.rsplit("/", 1)[1] for p in inventory() if p.startswith("usr/lib/modules/") and p.endswith(".ko.xz")}
        for name in sorted(ADDED):
            with self.subTest(module=name):
                self.assertIn(name + ".ko.xz", kos)
        self.assertRegex(SETUP.read_text(), r"instmods wireguard nf_tables nft_ct nf_conntrack ")


if __name__ == "__main__":
    unittest.main()
