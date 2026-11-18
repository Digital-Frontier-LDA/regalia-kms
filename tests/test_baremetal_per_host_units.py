"""What a verity host starts once ITS state is there is the image's, gated on per-host files (regalia-kms-r1s.8).

On a verity-/usr host / is a tmpfs and /etc is made from the image at every boot: PID 1 loads units while /etc is still
empty, so an operator's `systemctl enable` or a drop-in under /etc/systemd/system is never seen and is gone at the next
boot. So the image enables every unit a host runs under /usr (deploy/baremetal/image/units-enabled.txt), and what is
THIS host's decides by a per-host file under /etc whose /etc name links to /var ([per-host]: ConditionPathExists=):
the firewall, the node units, every audit shipper and its prune timer. Where a skip would leave the host unprotected
the unit that depends on it refuses: regalia-kms.service asserts the firewall's ruleset and checks its table is loaded.
The PIN credentials, the one per-host unit content, come from the /var credstore through the image's generator.

Held here, statically, with a MUTANT CONTROL for each rule (a planted regression must be refused by name); the QEMU
boots (tests/test_baremetal_unlock_boot.py, OnQemuVerity) show the same on the real image: started after a reboot, and
skipped, the KMS refusing, with the files gone. tests/etc_writes.py refuses a write under /etc/systemd/system in deploy/.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import etc_writes  # noqa: E402
from deploy.baremetal import firewall, hostpaths, trails  # noqa: E402

UNITS = "deploy/baremetal/units"
ENABLED = "deploy/baremetal/image/units-enabled.txt"
BUILD = "deploy/baremetal/image/build-rootfs.sh"
GENERATOR = "deploy/baremetal/generators/regalia-kms-credentials"
FIREWALL_DROPIN = UNITS + "/regalia-kms.service.d/firewall.conf"
NFT_DROPIN = UNITS + "/nftables.service.d/regalia.conf"
RULESET = "/etc/nftables.d/regalia-kms.nft"
NODE_JSON = "/etc/regalia/node.json"
AUDIT_ENV = "/etc/regalia/audit-ship.env"
# the operator's documents: no step in them may enable, mask or install a unit under /etc/systemd/system
DOCS = sorted([p for p in ROOT.glob("*.md")] + [p for p in (ROOT / "deploy").rglob("*.md")])


class Tree:
    """The files read, from the checkout or a mutant's overrides ({relative path: text, or None for removed})."""

    def __init__(self, overrides=None):
        self.overrides = overrides or {}

    def text(self, rel):
        if rel in self.overrides:
            return self.overrides[rel]
        path = ROOT / rel
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def listdir(self, rel):
        names = set(os.listdir(ROOT / rel)) if (ROOT / rel).is_dir() else set()
        for over, text in self.overrides.items():
            if os.path.dirname(over) == rel:
                (names.add if text is not None else names.discard)(os.path.basename(over))
        return sorted(names)


def sections(text):
    """units-enabled.txt as {section: [[field, ...], ...]}."""
    out, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[([a-z-]+)\]", line)
        if m:
            section = m.group(1)
            out.setdefault(section, [])
            continue
        out[section].append([f.strip() for f in line.split("|")])
    return out


def template(unit):
    m = re.fullmatch(r"([^@]+@)[^.]+(\..+)", unit)
    return m.group(1) + m.group(2) if m else unit


def unit_lines(tree, unit):
    """[(section, key, value)] of the unit as this repository ships it into the image: its file (deploy/baremetal/units,
    or deploy/systemd for the daemon; none for a package's unit), then its template's and its own drop-ins."""
    lines = []
    texts = []
    base = template(unit)
    for rel in (UNITS + "/" + base, "deploy/systemd/" + base):
        if tree.text(rel) is not None:
            texts.append(tree.text(rel))
            break
    for d in dict.fromkeys((base + ".d", unit + ".d")):
        for name in tree.listdir(UNITS + "/" + d):
            if name.endswith(".conf") and tree.text(UNITS + "/" + d + "/" + name) is not None:
                texts.append(tree.text(UNITS + "/" + d + "/" + name))
    for text in texts:
        section = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            key, _, value = line.partition("=")
            lines.append((section, key.strip(), value.strip()))
    return lines


def has(lines, section, key, value):
    return (section, key, value) in lines


def installs(text):
    """The [Install] WantedBy= of a unit file's text, or []."""
    section, wanted = None, []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == "Install" and line.startswith("WantedBy="):
            wanted += line.split("=", 1)[1].split()
    return wanted


def shell_blocks(text):
    """The fenced code blocks of a Markdown text, with the line each starts on."""
    out, block, start = [], None, 0
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            if block is None:
                block, start = [], number + 1
            else:
                out.append((start, "\n".join(block)))
                block = None
        elif block is not None:
            block.append(line.strip())
    return out


def problems(overrides=None):
    """Every rule broken, each naming its unit or file."""
    tree, found = Tree(overrides), []
    spec = sections(tree.text(ENABLED))
    per_host = {row[1]: row for row in spec.get("per-host", [])}
    enabled = {row[1] for row in spec.get("enabled", [])}
    # 1. every [per-host] unit is gated on a per-host file, by the unit itself or a drop-in the image installs
    for unit, (target, _, path, why) in per_host.items():
        if hostpaths.covering(path) is None:
            found.append("%s: its gate %s is not a per-host file (hostpaths.PER_HOST): on a tmpfs /etc it is the image's, "
                         "the same on every host" % (unit, path))
        if not has(unit_lines(tree, unit), "Unit", "ConditionPathExists", path):
            found.append("%s: enabled by the image for every host, and nothing says ConditionPathExists=%s" % (unit, path))
    # 2. nothing is left for an operator to enable: every unit of ours with an [Install] section is enabled by the image
    #    ([enabled]) or gated ([per-host]); a template, once per trail of the registry
    for name in tree.listdir(UNITS):
        if not re.search(r"\.(service|path|timer|socket)$", name) or tree.text(UNITS + "/" + name) is None:
            continue
        if not installs(tree.text(UNITS + "/" + name)):
            continue
        wanted = [name.replace("@.", "@%s." % t) for t in trails.TRAILS] if "@." in name else [name]
        for unit in wanted:
            if unit not in per_host and unit not in enabled:
                found.append("%s: has an [Install] section and the image neither enables nor gates it: an operator would "
                             "have to `systemctl enable` it, gone at the next boot" % unit)
    for t in trails.TRAILS:
        for unit, gate in (("regalia-audit-ship@%s.service" % t, AUDIT_ENV), ("regalia-audit-prune@%s.timer" % t, AUDIT_ENV)):
            if unit not in per_host or per_host[unit][2] != gate:
                found.append("%s: the trail %s is not shipped from /usr, gated on %s" % (unit, t, gate))
    if "nftables.service" not in per_host or per_host["nftables.service"][2] != RULESET:
        found.append("nftables.service: not enabled by the image, gated on %s" % RULESET)
    # 3. the KMS never serves without the firewall
    kms = unit_lines(tree, "regalia-kms.service")
    for key, value in (("Requires", "nftables.service"), ("After", "nftables.service"), ("AssertPathExists", RULESET)):
        if not has(kms, "Unit", key, value):
            found.append("regalia-kms.service: no %s=%s (%s)" % (key, value, FIREWALL_DROPIN))
    pre = [v for s, k, v in kms if s == "Service" and k == "ExecStartPre"]
    if not any(re.fullmatch(r"\+/usr/sbin/nft (?:--terse |-t )?list table inet %s" % re.escape(firewall.TABLE), v) for v in pre):
        found.append("regalia-kms.service: no ExecStartPre=+/usr/sbin/nft list table inet %s: it would start whatever the "
                     "kernel holds (%s)" % (firewall.TABLE, FIREWALL_DROPIN))
    if any(s == "Unit" and k == "ConditionPathExists" and v == RULESET for s, k, v in kms):
        found.append("regalia-kms.service: a ConditionPathExists=%s SKIPS the KMS without a firewall, silently: assert it" % RULESET)
    nft = unit_lines(tree, "nftables.service")
    for key in ("Requires", "After"):
        if not has(nft, "Unit", key, "regalia-etc-factory.service"):
            found.append("nftables.service: no %s=regalia-etc-factory.service: it could load an empty /etc (%s)" % (key, NFT_DROPIN))
    # 4. the image's nftables.conf loads this host's ruleset, by name, and the build installs the KMS's sandbox and generator
    build = tree.text(BUILD)
    conf = re.search(r'printf \'(#!/usr/sbin/nft -f.*?)\' *\\\n *> "\$ROOT/etc/nftables.conf"', build, re.S)
    if not conf or "flush ruleset" not in conf.group(1) or 'include "%s"' % RULESET not in conf.group(1):
        found.append("%s: the image's /etc/nftables.conf does not flush and include %s by name" % (BUILD, RULESET))
    for needle in ('"$ROOT/usr/lib/systemd/system/regalia-kms.service.d/hardening.conf"',
                   '"$ROOT/usr/lib/systemd/system-generators/regalia-kms-credentials"'):
        if needle not in build:
            found.append("%s: does not install %s" % (BUILD, needle))
    # 5. the documents: no step enables, masks or installs a unit under /etc/systemd/system
    for path in DOCS:
        rel = str(path.relative_to(ROOT))
        text = tree.text(rel) or ""
        for start, block in shell_blocks(text):
            for f in etc_writes.scan_shell(block, rel):
                if f.entry == etc_writes.SYSTEMD_ETC:
                    found.append("%s:%d: a step writes /etc/systemd/system (%s)" % (rel, start + f.line - 1, f.how))
        for number, line in enumerate(text.splitlines(), 1):
            for span in re.findall(r"`([^`]+)`", line):
                if re.match(r"/etc/systemd/system/\S", span):
                    found.append("%s:%d: names a file under /etc/systemd/system to install (%s)" % (rel, number, span))
                words = span.split()
                if words[:1] == ["systemctl"] and len(words) > 2 and etc_writes.systemctl_writes(words[1:]):
                    found.append("%s:%d: a step runs `%s`, which writes /etc/systemd/system" % (rel, number, span))
    return found


def mutate(rel, old, new):
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert text.count(old) == 1, "%s: the mutant's anchor %r is not exactly once in it" % (rel, old)
    return {rel: text.replace(old, new)}


def remove_row(unit):
    text = (ROOT / ENABLED).read_text(encoding="utf-8")
    rows = [l for l in text.splitlines(True) if l.split(" | ")[1:2] == [unit]]
    assert len(rows) == 1, unit
    return {ENABLED: text.replace(rows[0], "")}


# (name, overrides, a text the refusal must contain)
MUTANTS = [
    ("the shippers' gate removed", lambda: {UNITS + "/regalia-audit-ship@.service.d/per-host.conf": None}, "regalia-audit-ship@sync.service: enabled by the image"),
    ("the prune timers' gate removed", lambda: {UNITS + "/regalia-audit-prune@.timer.d/per-host.conf": None}, "regalia-audit-prune@update.timer: enabled by the image"),
    ("the firewall's gate removed", lambda: mutate(NFT_DROPIN, "ConditionPathExists=%s\n" % RULESET, ""), "nftables.service: enabled by the image"),
    ("a node unit's gate removed", lambda: {UNITS + "/regalia-sync.service.d/per-host.conf": None}, "regalia-sync.service: enabled by the image"),
    ("a gate on the image's /etc, not a per-host file", lambda: mutate(ENABLED, "| regalia-sync.service | %s |" % NODE_JSON, "| regalia-sync.service | /etc/os-release |"),
     "regalia-sync.service: its gate /etc/os-release is not a per-host file"),
    ("a node unit left for the operator to enable", lambda: remove_row("regalia-admission.service"), "regalia-admission.service: has an [Install] section"),
    ("a trail not shipped", lambda: remove_row("regalia-audit-ship@time.service"), "regalia-audit-ship@time.service: has an [Install] section"),
    ("the firewall not enabled", lambda: remove_row("nftables.service"), "nftables.service: not enabled by the image"),
    ("the KMS without the firewall's assert", lambda: mutate(FIREWALL_DROPIN, "AssertPathExists=%s\n" % RULESET, ""), "regalia-kms.service: no AssertPathExists="),
    ("the KMS skips instead of refusing", lambda: mutate(FIREWALL_DROPIN, "AssertPathExists=%s" % RULESET, "ConditionPathExists=%s" % RULESET),
     "SKIPS the KMS without a firewall"),
    ("the KMS not requiring nftables", lambda: mutate(FIREWALL_DROPIN, "Requires=nftables.service\n", ""), "regalia-kms.service: no Requires=nftables.service"),
    ("the KMS's table check gone", lambda: mutate(FIREWALL_DROPIN, "ExecStartPre=+/usr/sbin/nft --terse list table inet regalia_kms\n", ""),
     "regalia-kms.service: no ExecStartPre=+/usr/sbin/nft list table"),
    ("the KMS's table check on another table", lambda: mutate(FIREWALL_DROPIN, "list table inet regalia_kms", "list table inet filter"),
     "regalia-kms.service: no ExecStartPre=+/usr/sbin/nft list table"),
    ("nftables before the /etc copy", lambda: mutate(NFT_DROPIN, "Requires=regalia-etc-factory.service\n", ""), "nftables.service: no Requires=regalia-etc-factory.service"),
    ("nftables.conf includes a glob", lambda: mutate(BUILD, 'include \"/etc/nftables.d/regalia-kms.nft\"', 'include \"/etc/nftables.d/*.nft\"'),
     "the image's /etc/nftables.conf does not flush and include"),
    ("the hardening drop-in not installed", lambda: mutate(BUILD, '"$ROOT/usr/lib/systemd/system/regalia-kms.service.d/hardening.conf"', '"$ROOT/tmp/hardening.conf"'),
     "does not install \"$ROOT/usr/lib/systemd/system/regalia-kms.service.d/hardening.conf\""),
    ("README back to systemctl enable --now", lambda: mutate("deploy/baremetal/README.md", "systemctl start \\\n    regalia-audit-ship@admission", "systemctl enable --now \\\n    regalia-audit-ship@admission"),
     "deploy/baremetal/README.md:"),
    ("README back to a drop-in under /etc", lambda: mutate("deploy/baremetal/README.md", "`/usr/lib/systemd/system/regalia-kms.service.d/hardening.conf`", "`/etc/systemd/system/regalia-kms.service.d/hardening.conf`"),
     "names a file under /etc/systemd/system to install (/etc/systemd/system/regalia-kms.service.d/hardening.conf)"),
    ("a document masks inline", lambda: mutate("PIN-CUSTODY.md", "so seal only the\nIDs the manifest names.", "so seal only the\nIDs the manifest names; then `systemctl mask chronyd-restricted.service`."),
     "PIN-CUSTODY.md:"),
]


def generate(store, generator=None):
    """Runs the generator on a credstore directory; (its drop-in or None, stderr)."""
    out = tempfile.mkdtemp()
    done = subprocess.run(["sh", generator or str(ROOT / GENERATOR), out, out + "/early", out + "/late", store],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    path = Path(out) / "regalia-kms.service.d" / "50-regalia-credentials.conf"
    return (path.read_text() if path.exists() else None), done.stderr


class PerHostUnits(unittest.TestCase):
    def test_every_per_host_unit_is_enabled_by_the_image_and_gated(self):
        self.assertEqual(problems(), [], "\n" + "\n".join(problems()))

    def test_the_list_is_what_it_says(self):
        """A check that read nothing would pass: the list has the firewall, every node unit, every trail twice."""
        rows = sections((ROOT / ENABLED).read_text())["per-host"]
        self.assertEqual(len(rows), 1 + 10 + 2 * len(trails.TRAILS))
        self.assertEqual({row[2] for row in rows}, {RULESET, NODE_JSON, AUDIT_ENV})
        self.assertGreater(len(DOCS), 10)
        self.assertIn(ROOT / "deploy/baremetal/README.md", DOCS)

    def test_each_mutant_is_refused_by_name(self):
        for name, overrides, named in MUTANTS:
            with self.subTest(mutant=name):
                found = problems(overrides())
                self.assertTrue(any(named in p for p in found), "the mutant %r was not refused by %r: %s" % (name, named, found))

    def test_prose_and_starting_pass(self):
        """No-ops: prose that names the verb, and starting units now, are no step that writes /etc/systemd/system."""
        readme = (ROOT / "deploy/baremetal/README.md").read_text()
        self.assertIn("a `systemctl enable` or a drop-in under `/etc/systemd/system`", readme)
        self.assertEqual(problems(mutate("deploy/baremetal/README.md", "regalia-kms.service` then starts what the boot skipped",
                                         "regalia-kms.service` then starts what the boot skipped (`systemctl daemon-reload`, `systemctl enable --runtime x.service`)")), [])


class Generator(unittest.TestCase):
    """deploy/baremetal/generators/regalia-kms-credentials: this host's PIN credentials, from /var, named to the KMS."""

    def store(self, names, links=(), dirs=()):
        d = tempfile.mkdtemp()
        for name in names:
            Path(d, name).write_text("sealed")
        for name, target in links:
            os.symlink(target, os.path.join(d, name))
        for name in dirs:
            os.mkdir(os.path.join(d, name))
        return d

    def test_it_names_each_sealed_pin_as_seal_hsm_pin_prints_it(self):
        conf, _ = generate(self.store(["regalia-kms-hsm-site-a.pin", "regalia-kms-yubi-site-a.pin"]))
        self.assertEqual([l for l in conf.splitlines() if not l.startswith("#")], [
            "[Service]",
            "LoadCredentialEncrypted=hsm-site-a.pin:/etc/credstore.encrypted/regalia-kms-hsm-site-a.pin",
            "LoadCredentialEncrypted=yubi-site-a.pin:/etc/credstore.encrypted/regalia-kms-yubi-site-a.pin"])
        # the very line seal-hsm-pin.sh prints for the image's credstore (NAME="$ID.pin", READ_AS the /etc name)
        script = (ROOT / "deploy/seal-hsm-pin.sh").read_text()
        self.assertIn('NAME="$ID.pin"; DEST="$CREDSTORE/regalia-kms-$ID.pin"', script)
        self.assertIn('READ_AS="/etc/credstore.encrypted/regalia-kms-$ID.pin"', script)

    def test_it_names_nothing_else(self):
        conf, said = generate(self.store(
            ["regalia-kms-hsm-site-a.pin", "regalia-kms-hsm-site-a.pin.prev-20260101T000000Z", ".regalia-kms.abc123",
             ".nosig-XXXXXX", "regalia-kms-Bad.pin", "regalia-kms-a_b.pin", "regalia-kms--x.pin", "regalia-kms-x-.pin",
             "regalia-etcd-peer.key", "regalia-kms-.pin"],
            links=[("regalia-kms-link.pin", "regalia-kms-hsm-site-a.pin")], dirs=["regalia-kms-dir.pin"]))
        self.assertEqual(re.findall(r"^LoadCredentialEncrypted=(.*)$", conf, re.M),
                         ["hsm-site-a.pin:/etc/credstore.encrypted/regalia-kms-hsm-site-a.pin"])
        self.assertEqual([l for l in conf.splitlines() if not (l.startswith("#") or l == "[Service]" or l.startswith("LoadCredentialEncrypted="))], [],
                         "only credential lines: nothing else comes from /var")
        for name in ("regalia-kms-Bad.pin", "regalia-kms-a_b.pin", "regalia-kms-link.pin", "regalia-kms-dir.pin"):
            self.assertIn(name, said)

    def test_no_credstore_no_credentials_no_failure(self):
        self.assertEqual(generate(self.store([]))[0], None)
        self.assertEqual(generate("/nonexistent/regalia-credstore")[0], None)

    def test_a_generator_that_trusts_any_name_is_caught(self):
        """MUTANT: the --id check gone, a name with a newline-free but foreign shape is named, and the test above fails."""
        text = (ROOT / GENERATOR).read_text()
        anchor = '    ""|-*|*-|*--*|*[!abcdefghijklmnopqrstuvwxyz0123456789-]*) echo'
        self.assertEqual(text.count(anchor), 1)
        planted = Path(tempfile.mkdtemp(), "g")
        planted.write_text(text.replace(anchor, '    "") echo'))
        conf, _ = generate(self.store(["regalia-kms-Bad.pin"]), str(planted))
        self.assertIn("Bad.pin", conf or "")

    def test_the_generator_reads_the_var_name(self):
        """PID 1 runs it before /etc is made (/etc is EMPTY then): only the /var name is there."""
        self.assertIn('store="${4:-%s}"' % hostpaths.persistent("/etc/credstore.encrypted"), (ROOT / GENERATOR).read_text())


if __name__ == "__main__":
    unittest.main()
