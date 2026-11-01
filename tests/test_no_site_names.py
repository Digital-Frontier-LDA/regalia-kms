"""The real KMS site names never appear in this public repository (regalia-fft).

The 2026-09-15 publication scrubbed them; they came back with the bare-metal work and had to be scrubbed
again. This guard refuses them in every tracked text file, in any case and inside identifiers (`FOO_BAR`,
`fooBar`, `foo2`, `foo.boot.key`). The one shape it lets through is a name glued to a preceding lowercase
letter, because English words contain one of them (a `Transport` followed by `Opener`).

The words are stored ROT13-encoded so that this file does not trip its own scan. Neutral fixture names are
`alder`, `birch` and `cedar`.
"""

import codecs
import os
import re
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDS = [codecs.decode(w, "rot13") for w in ("yvfoba", "yvfobn", "cbegb", "pbvzoen")]
_ANY = "|".join(WORDS)
_CAPS = "|".join([w.capitalize() for w in WORDS] + [w.upper() for w in WORDS])
PATTERN = re.compile(r"(?<![a-zA-Z])(?i:%s)|(?<=[a-z])(?:%s)" % (_ANY, _CAPS))


def hits(text):
    return [m.group(0) for m in PATTERN.finditer(text)]


def scan(root):
    """Every hit in the tracked files under root: paths, symlink targets, and contents (binary byte for byte).
    Returns (hits, files listed, files scanned)."""
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    paths = [p for p in listed.decode("utf-8").split("\0") if p]
    found, scanned = [], 0
    for rel in paths:
        found.extend("%s (path): %s" % (rel, h) for h in hits(rel))
        path = os.path.join(root, rel)
        if os.path.islink(path):                   # a tracked symlink: its target is content too
            found.extend("%s (symlink target): %s" % (rel, h) for h in hits(os.readlink(path)))
            scanned += 1
            continue
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            found.extend("%s:%d: %s" % (rel, lineno, h) for h in hits(line))
    return found, len(paths), scanned


class SiteNamesNeverAppear(unittest.TestCase):

    def test_the_scan_catches_every_shape_and_spares_english(self):
        a, _, b, c = WORDS
        for planted in (a, a.upper(), a.capitalize(), b + "2", b + ".boot.key", "%s_MAC" % c.upper(),
                        "from" + b.capitalize(), "x-%s-y" % c, '"node_id": "%s"' % a):
            with self.subTest(planted=planted):
                self.assertTrue(hits(planted), planted)
        # An independent copy of the words (reversed, not ROT13), so a mutated WORDS cannot test itself.
        control = [w[::-1] for w in ("nobsil", "aobsil", "otrop", "arbmioc")]
        self.assertEqual(sorted(WORDS), sorted(control))
        for word in control:                       # every listed word, so none of them can go untested
            for planted in (word, word.capitalize(), word.upper() + "_X", "from" + word.capitalize()):
                with self.subTest(planted=planted):
                    self.assertEqual(hits(planted), [planted[4:] if planted.startswith("from") else planted.split("_")[0]])
        for clean in ("Trans" + b[:4] + "Opener", "trans" + b[:4] + "ation", "alder birch cedar", ""):
            with self.subTest(clean=clean):
                self.assertEqual(hits(clean), [])

    def test_the_scan_reads_paths_symlink_targets_and_contents(self):
        a, _, b, c = WORDS
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            with open(os.path.join(d, "clean.txt"), "w") as f:
                f.write("nothing here\n")
            with open(os.path.join(d, "content.txt"), "w") as f:
                f.write("x\n%s.boot.key\n" % b)
            os.symlink("../%s/target" % c, os.path.join(d, "link"))
            os.mkdir(os.path.join(d, a.capitalize()))
            with open(os.path.join(d, a.capitalize(), "f"), "w") as f:
                f.write("\n")
            subprocess.run(["git", "-C", d, "add", "-A"], check=True)
            found, listed, scanned = scan(d)
        self.assertEqual((listed, scanned), (4, 4))
        self.assertEqual(sorted(x.split(":")[0].split(" (")[0] for x in found), ["%s/f" % a.capitalize(), "content.txt", "link"])
        self.assertTrue(any("(symlink target)" in x for x in found), found)

    def test_no_tracked_file_names_a_site(self):
        found, listed, scanned = scan(REPO)
        self.assertGreater(listed, 100, "git ls-files listed almost nothing: the scan would prove nothing")
        self.assertGreater(scanned, 100)
        self.assertEqual(found, [], "real site names in a public repository; use alder/birch/cedar:\n" + "\n".join(found[:40]))


if __name__ == "__main__":
    unittest.main()
