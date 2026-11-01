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
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDS = [codecs.decode(w, "rot13") for w in ("yvfoba", "cbegb", "pbvzoen")]
_ANY = "|".join(WORDS)
_CAPS = "|".join([w.capitalize() for w in WORDS] + [w.upper() for w in WORDS])
PATTERN = re.compile(r"(?<![a-zA-Z])(?i:%s)|(?<=[a-z])(?:%s)" % (_ANY, _CAPS))


def hits(text):
    return [m.group(0) for m in PATTERN.finditer(text)]


class SiteNamesNeverAppear(unittest.TestCase):

    def test_the_scan_catches_every_shape_and_spares_english(self):
        a, b, c = WORDS
        for planted in (a, a.upper(), a.capitalize(), b + "2", b + ".boot.key", "%s_MAC" % c.upper(),
                        "from" + b.capitalize(), "x-%s-y" % c, '"node_id": "%s"' % a):
            with self.subTest(planted=planted):
                self.assertTrue(hits(planted), planted)
        for clean in ("Trans" + b[:4] + "Opener", "trans" + b[:4] + "ation", "alder birch cedar", ""):
            with self.subTest(clean=clean):
                self.assertEqual(hits(clean), [])

    def test_no_tracked_file_names_a_site(self):
        listed = subprocess.run(["git", "-C", REPO, "ls-files", "-z"], capture_output=True, check=True).stdout
        paths = [p for p in listed.decode("utf-8").split("\0") if p]
        self.assertGreater(len(paths), 100, "git ls-files listed almost nothing: the scan would prove nothing")
        found, scanned = [], 0
        for rel in paths:
            for name_hit in hits(rel):
                found.append("%s (path): %s" % (rel, name_hit))
            path = os.path.join(REPO, rel)
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin-1")      # binary files are scanned too, byte for byte
            scanned += 1
            for lineno, line in enumerate(text.splitlines(), 1):
                for name_hit in hits(line):
                    found.append("%s:%d: %s" % (rel, lineno, name_hit))
        self.assertGreater(scanned, 100)
        self.assertEqual(found, [], "real site names in a public repository; use alder/birch/cedar:\n" + "\n".join(found[:40]))


if __name__ == "__main__":
    unittest.main()
