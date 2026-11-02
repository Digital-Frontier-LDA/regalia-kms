"""The real KMS site names never appear in this public repository (regalia-fft).

The 2026-09-15 publication scrubbed them; they came back with the bare-metal work and had to be scrubbed
again. This guard refuses them in every tracked file, in any case and inside identifiers (`FOO_BAR`,
`fooBar`, `foo2`, `foo.boot.key`): in paths, symlink targets and contents, the contents read as UTF-8 (or
byte for byte) and, where they hold NUL bytes, as UTF-16 in both byte orders (regalia-iy9). The one shape it
lets through is a name glued to a preceding lowercase letter, because English words contain one of them (a
`Transport` followed by `Opener`).

It never prints a name, not even when it fails (regalia-9lr): this is a public repository and its CI logs
are public. A hit is reported as `<site-N>`, N being the word's place in WORDS, and the controls report
word and shape numbers. The words are stored ROT13-encoded so this file does not trip its own scan.
Neutral fixture names are `alder`, `birch` and `cedar`.
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


def redact(text):
    """text with every hit replaced by <site-N>: the only form a hit is ever printed in."""
    return PATTERN.sub(lambda m: "<site-%d>" % (WORDS.index(m.group(0).lower()) + 1), text)


def decodings(data):
    """(label, text) for every reading of a file's bytes the scan makes."""
    try:
        out = [("", data.decode("utf-8"))]
    except UnicodeDecodeError:
        out = [("", data.decode("latin-1"))]
    if b"\0" in data:                              # UTF-16 hides a name from a byte-wise reading
        for offset in (0, 1):
            for codec in ("utf-16-le", "utf-16-be"):
                out.append((" (%s+%d)" % (codec, offset), data[offset:].decode(codec, "ignore")))
    return out


def scan(root):
    """Every hit in the tracked files under root, redacted. Returns (hits, files listed, files scanned)."""
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    paths = [p for p in listed.decode("utf-8").split("\0") if p]
    found, scanned = [], 0
    for rel in paths:
        shown = redact(rel)
        found.extend("%s (path): %s" % (shown, redact(h)) for h in hits(rel))
        path = os.path.join(root, rel)
        if os.path.islink(path):                   # a tracked symlink: its target is content too
            found.extend("%s (symlink target): %s" % (shown, redact(h)) for h in hits(os.readlink(path)))
            scanned += 1
            continue
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        scanned += 1
        for label, text in decodings(data):
            for lineno, line in enumerate(text.splitlines(), 1):
                found.extend("%s:%d%s: %s" % (shown, lineno, label, redact(h)) for h in hits(line))
    return found, len(paths), scanned


class SiteNamesNeverAppear(unittest.TestCase):
    # Every assertion here reports numbers, never a word: a failing guard must not print the names.

    def test_the_scan_catches_every_shape_and_spares_english(self):
        # An independent copy of the words (reversed, not ROT13), so a mutated WORDS cannot test itself.
        control = [w[::-1] for w in ("nobsil", "aobsil", "otrop", "arbmioc")]
        self.assertTrue(sorted(WORDS) == sorted(control), "WORDS differs from the control list")
        for i, word in enumerate(control, 1):      # every listed word, so none of them can go untested
            shapes = (word, word.capitalize(), word.upper(), word.upper() + "_MAC", "from" + word.capitalize(),
                      word + "2", word + ".boot.key", "x-%s-y" % word, '"node_id": "%s"' % word)
            for j, planted in enumerate(shapes, 1):
                found = hits(planted)
                self.assertTrue(len(found) == 1 and found[0].lower() == word, "word %d, shape %d: not caught" % (i, j))
                self.assertTrue(redact(planted).count("<site-%d>" % i) == 1 and not hits(redact(planted)),
                                "word %d, shape %d: not redacted" % (i, j))
        b = control[2]
        for j, clean in enumerate(("Trans" + b[:4] + "Opener", "trans" + b[:4] + "ation", "alder birch cedar", ""), 1):
            self.assertTrue(hits(clean) == [], "clean text %d flagged" % j)

    def test_the_scan_reads_paths_symlink_targets_contents_and_utf16(self):
        a, _, b, c = WORDS
        d_ = WORDS[1]
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            files = {"clean.txt": b"nothing here\n", "content.txt": ("x\n%s.boot.key\n" % b).encode(),
                     os.path.join(a.capitalize(), "f"): b"\n",
                     "le.txt": ("x\n%s\n" % c).encode("utf-16"),          # with a BOM, little-endian here
                     "be.bin": b"\x01" + ("%s\n" % d_.upper()).encode("utf-16-be"),   # no BOM, at an odd offset
                     "clean16.txt": "nothing\n".encode("utf-16")}
            for rel, data in files.items():
                os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
                with open(os.path.join(d, rel), "wb") as f:
                    f.write(data)
            os.symlink("../%s/target" % c, os.path.join(d, "link"))
            subprocess.run(["git", "-C", d, "add", "-A"], check=True)
            found, listed, scanned = scan(d)
        self.assertTrue((listed, scanned) == (7, 7), "listed %d, scanned %d, not 7 and 7" % (listed, scanned))
        flagged = sorted(set(x.split(":")[0].split(" (")[0] for x in found))
        expected = ["<site-1>/f", "be.bin", "content.txt", "le.txt", "link"]
        self.assertTrue(flagged == expected, "flagged %d files, %d of them the expected ones; want exactly %d"
                        % (len(flagged), len(set(flagged) & set(expected)), len(expected)))
        self.assertTrue(any("(symlink target)" in x for x in found), "no symlink-target hit")
        self.assertTrue(any("(utf-16-be+1)" in x for x in found), "no UTF-16 hit at an odd offset")
        self.assertTrue(not hits("\n".join(found)), "the scan's own report names a site")

    def test_no_tracked_file_names_a_site(self):
        found, listed, scanned = scan(REPO)
        self.assertGreater(listed, 100, "git ls-files listed almost nothing: the scan would prove nothing")
        self.assertGreater(scanned, 100)
        self.assertTrue(found == [], "real site names in a public repository (shown redacted); use alder/birch/cedar:\n"
                        + "\n".join(found[:40]))


if __name__ == "__main__":
    unittest.main()
