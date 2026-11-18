"""regalia-kms-dx7.11: docs/single-node-limits.md is the one source of the "1 node or 3 nodes?" table.

The single-node genesis (slice dx7.2) prints that file and records the SHA-256 of its bytes in the root-signed
manifest, so it must stay plain ASCII text with a version line. README.md ("## 1 node or 3 nodes?") and
LIMITATIONS.md ("## Single-node deployments") carry copies of its table; this test holds each copy equal to it, line
for line, and holds every not-supported or degraded row to an accepted entry in LIMITATIONS that cites
regalia-kms-dx7. The controls edit one cell of a copy, in memory, and require the comparison to fail."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "docs" / "single-node-limits.md"
COPIES = {"README.md": "## 1 node or 3 nodes?", "LIMITATIONS.md": "## Single-node deployments"}
WORDS = ("supported", "degraded", "not supported")
VERSION = "Version: regalia.single-node-limits/v1"

# The rows the bead's acceptance criteria name, each by the start of its feature cell.
REQUIRED = (
    "Activation", "Survives the loss of a node", "Survives a site", "Unattended reboot",
    "Theft of a powered-off node", "Theft of a running node", "Root compromise", "Revocation", "Heartbeats",
    "Rolling measured-boot update", "Site advance", "Re-anchor after anchor damage", "Recovery after a total outage",
    "Lone-survivor mode, fencing", "Cross-node detection", "Audit trail", "Operation approvals", "Stateful operations",
)


def section(text, heading):
    """The body under `heading` (a level-2 heading) up to the next level-2 heading."""
    start = text.index("\n" + heading + "\n")
    rest = text[start + len(heading) + 2:]
    end = re.search(r"^## ", rest, re.M)
    return rest[:end.start()] if end else rest


def table(text):
    """The first markdown table in `text`: its lines, as written."""
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith("|"))
    end = next((i for i in range(start, len(lines)) if not lines[i].startswith("|")), len(lines))
    return lines[start:end]


def rows(lines):
    """(feature, 1 node, 3 nodes, consequence) for each body row."""
    return [tuple(cell.strip() for cell in line.strip("|").split("|")) for line in lines[2:]]


def differences(canonical, copy):
    """Every line of `copy`'s table that is not the canonical table's, by position."""
    want, got = table(canonical), table(copy)
    out = ["line %d: %r != %r" % (i + 1, g, w) for i, (w, g) in enumerate(zip(want, got)) if w != g]
    if len(want) != len(got):
        out.append("%d lines, not %d" % (len(got), len(want)))
    return out


class CanonicalText(unittest.TestCase):
    def setUp(self):
        self.data = CANONICAL.read_bytes()
        self.text = self.data.decode("ascii")       # plain ASCII: it is printed on the ceremony terminal and hashed

    def test_it_is_plain_text_with_a_version_line(self):
        self.assertNotIn(b"\r", self.data)
        self.assertTrue(self.data.endswith(b"\n") and not self.data.endswith(b"\n\n"))
        self.assertIn("\n" + VERSION + "\n", self.text)

    def test_its_table_has_four_columns_and_only_the_three_words(self):
        lines = table(self.text)
        self.assertEqual(lines[0], "| Feature or guarantee | 1 node | 3 nodes | Consequence with 1 node |")
        self.assertEqual(lines[1], "|---|---|---|---|")      # without it GitHub renders no table, copies or not
        for row in rows(lines):
            with self.subTest(row[0]):
                self.assertEqual(len(row), 4)
                self.assertIn(row[1], WORDS)
                self.assertIn(row[2], WORDS)
                self.assertTrue(row[3])

    def test_every_row_the_acceptance_criteria_name_is_there(self):
        features = [row[0] for row in rows(table(self.text))]
        for name in REQUIRED:
            with self.subTest(name):
                self.assertEqual(len([f for f in features if f.startswith(name)]), 1, features)

    def test_the_owner_s_seven_decisions_are_recorded(self):
        decisions = section(self.text, "## The owner's decisions (2026-11-18)")
        found = re.findall(r"^- (Q\d)\. (.*)$", decisions, re.M)
        self.assertEqual([q for q, _ in found], ["Q%d" % i for i in range(1, 8)])
        for q, first_line in found:
            with self.subTest(q):
                self.assertRegex(first_line, r"\w.{20,}")    # a decision, not its bare marker


class Copies(unittest.TestCase):
    def setUp(self):
        self.canonical = CANONICAL.read_text()

    def test_each_copy_equals_the_canonical_table(self):
        for name, heading in COPIES.items():
            with self.subTest(name):
                copy = section((ROOT / name).read_text(), heading)
                self.assertEqual(differences(self.canonical, copy), [])

    def test_each_copy_links_the_canonical_text(self):
        for name, heading in COPIES.items():
            with self.subTest(name):
                self.assertIn("(docs/single-node-limits.md)", section((ROOT / name).read_text(), heading))

    def test_every_lost_or_degraded_row_is_an_accepted_limitation_citing_dx7(self):
        body = section((ROOT / "LIMITATIONS.md").read_text(), COPIES["LIMITATIONS.md"])
        entries = re.findall(r"^- \*\*(.+?)\*\* \((.+?)\): (.+)$", body, re.M)
        by_feature = {feature: (word, rest) for feature, word, rest in entries}
        for feature, one, _, _ in rows(table(self.canonical)):
            if one == "supported":
                continue
            with self.subTest(feature):
                self.assertIn(feature, by_feature)
                word, rest = by_feature[feature]
                self.assertEqual(word, one)
                self.assertTrue(rest.startswith("**accepted** (regalia-kms-dx7), because "), rest)


class MutantControls(unittest.TestCase):
    """The comparison must see one edited cell, in either copy, in any column."""

    def mutated(self, text, line, column):
        lines = text.split("\n")
        row = [i for i, l in enumerate(lines) if l.startswith("|")][line]
        cells = lines[row].split("|")
        cells[column + 1] = cells[column + 1].replace(cells[column + 1].strip(), cells[column + 1].strip() + "x")
        lines[row] = "|".join(cells)
        return "\n".join(lines)

    def test_one_edited_cell_fails_the_comparison(self):
        canonical = CANONICAL.read_text()
        for name, heading in COPIES.items():
            copy = section((ROOT / name).read_text(), heading)
            self.assertEqual(differences(canonical, copy), [])
            for line, column in ((2, 0), (5, 1), (9, 2), (12, 3)):
                with self.subTest(name=name, line=line, column=column):
                    self.assertEqual(len(differences(canonical, self.mutated(copy, line, column))), 1)

    def test_the_entry_and_decision_patterns_refuse_their_hollow_forms(self):
        entry = re.compile(r"^- \*\*(.+?)\*\* \((.+?)\): (.+)$", re.M)
        hollow = "- **Heartbeats** (degraded): **not accepted**; previously **accepted** (regalia-kms-dx7), because x."
        rest = entry.findall(hollow)[0][2]
        self.assertFalse(rest.startswith("**accepted** (regalia-kms-dx7), because "))
        self.assertNotRegex("", r"\w.{20,}")
        self.assertNotEqual(table("| a | b |\n| a | b |\n")[1], "|---|---|---|---|")

    def test_a_dropped_row_fails_the_comparison(self):
        canonical = CANONICAL.read_text()
        copy = section((ROOT / "README.md").read_text(), COPIES["README.md"])
        lines = copy.split("\n")
        lines.remove(table(copy)[-1])
        self.assertTrue(differences(canonical, "\n".join(lines)))


if __name__ == "__main__":
    unittest.main()
