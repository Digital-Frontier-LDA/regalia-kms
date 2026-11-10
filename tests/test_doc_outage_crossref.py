"""#388: the outage runbook's first step (PIN-CUSTODY.md, "The disk recovery key") leads to the re-anchor procedure,
so an operator who opens a host by hand after a total outage, and finds its anchor unusable, reaches it. The link's
file and heading anchor resolve (GitHub's slug: lower case, punctuation dropped, spaces to hyphens)."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def slug(heading):
    return re.sub(r"[^a-z0-9 _-]", "", heading.strip().lower()).replace(" ", "-")


def section(text, heading):
    start = text.index("\n" + heading + "\n")
    rest = text[start + len(heading) + 2:]
    end = re.search(r"^## ", rest, re.M)
    return rest[:end.start()] if end else rest


class OutageCrossReference(unittest.TestCase):
    def test_the_recovery_key_section_links_the_total_outage_re_anchor(self):
        body = section((ROOT / "PIN-CUSTODY.md").read_text(), "## The disk recovery key")
        links = re.findall(r"\]\((deploy/baremetal/MEMBERSHIP-RECOVERY\.md)#([a-z0-9_-]+)\)", body)
        self.assertTrue(links, "the section names no MEMBERSHIP-RECOVERY.md anchor")
        for path, anchor in links:
            with self.subTest(anchor):
                target = (ROOT / path).read_text()
                slugs = {slug(h) for h in re.findall(r"^#+ (.+)$", target, re.M)}
                self.assertIn(anchor, slugs)
        self.assertIn("in-a-total-outage-388", [a for _, a in links])

    def test_the_slug_is_github_s(self):
        self.assertEqual(slug("In a total outage (#388)"), "in-a-total-outage-388")


if __name__ == "__main__":
    unittest.main()
