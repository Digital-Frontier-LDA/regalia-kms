"""No tracked file carries an unresolved merge-conflict marker.

Nothing in this repository detected one. #257 was resolved against #241 and the full 257-test
contract suite passed with markers sitting in `kms/TESTING.md` -- nineteen files reference that
document and every one of them reads it for the section numbers it cites, so none reads it as a
document.

In Go and Python a marker is a syntax error and the build catches it. The exposure is everywhere
else, and this repository is mostly everywhere else:

  * the operator and incident runbooks render as plausible text with a duplicated procedure and
    no error, read under deadline by the person least able to notice;
  * a conflicted `.github/workflows/*.yml` fails to parse, so GitHub silently stops running that
    workflow -- a check that DISAPPEARS looks exactly like a check that passes;
  * a conflicted `.gitleaksignore` changes what the secret scan suppresses.

The usual argument against bothering is that whoever resolves the conflict will notice. That holds
for a person at a terminal. It does not hold here: several agents resolve conflicts in worktrees
they do not re-read, and the failure is silent by construction.

WHICH DIRECTIONS THIS COVERS, stated because an unstated half-check reads as a whole one (#256):

  COVERED      `<<<<<<<` and `>>>>>>>` at the start of a line -- the two markers git writes that
               have no other meaning in any format this repository stores.
  NOT COVERED  `=======` alone. Seven equals signs on their own line are also a legitimate
               Markdown setext heading underline, and this repository is full of Markdown. A rule
               that flagged it would report real headings, be silenced within a day, and take the
               two useful markers with it. Every genuine conflict git writes contains BOTH an
               opening and a closing marker, so nothing real is missed by leaving the separator
               alone -- only a hand-edited half-conflict, which is not the failure mode this
               exists for.

WHY IT IS ANCHORED TO THE START OF A LINE, and what that means for this file. Git always writes a
marker in column zero, so anchoring loses nothing real -- and it is what lets a document DISCUSS
conflict markers without flagging itself. The COVERED line above contains both markers as literal
text, indented and inside backticks; that is deliberate, it is the clearest way to say what is
covered, and it is not a finding because it is not in column zero.

An earlier version of this docstring claimed "write a literal in this file and this check fails".
That was false -- review caught it -- and it is the same defect this repository has been correcting
all week: prose asserting more than the code beside it does. The accurate statement is narrower:
write a marker AT THE START OF A LINE in any tracked file, including this one, and the check fails.

The pattern is assembled from fragments rather than written whole, and this is the THIRD rationale
that sentence has carried, because the first two were wrong and review caught both. So here is the
measured one: composing is NOT load-bearing for this check. Writing `_OPEN = "<" + ...` as a plain
literal instead leaves the marker at column 8 of an assignment, the scanner passes, and the file
does not flag itself either way -- measured, not assumed.

What composing actually buys is smaller and outside this check: a person running a repo-wide grep
for markers to find a conflict by hand does not land in this file first. That is worth the two
characters and nothing more. `kms/tools/secret_inventory.py` is the case where the same habit WAS
load-bearing -- a regexp hunting for private-key armour supplied the armour out of its own syntax
and became a gitleaks finding -- and the difference is that gitleaks is not line-anchored.

The lesson for whoever edits this next: every claim in this docstring about what the code does was
checkable by running it, and three of them were written from expectation instead. Run it.

There is deliberately NO self-exclusion. The first version had one; measured, it skipped nothing.
A skip that skips nothing is worse than no skip -- it tells the next reader the file needs excusing,
and it would swallow a real column-zero marker pasted in here later.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Assembled, never written whole: a literal here would be found by this very check.
_OPEN = "<" * 7
_CLOSE = ">" * 7
CONFLICT_MARKER = re.compile(rf"^({re.escape(_OPEN)}|{re.escape(_CLOSE)})( |$)")

# Binary and vendored trees have no business being scanned line by line.
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2", ".gz", ".zip")


def tracked_text_files():
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    for name in listing.stdout.split("\0"):
        if not name or name.endswith(SKIP_SUFFIXES):
            continue
        path = REPO_ROOT / name
        if path.is_file():
            yield name, path


def scan(lines):
    """Return the 1-indexed line numbers carrying a conflict marker."""
    return [n for n, line in enumerate(lines, 1) if CONFLICT_MARKER.match(line)]


class ConflictMarkerTests(unittest.TestCase):
    def test_the_scanner_catches_a_real_conflict(self):
        """POSITIVE CONTROL, first: a zero-finding run over the tree proves nothing until the
        instrument is shown to see a genuine marker. The fixture is what git actually writes."""
        conflicted = [
            "shared line",
            _OPEN + " HEAD",
            "ours",
            "=" * 7,
            "theirs",
            _CLOSE + " feature-branch",
        ]
        self.assertEqual([2, 6], scan(conflicted),
                         "the scanner did not flag a conflict git itself would have written, so a "
                         "clean result over the repository means nothing")

        # And it must NOT flag the separator alone, or every Markdown setext heading becomes a
        # finding and the rule is switched off within a day.
        heading = ["A Section Heading", "=" * 7, "", "body text"]
        self.assertEqual([], scan(heading),
                         "a Markdown setext underline was reported as a conflict — this rule would "
                         "be suppressed within a day and take the two useful markers with it")

    def test_the_scanner_reads_files_from_disk(self):
        """The row above proves the regexp. This proves the file plumbing, which is the half a
        pure-function test leaves untested — a scanner that reads nothing reports nothing."""
        with tempfile.TemporaryDirectory() as directory:
            planted = Path(directory) / "conflicted.md"
            planted.write_text("intro\n" + _OPEN + " HEAD\nours\n", encoding="utf-8")
            found = scan(planted.read_text(encoding="utf-8").splitlines())
            self.assertEqual([2], found, "a marker written to a real file was not found when read back")

    def test_no_tracked_file_carries_a_conflict_marker(self):
        scanned = 0
        offenders = []
        for name, path in tracked_text_files():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (UnicodeDecodeError, OSError):
                continue  # genuinely binary, or unreadable: not this check's business
            scanned += 1
            for line_number in scan(lines):
                offenders.append(f"{name}:{line_number}")

        self.assertGreater(scanned, 100,
                           f"only {scanned} files were read, so almost nothing was examined and a "
                           f"clean result would be the instrument rather than the tree")
        self.assertEqual([], offenders,
                         "unresolved merge-conflict markers are committed at: " + ", ".join(offenders))


if __name__ == "__main__":
    unittest.main()
