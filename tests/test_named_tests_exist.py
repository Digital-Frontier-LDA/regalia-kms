"""A comment claiming something is proved must name a test that exists.

WHY THIS IS A TEST AND NOT A CONVENTION. A docstring recording a HAZARD recruits the next reader:
it describes something that might still be true, so they check. A docstring recording a FIX
dismisses them — it says the question is settled, so they skip it. That asymmetry is not about how
well either is written; it is about what each licenses the next person to skip.

It cost a real defect. `sops_inventory.py` said trap 4 was handled by `--full-name`. It was
half-handled: the flag fixes how `ls-tree` spells paths, not which paths it lists. A reader auditing
that file reconstructed every other trap from its docstrings and skipped that one — not failing to
find it, actively not looking, because the comment said it was closed.

So a claim of completion has to be checkable, and the check is: name the test, and let this fail if
the test is not there. A fix comment naming a test that does not exist is a hazard comment wearing a
fix comment's clothes.

An abbreviated name defeats the purpose — `TestFenceRunner...` was readable and unverifiable — so
matching is exact.
"""

import ast
import functools
import re
import subprocess
import unittest
from pathlib import Path

from tests.source_lexing import go_code

ROOT = Path(__file__).resolve().parents[1]
GO_REFERENCE = re.compile(r"\b(Test[A-Z]\w+)")
# NOT followed by `.py`: naming the FILE a proof lives in is legitimate and useful, and
# `tests/test_sops_inventory_git_layer.py` is a module, not a function. The first version demanded a
# test function of that name and failed a docstring that was correct — a detector that cannot tell a
# filename from an identifier reports a true reference as a missing one, which teaches the next
# person to stop naming the file.
PY_REFERENCE = re.compile(r"\b(test_[a-z0-9_]+)(?!\.py)\b")
@functools.lru_cache(maxsize=1)
def _tracked_files():
    """Every file git tracks, which is the only set this check has an opinion about.

    This walked the FILESYSTEM until #288. That let anything sitting in the working tree fail a
    repository contract: three agent worktrees under `scratchpad/` made every bare filename in
    TESTING.md resolve four times and failed sixteen assertions, visible only to whoever was in a
    contaminated checkout and never in CI, where a fresh clone has none of it. A denylist cannot fix
    that — the next stray copy arrives under a name nobody listed. Only a tracked file can be a
    repository defect, so asking git removes the whole class by construction.

    `check=True` is load-bearing: a git failure must raise, not yield nothing. An empty enumeration
    would make every assertion below pass vacuously, which is the same silent-clean this check
    exists to prevent one level up.

    Cached because `walk` is called once per suffix per test and each call would otherwise spawn
    git again. The cache is per process and the tree does not change under a test run; returning a
    tuple keeps the cached value immutable, so no caller can shrink the enumeration for the ones
    that follow it.
    """
    completed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True)
    return tuple(ROOT / name for name in completed.stdout.split("\0") if name)


def walk(suffix):
    """Every TRACKED file with this suffix."""
    for path in _tracked_files():
        if path.name.endswith(suffix):
            yield path


# Directories the enumeration must actually reach. Anything that shrinks it — a broken `git
# ls-files`, a pathspec, a filter — shrinks BOTH the set of tests found and the set of references
# found, so every other assertion keeps passing while inspecting a fraction of the repository: the
# instrument quietly measuring less, with no failing state. This is the guard that makes an empty
# enumeration loud, and it is why `_tracked_files` raises rather than yielding nothing.
MUST_REACH = ("internal", "cmd", "tests")


class TraversalTests(unittest.TestCase):
    def test_the_walk_reaches_every_directory_this_check_is_about(self):
        reached = set()
        for suffix in (".go", ".py"):
            for path in walk(suffix):
                relative = path.relative_to(ROOT).as_posix()
                for prefix in MUST_REACH:
                    if relative.startswith(prefix + "/"):
                        reached.add(prefix)
        for prefix in MUST_REACH:
            with self.subTest(directory=prefix):
                self.assertIn(
                    prefix, reached,
                    f"the walk found nothing under {prefix}. An over-broad SKIP shrinks the tests "
                    f"found and the references found together, so every other assertion here still "
                    f"passes while checking a fraction of the repository.")


# A file reference inside TESTING.md: a path or filename in backticks.
#
# THE DEFECT IS AMBIGUITY, NOT BREVITY. `test_runbook_structure.py` names exactly one file in this
# repository and is a fine citation. `config.go` names two (kms/internal/config/ and
# kms/adapters/sops/cmd/regalia-sops-kms/), so a reader who greps it lands in the wrong one half the
# time — and the same sentence in a runbook was already wrong about which file it meant. So the rule
# is that a reference must resolve to exactly ONE tracked path, not that it must be fully qualified:
# demanding a full path everywhere would churn a citation style this file itself endorses two
# paragraphs up, to catch nothing extra.
DOC_FILE_REFERENCE = re.compile(r"`([A-Za-z0-9_./-]+\.(?:go|py|json|sh|md|yml))`")
TESTING_DOC = ROOT / "TESTING.md"


class DocumentReferenceTests(unittest.TestCase):
    """TESTING.md may only name files that exist, unambiguously.

    Same rule as the test-name check above, one level out: a claim that points somewhere has to
    point somewhere real, or the reader who follows it to check the argument is handed the
    reasoning and denied the evidence. Three bare filenames in this document resolved to nothing
    from the repository root when the check was written, two of them to more than one file.
    """

    def references(self):
        text = TESTING_DOC.read_text(encoding="utf-8")
        found = sorted(set(DOC_FILE_REFERENCE.findall(text)))
        self.assertGreater(
            len(found), 8,
            f"only {len(found)} file references parsed from {TESTING_DOC}: the citation style "
            f"changed and this check would pass by verifying almost nothing")
        return found

    # Go test names TESTING.md may MENTION without them existing. Each is a generic rather than a
    # citation, and each carries its reason — a bare skip-list is how a real stale citation hides
    # among deliberate exclusions.
    GENERIC_TEST_NAMES = {
        "TestXxx": "the Go convention placeholder, used when describing test naming in general",
        "TestMain": "Go's own entry-point hook, referred to as a language feature",
        "TestFenceRunner": "§15 quotes this ABBREVIATED name as its example of an unverifiable "
                           "reference; writing the full one would destroy the point",
    }

    def test_the_generic_exemptions_are_still_exactly_these_three(self):
        """The exemption set is this check's corpus filter, so widening it disables the check.

        Falsified and confirmed: replacing the membership test with `name.startswith("Test")`
        exempts everything, and the citation check below then passes while verifying nothing —
        §16, inside the guard I had just written for citations. Pinning the NAMES makes a widened
        exemption a visible edit, the same way DECLARED_ELEMENTS pins the runbook contracts.
        """
        self.assertEqual(
            {"TestXxx", "TestMain", "TestFenceRunner"}, set(self.GENERIC_TEST_NAMES),
            "the generic-name exemptions changed. Each is a name TESTING.md mentions rather than "
            "cites; a fourth means a real citation is being excused, so say which and why in the "
            "dict itself.")
        for name, reason in self.GENERIC_TEST_NAMES.items():
            with self.subTest(generic=name):
                self.assertGreater(len(reason), 30,
                                   f"{name} is exempted without a reason worth reading, which is "
                                   f"how a stale citation hides among deliberate exclusions")

    def test_every_go_test_named_in_testing_md_exists(self):
        """A section citing a test by name makes a checkable claim — so check it.

        It found one immediately, and that citation has since been corrected — described here in
        the past tense so this docstring does not contradict the document it checks. §12 USED TO
        cite `TestNoCarrierFieldIsWrittenAndNeverRead`; the test had been renamed to
        `TestNoListedCarrierFieldIsWrittenAndNeverRead`, inserting `Listed` as §12's OWN FIX —
        narrowing a name that claimed more than the code did — and the citation did not follow.
        The section describing the defect was carrying its artifact.

        A file reference and a test name are different claims, and only the first was checked:
        test_go_source_naming_a_test_names_one_that_exists covers .go files, not this document.
        """
        cited = set(GO_REFERENCE.findall(TESTING_DOC.read_text(encoding="utf-8")))
        self.assertGreater(len(cited), 8,
                           "too few Go test names parsed from TESTING.md: the citation style "
                           "changed and this would pass by verifying almost nothing")
        defined = set()
        for path in walk("_test.go"):
            defined |= set(re.findall(r"func (Test[A-Z]\w+)", path.read_text(encoding="utf-8")))
        self.assertGreater(len(defined), 200,
                           "almost no tests were found, so every citation would look stale and "
                           "the failure would be the instrument rather than the document")
        checked = 0
        for name in sorted(cited - set(self.GENERIC_TEST_NAMES)):
            checked += 1
            with self.subTest(test=name):
                self.assertIn(
                    name, defined,
                    f"TESTING.md cites {name}, which no test defines. Either it was renamed and "
                    f"the citation did not follow, or it never existed — and in this document the "
                    f"citation is the argument. If it is a generic rather than a citation, add it "
                    f"to GENERIC_TEST_NAMES with the reason.")
        # The names PARSED are guarded above; this guards the names actually ASSERTED. The two
        # differ by the exemption set, so a loop that iterates nothing passes every assertion in
        # it — the failure mode a count catches here precisely because the corpus is parsed
        # independently of the filter (contrast §16, where the bug shrinks both together).
        self.assertGreater(checked, 8,
                           f"only {checked} citations were checked. The exemption set has grown to "
                           f"swallow the corpus, or the loop stopped iterating it.")

    def test_every_file_named_in_testing_md_resolves_to_exactly_one_file(self):
        # ONE traversal, not six. `str.endswith` takes a tuple, so `walk` needs no change and the
        # nested comprehension that walked the tree once per suffix becomes a single pass — this
        # file already walks it twice more for the test-name checks.
        tracked = [path.relative_to(ROOT).as_posix()
                   for path in walk((".go", ".py", ".json", ".sh", ".md", ".yml"))]
        self.assertGreater(len(tracked), 100,
                           "the walk found almost no files, so every reference would look "
                           "unresolvable and the failure would be the instrument, not the document")
        for reference in self.references():
            with self.subTest(reference=reference):
                matches = [t for t in tracked if t == reference or t.endswith("/" + reference)]
                self.assertNotEqual(
                    [], matches,
                    f"TESTING.md names {reference}, which is not a file in this repository")
                self.assertEqual(
                    1, len(matches),
                    f"TESTING.md names {reference}, which matches {len(matches)} files "
                    f"({', '.join(sorted(matches))}). Qualify it with enough path to be "
                    f"unambiguous — a reader who greps a bare name lands in the wrong one.")


class NamedTestsExistTests(unittest.TestCase):
    def test_comment_only_definitions_are_not_counted(self):
        go = '/*\nfunc TestRetired(t *testing.T) {}\n*/\nfunc TestLive(t *testing.T) {}\n'
        self.assertEqual(["TestLive"], re.findall(r"^func (Test\w+)", go_code(go), re.M),
                         "a Go comment was counted as a test definition")
        python = '"""\ndef test_retired(): pass\n"""\ndef test_live(): pass\n'
        definitions = {
            node.name for node in ast.walk(ast.parse(python))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertEqual({"test_live"}, definitions,
                         "a Python docstring was counted as a test definition")

    # Go test names a Go source file may MENTION without them existing, keyed by (file, name).
    #
    # A mention is not a citation: it names a test that deliberately does not exist, to say so.
    # Keyed by file rather than by name alone, so excusing a name in the one place it is a
    # historical record does not excuse the same name as a citation anywhere else. Each entry
    # carries its reason for the reason GENERIC_TEST_NAMES does: a bare skip-list is how a real
    # stale citation hides among deliberate exclusions.
    GO_MENTIONS_NOT_CITATIONS = {
        ("internal/operations/guard_coverage_test.go", "TestPolicyStateUnavailableIsRetryable503NotDenied403"):
            "one of three names a mutation sweep suggested; the comment records that they were deliberately "
            "merged into a single table-driven test instead of written",
        ("internal/operations/guard_coverage_test.go", "TestReplayedNonceIsConflict409NotDenied403"):
            "one of three names a mutation sweep suggested; the comment records that they were deliberately "
            "merged into a single table-driven test instead of written",
        ("internal/operations/guard_coverage_test.go", "TestPolicyQuotaDenialIsResourceExhausted429AndRetryable"):
            "one of three names a mutation sweep suggested; the comment records that they were deliberately "
            "merged into a single table-driven test instead of written",
        ("internal/fencing/sweep_uncovered_test.go", "TestVerifyLeaseRejectsMalformedBase64Signature"):
            "removed as hollow in f151054 because ed25519 refuses the input downstream; the comment records "
            "why no test exists and must name the one that was deleted",
        ("internal/fencing/sweep_sole_detectors_test.go", "TestXxx"):
            "Go's placeholder test name, inside a quoted `--- FAIL:` line showing the output format",
        ("adapters/sops/cmd/regalia-sops-kms/startup_test.go",
         "TestNoRefusalLeavesASocketBehind_identity_material_that_is_missing"):
            "a quoted t.TempDir() path, which embeds the test and subtest name; the parent test exists and "
            "the path is the measurement the comment explains",
    }

    def _go_references(self):
        """Every (file, name) a tracked Go file names, test files included, and every defined test.

        TEST FILES USED TO BE SKIPPED, and they are where this repository cites tests most: falsifier
        notes, sweep ledgers, unwiredControls reasons, "pinned by" comments. Only non-test files were
        read, so a citation in a _test.go file was never checked — deleting a test that one cited left
        this rule green. Measured when the gap was found (#453): 29 names cited inside _test.go files
        resolved to no test, including a claim that two refusals were "both pinned by" a test that
        never existed, and a block describing a contract that had since been reversed.
        """
        defined, references = set(), set()
        for path in walk(".go"):
            text = path.read_text(encoding="utf-8")
            if path.name.endswith("_test.go"):
                defined |= set(re.findall(r"^func (Test\w+)", go_code(text), re.M))
            where = str(path.relative_to(ROOT))
            for name in set(GO_REFERENCE.findall(text)):
                references.add((where, name))
        self.assertTrue(defined, "no Go tests were found at all: this check is inspecting nothing")
        self.assertTrue(references, "no Go source names a test: the convention has stopped being used")
        return defined, references

    def test_go_source_naming_a_test_names_one_that_exists(self):
        defined, references = self._go_references()
        for where, name in sorted(references):
            if name in defined or (where, name) in self.GO_MENTIONS_NOT_CITATIONS:
                continue
            with self.subTest(file=where, test=name):
                self.fail(
                    f"{where} names {name}, which does not exist. Either the test was renamed and "
                    f"the claim it backed is now unproved, or the name is abbreviated or wrapped across "
                    f"a line and therefore unverifiable — both leave a comment asserting something "
                    f"nothing checks. If the name is a deliberate mention of a test that does not "
                    f"exist, add it to GO_MENTIONS_NOT_CITATIONS with its reason.")

    def test_the_go_mention_exemptions_are_exactly_these_and_each_is_still_needed(self):
        """The exemption set is this check's corpus filter, so widening it silently disables the check.

        Pinned by size and reason, as GENERIC_TEST_NAMES is. And each entry must still be doing work:
        an exempted name that now exists, or that its file no longer mentions, is an excuse for
        nothing — and a stale excuse is where the next real stale citation gets filed without anyone
        reading it.
        """
        self.assertEqual(6, len(self.GO_MENTIONS_NOT_CITATIONS),
                         "the Go mention exemptions changed. Each is a name a file MENTIONS rather than "
                         "cites; a new one means a citation is being excused, so say which and why.")
        defined, references = self._go_references()
        for (where, name), reason in self.GO_MENTIONS_NOT_CITATIONS.items():
            with self.subTest(file=where, test=name):
                self.assertGreater(len(reason), 30, f"{name} in {where} is exempted without a reason worth reading")
                self.assertNotIn(name, defined,
                                 f"{name} now exists, so exempting it in {where} excuses nothing; remove the entry")
                self.assertIn((where, name), references,
                              f"{where} no longer mentions {name}; the exemption is stale, remove it")

    def test_a_named_test_FILE_is_not_read_as_a_named_test_function(self):
        """`tests/test_x.py` names a module; `test_x` names a function.

        The detector could not tell them apart and failed a docstring that correctly pointed at the
        file its proof lives in. A check that rejects a true reference teaches people to stop making
        references, which costs more than it catches.
        """
        self.assertIsNone(
            PY_REFERENCE.search("see tests/test_sops_inventory_git_layer.py for the proof"),
            "a reference to a test FILE was read as a reference to a test function")
        found = PY_REFERENCE.search("proved by test_one_entry_per_origin_not_per_path.")
        self.assertIsNotNone(found, "the control failed: a real function reference is no longer matched")
        self.assertEqual(found.group(1), "test_one_entry_per_origin_not_per_path")

    def test_python_tools_naming_a_test_name_ones_that_exist(self):
        defined = set()
        for path in walk(".py"):
            if path.name.startswith("test_"):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                defined |= {
                    node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test_")
                }
        self.assertTrue(defined, "no Python tests were found at all: this check is inspecting nothing")
        referenced = {}
        for path in (ROOT / "tools").glob("*.py"):
            for name in set(PY_REFERENCE.findall(path.read_text(encoding="utf-8"))):
                referenced.setdefault(name, path.relative_to(ROOT))
        for name, where in sorted(referenced.items()):
            with self.subTest(test=name):
                self.assertIn(
                    name, defined,
                    f"{where} names {name}, which does not exist. A fix comment naming a missing "
                    f"test is a hazard comment wearing a fix comment's clothes.")


if __name__ == "__main__":
    unittest.main()
