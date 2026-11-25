"""tests/requirements-unit.txt (regalia-kms-kow): the unit tests' hash-locked lock, from which heavy's sanctioned venv is
built. Standard library only, so it runs before any of those packages exist. It holds the lock installable under
--require-hashes (every requirement pinned with == and hashed, cffi and pycparser present for cryptography), and in step
with tools/bench/requirements.txt: a package both pin has one version, and every bench hash for it is here too."""
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "tests" / "requirements-unit.txt"
BENCH = ROOT / "tools" / "bench" / "requirements.txt"


def requirements(path):
    """{name: (version, [sha256 hashes])}, from a pip requirements file with backslash continuations. A requirement that
    is not `name==version` maps to version None, which the tests refuse."""
    text = re.sub(r"\\\n", " ", path.read_text())
    found = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        spec, *rest = line.split()
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", spec)
        name = re.sub(r"[-_.]+", "-", (m.group(1) if m else re.split(r"[<>=!~\[ ;]", spec)[0])).lower()
        found[name] = (m.group(2) if m else None, re.findall(r"--hash=sha256:([0-9a-f]{64})\b", " ".join(rest)))
    return found


class UnitLock(unittest.TestCase):
    def setUp(self):
        self.unit = requirements(UNIT)
        self.bench = requirements(BENCH)

    def test_every_requirement_is_pinned_and_hashed(self):
        self.assertGreater(len(self.unit), 0)
        for name, (version, hashes) in self.unit.items():
            with self.subTest(package=name):
                self.assertIsNotNone(version, "not pinned with ==")
                self.assertTrue(hashes, "no sha256 hash")
                self.assertEqual(len(hashes), len(set(hashes)), "a hash is listed twice")

    def test_it_holds_what_the_unit_tests_import(self):
        """PyYAML is CI's (Ubuntu 26.04's python3-yaml); cryptography needs cffi and pycparser at RUNTIME, and
        --require-hashes refuses an unpinned transitive requirement."""
        self.assertEqual(self.unit["pyyaml"][0], "6.0.3")
        for name in ("cryptography", "cffi", "pycparser"):
            self.assertIn(name, self.unit)

    def test_it_is_in_step_with_the_bench_lock(self):
        shared = sorted(set(self.unit) & set(self.bench))
        self.assertEqual(shared, ["cffi", "cryptography", "pycparser"])
        for name in shared:
            with self.subTest(package=name):
                self.assertEqual(self.unit[name][0], self.bench[name][0])
                self.assertEqual(set(self.bench[name][1]) - set(self.unit[name][1]), set(),
                                 "a bench hash for this version is missing here")

    def test_the_header_cites_where_pyyaml_s_version_comes_from(self):
        header = UNIT.read_text().split("\npyyaml==", 1)[0]
        self.assertIn("python3-yaml 6.0.3-1build1", header)
        self.assertIn("packages.ubuntu.com/resolute/python3-yaml", header)


class TheParserRefusesWhatPipWould(unittest.TestCase):
    """The checks above are only as good as the parser: an unpinned or unhashed line must read as such."""

    def parse(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            path.write_text(text)
            return requirements(path)

    def test_unpinned_and_unhashed_lines_are_seen(self):
        found = self.parse("pyyaml>=6 \\\n    --hash=sha256:%s\ncffi==2.1.1\n# a==1\n" % ("a" * 64))
        self.assertEqual(found, {"pyyaml": (None, ["a" * 64]), "cffi": ("2.1.1", [])})

    def test_names_are_normalised(self):
        self.assertEqual(list(self.parse("PyYAML==6.0.3 --hash=sha256:%s\n" % ("b" * 64))), ["pyyaml"])


if __name__ == "__main__":
    unittest.main()
