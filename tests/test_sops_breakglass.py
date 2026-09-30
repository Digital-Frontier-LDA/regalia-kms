"""tools/sops_breakglass.py against real sops and age: the two-stage breakglass swap.

Stage 1 (add) must leave every file openable by the new key and the old one; stage 2 (remove) must
leave it openable by the new key only, refuse to run while any file lacks the new key, and never
write a .sops.yaml it cannot parse back. The recipient forms are the three the SOPS inventory found
in the estate: a folded multi-line string, a list under key_groups, and a flat comma-separated value.

Needs sops >= 3.13 and age >= 1.3 on PATH (CI installs both, hash-pinned); skipped otherwise.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "sops_breakglass.py"


def have_tools():
    if not (shutil.which("sops") and shutil.which("age-keygen")):
        return False
    r = subprocess.run(["age-keygen", "-pq"], capture_output=True, text=True)
    return r.returncode == 0 and "AGE-SECRET-KEY-PQ-1" in r.stdout


@unittest.skipUnless(have_tools(), "needs sops >= 3.13 and age >= 1.3 on PATH")
class BreakglassSwap(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.run_in("git", "init", "-q", ".")
        self.run_in("git", "config", "user.email", "t@example.invalid")
        self.run_in("git", "config", "user.name", "t")
        self.ci, self.ci_id = self.keygen()
        self.old, self.old_id = self.keygen()
        self.new, self.new_id = self.keygen(pq=True)
        (self.dir / ".sops.yaml").write_text(
            "# estate config: comments must survive\n"
            "creation_rules:\n"
            "  - path_regex: ^a/.*\n"
            "    age: >-\n"
            f"      {self.ci},\n"
            f"      {self.old}\n"
            "  - path_regex: ^b/.*\n"
            "    key_groups:\n"
            "      - age:\n"
            f"          - {self.ci}\n"
            f"          - {self.old}\n"
            "  - path_regex: ^c/.*\n"
            f"    age: {self.ci},{self.old}\n")
        for d in "abc":
            (self.dir / d).mkdir()
        (self.dir / "a" / "s.yaml").write_text("db_password: hunter2\n")
        (self.dir / "b" / "s.json").write_text('{"token": "abc"}')
        (self.dir / "c" / "s.env").write_text("API_KEY=xyz\n")
        self.sops(self.ci_id, "-e", "-i", "a/s.yaml")
        self.sops(self.ci_id, "-e", "-i", "b/s.json")
        self.sops(self.ci_id, "-e", "-i", "--input-type", "dotenv", "--output-type", "dotenv", "c/s.env")
        self.run_in("git", "add", "-A")
        self.run_in("git", "commit", "-qm", "init")

    def run_in(self, *cmd, env=None, check=True):
        return subprocess.run(cmd, cwd=self.dir, capture_output=True, text=True, env=env, check=check)

    def keygen(self, pq=False):
        out = subprocess.run(["age-keygen"] + (["-pq"] if pq else []), capture_output=True, text=True, check=True).stdout
        identity = next(line for line in out.splitlines() if line.startswith("AGE-SECRET-KEY"))
        recipient = subprocess.run(["age-keygen", "-y"], input=identity + "\n", capture_output=True, text=True, check=True).stdout.strip()
        return recipient, identity

    def sops(self, identity, *args, check=True):
        env = dict(os.environ, SOPS_AGE_KEY=identity)
        return self.run_in("sops", *args, env=env, check=check)

    def tool(self, *args):
        env = dict(os.environ, SOPS_AGE_KEY=self.ci_id)
        r = subprocess.run([sys.executable, str(TOOL), *args], cwd=self.dir, capture_output=True, text=True, env=env)
        return r.returncode, r.stdout + r.stderr

    def opens(self, identity):
        """Which of the three files this identity can decrypt."""
        ok = []
        for f, extra in (("a/s.yaml", []), ("b/s.json", []), ("c/s.env", ["--input-type", "dotenv", "--output-type", "dotenv"])):
            if self.sops(identity, "-d", *extra, f, check=False).returncode == 0:
                ok.append(f)
        return ok

    def test_add_then_remove(self):
        everything = ["a/s.yaml", "b/s.json", "c/s.env"]
        rc, out = self.tool("add", "--old", self.old, "--new", self.new)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.opens(self.new_id), everything, "after add, the new key opens every file")
        self.assertEqual(self.opens(self.old_id), everything, "after add, the old key still opens every file")
        self.assertIn("# estate config: comments must survive", (self.dir / ".sops.yaml").read_text())
        rc, out = self.tool("check", "--require", self.new)
        self.assertEqual(rc, 0, out)
        self.run_in("git", "add", "-A")
        self.run_in("git", "commit", "-qm", "stage 1")

        rc, out = self.tool("remove", "--old", self.old, "--new", self.new)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.opens(self.new_id), everything, "after remove, the new key opens every file")
        self.assertEqual(self.opens(self.old_id), [], "after remove, the old key opens nothing")
        self.assertNotIn(self.old, (self.dir / ".sops.yaml").read_text())
        rc, out = self.tool("check", "--require", self.new, "--forbid", self.old)
        self.assertEqual(rc, 0, out)
        self.assertIn("CHECK OK", out)

    def test_add_is_idempotent(self):
        self.assertEqual(self.tool("add", "--old", self.old, "--new", self.new)[0], 0)
        config = (self.dir / ".sops.yaml").read_text()
        self.assertEqual(self.tool("add", "--old", self.old, "--new", self.new)[0], 0)
        self.assertEqual((self.dir / ".sops.yaml").read_text(), config, "a second add changed .sops.yaml")

    def test_remove_before_add_is_refused_and_changes_nothing(self):
        before = {p: (self.dir / p).read_text() for p in (".sops.yaml", "a/s.yaml", "b/s.json", "c/s.env")}
        rc, out = self.tool("remove", "--old", self.old, "--new", self.new)
        self.assertEqual(rc, 1, out)
        self.assertIn("does not carry the new breakglass yet", out)
        self.assertEqual({p: (self.dir / p).read_text() for p in before}, before, "a refused remove changed files")
        self.assertEqual(self.opens(self.old_id), ["a/s.yaml", "b/s.json", "c/s.env"])

    def test_check_names_the_files_without_the_key(self):
        rc, out = self.tool("check", "--require", self.new)
        self.assertEqual(rc, 1)
        for f in ("a/s.yaml", "b/s.json", "c/s.env"):
            self.assertIn("%s: the breakglass recipient is missing" % f, out)
        self.assertIn("rule 0 does not name the breakglass recipient", out)

    def test_bad_recipients_are_refused(self):
        rc, _ = self.tool("add", "--old", self.old, "--new", "AGE-SECRET-KEY-PQ-1NOTARECIPIENT")
        self.assertEqual(rc, 2)
        rc, _ = self.tool("add", "--old", self.old, "--new", self.old)
        self.assertEqual(rc, 2)
        rc, _ = self.tool("add", "--old", self.old, "--new", "age1pq1 injected; rm -rf /")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
