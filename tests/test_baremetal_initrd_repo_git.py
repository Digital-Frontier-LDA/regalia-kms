"""deploy/baremetal/initrd/repo-git.sh (#382): build-initrd.sh, run as root, reads the checkout with git as the
checkout's owner and refuses a checkout whose own configuration could make git run a command.

These run as an ordinary user (the as-root path, setpriv to the owner, runs in CI's initrd builds, which are root):
what they show is the refusal, and that a planted clean filter never runs, since repo_git_check refuses before any
git command that would apply it."""
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "deploy", "baremetal", "initrd", "repo-git.sh")


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "git and bash are required")
class RepoGit(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.repo = os.path.join(self.d, "repo")
        os.mkdir(self.repo)
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        for argv in (["init", "-q"], ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"]):
            subprocess.run(["git", "-C", self.repo] + argv, check=True, capture_output=True, env=env)
        with open(os.path.join(self.repo, "file.txt"), "w") as f:
            f.write("data\n")
        self.marker = os.path.join(self.d, "ran")

    def config(self, key, value):
        subprocess.run(["git", "-C", self.repo, "config", "--local", key, value], check=True, capture_output=True,
                       env=dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1"))

    def check(self):
        """repo_git_check, then (as build-initrd.sh would) status: (exit, stderr)."""
        script = '. "$LIB"; repo_git_check || exit 3; repo_git status --porcelain >/dev/null'
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "LIB": LIB, "REPO": self.repo})
        return done.returncode, done.stderr

    def test_a_clean_checkout_is_read(self):
        code, err = self.check()
        self.assertEqual(code, 0, err)

    def test_a_planted_clean_filter_is_refused_and_never_runs(self):
        self.config("filter.evil.clean", "touch %s; cat" % self.marker)
        with open(os.path.join(self.repo, ".gitattributes"), "w") as f:
            f.write("*.txt filter=evil\n")
        code, err = self.check()
        self.assertEqual(code, 3, err)
        self.assertIn("could run a command (filter.evil.clean", err)
        self.assertFalse(os.path.exists(self.marker), "the planted filter ran")

    def test_each_command_bearing_key_is_refused(self):
        for key, value in (("core.fsmonitor", "true"), ("core.hooksPath", "/tmp"), ("core.sshCommand", "true"),
                           ("diff.x.textconv", "cat"), ("include.path", "/dev/null"), ("alias.st", "!true"),
                           ("core.pager", "cat"), ("core.attributesFile", "/dev/null")):
            with self.subTest(key=key):
                self.setUp()
                self.config(key, value)
                code, err = self.check()
                self.assertEqual(code, 3, err)
                self.assertIn(key.lower(), err)

    def test_a_tracked_gitattributes_naming_a_driver_is_refused(self):
        for line in ("*.txt filter=x\n", "*.txt diff=x\n", "*.bin merge=ours\n"):
            with self.subTest(line=line):
                with open(os.path.join(self.repo, ".gitattributes"), "w") as f:
                    f.write(line)
                code, err = self.check()
                self.assertEqual(code, 3, err)
                self.assertIn(".gitattributes names a filter, diff or merge driver", err)

    def test_a_harmless_gitattributes_is_read(self):
        with open(os.path.join(self.repo, ".gitattributes"), "w") as f:
            f.write("*.sh text eol=lf\n")
        code, err = self.check()
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
