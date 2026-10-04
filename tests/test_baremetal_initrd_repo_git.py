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
        self.assertIn("sets filter.evil.clean, which a clone does not", err)
        self.assertFalse(os.path.exists(self.marker), "the planted filter ran")

    def test_anything_a_clone_does_not_write_is_refused(self):
        for key, value in (("core.fsmonitor", "true"), ("core.hooksPath", "/tmp"), ("core.sshCommand", "true"),
                           ("diff.x.textconv", "cat"), ("include.path", "/dev/null"), ("alias.st", "!true"),
                           ("core.pager", "cat"), ("credential.helper", "store"), ("gpg.program", "true"),
                           ("branch.main.description", "harmless, but not a clone's")):
            with self.subTest(key=key):
                self.setUp()
                self.config(key, value)
                code, err = self.check()
                self.assertEqual(code, 3, err)
                self.assertIn(key.lower() if "." not in key[key.index(".") + 1:] else key.split(".")[0], err.lower())

    def test_a_worktree_scope_plant_is_refused_and_never_runs(self):
        """regalia-kms-1e's reproduction on #384: extensions.worktreeConfig, then a filter and an attributes file in the
        WORKTREE scope (.git/config.worktree), outside the tree; a stale stat makes status run the filter."""
        attributes = os.path.join(self.d, "attr")
        with open(attributes, "w") as f:
            f.write("*.txt filter=evil\n")
        self.config("extensions.worktreeConfig", "true")
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        for key, value in (("filter.evil.clean", "touch %s; cat" % self.marker), ("core.attributesFile", attributes)):
            subprocess.run(["git", "-C", self.repo, "config", "--worktree", key, value], check=True, capture_output=True, env=env)
        os.utime(os.path.join(self.repo, "file.txt"), (978307200, 978307200))
        code, err = self.check()
        self.assertEqual(code, 3, err)
        self.assertIn("core.attributesfile", err)
        self.assertIn("filter.evil.clean", err)
        self.assertFalse(os.path.exists(self.marker), "the planted worktree-scope filter ran")

    def test_core_worktree_is_refused(self):
        """It would point the clean-tree check at another directory than the one the build reads."""
        self.config("core.worktree", self.d)
        code, err = self.check()
        self.assertEqual(code, 3, err)
        self.assertIn("core.worktree", err)

    def test_an_include_is_followed(self):
        inc = os.path.join(self.d, "more.cfg")
        with open(inc, "w") as f:
            f.write("[core]\n\tpager = cat\n")
        self.config("include.path", inc)
        code, err = self.check()
        self.assertEqual(code, 3, err)
        self.assertIn("core.pager", err)

    def test_what_a_clone_writes_is_read(self):
        for key, value in (("user.name", "x"), ("gc.auto", "0"), ("remote.origin.url", "https://example.invalid/r.git"),
                           ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"), ("branch.main.remote", "origin")):
            self.config(key, value)
        with open(os.path.join(self.repo, ".gitattributes"), "w") as f:
            f.write("*.sh text eol=lf\n*.txt filter=undefined\n")       # an attribute names no command without a driver
        code, err = self.check()
        self.assertEqual(code, 0, err)

    def test_the_allowlist_is_uki_pys(self):
        """The builder and the signer refuse the same configurations (#374's CLONE_CONFIG, once it lands)."""
        import re
        import sys
        sys.path.insert(0, os.path.join(HERE, ".."))
        from deploy.baremetal import uki
        if not hasattr(uki, "CLONE_CONFIG"):
            self.skipTest("uki.CLONE_CONFIG is #374's, not on this branch yet")
        with open(LIB) as f:
            shell = re.search(r"^REPO_GIT_ALLOWED='([^']*)'$", f.read(), re.M).group(1)
        self.assertEqual(shell.replace("[^[:space:]]+", "X"), uki.CLONE_CONFIG.pattern.replace("[^\\0\\n]+", "X"))


if __name__ == "__main__":
    unittest.main()
