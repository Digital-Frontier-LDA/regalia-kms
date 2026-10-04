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

    def test_root_runs_git_only_when_the_top_and_dot_git_are_both_roots(self):
        """regalia-kms-1e: whoever owns the working tree's top can swap .git, so they never get a root git. `stat` is
        stubbed with the owners (root-owned fixtures need sudo); repo_git_owner picks the top's owner unless it is root."""
        for top, dot_git, want in (("1001", "0", "1001"), ("0", "1001", "1001"), ("1001", "1002", "1001"), ("0", "0", "0")):
            with self.subTest(top=top, dot_git=dot_git):
                script = ('. "$LIB"; stat(){ case "${@: -1}" in "$REPO") echo "$TOP";; "$REPO/.git") echo "$DOTGIT";; esac; }; '
                          'repo_git_owner %u')
                done = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                      env={"PATH": "/usr/bin:/bin", "LIB": LIB, "REPO": "/r", "TOP": top, "DOTGIT": dot_git})
                self.assertEqual(done.stdout.strip(), want, done.stderr)

    def test_a_root_read_needs_root_owned_unwritable_ancestors(self):
        """#390: before git runs as root, every directory from / to the checkout, and .git, is root's and not group or
        other writable, a sticky directory excepted. `stat` and `realpath` are stubbed (root-owned fixtures need sudo)."""
        ok = {"/": "0 755", "/srv": "0 755", "/srv/r": "0 755", "/srv/r/.git": "0 755"}
        cases = (("all root's, 755", {}, {}, True, None),
                 ("a user's parent", {"/srv": "1000 755"}, {}, False, "/srv is not root's"),
                 ("a group-writable top", {"/srv/r": "0 775"}, {}, False, "/srv/r is writable"),
                 ("an other-writable .git", {"/srv/r/.git": "0 757"}, {}, False, "/srv/r/.git is writable"),
                 ("a sticky /srv, like /tmp", {"/srv": "0 1777"}, {}, True, None),
                 ("a user's .git", {"/srv/r/.git": "1000 755"}, {}, False, "/srv/r/.git is not root's"),
                 # regalia-kms-1e's read of #394
                 ("a sticky other-writable .git", {"/srv/r/.git": "0 1777"}, {}, False, "/srv/r/.git is writable"),
                 ("a sticky other-writable top", {"/srv/r": "0 1777"}, {}, False, "/srv/r is writable"),
                 ("a symlinked component", {}, {"REALPATH": "/elsewhere/r"}, False, "is not its own real path"),
                 ("a gitfile or link .git", {}, {"REALDIR": "no"}, False, "is not a directory of its own"),
                 ("a group-writable .git/config", {}, {"LOOSE": "/srv/r/.git/config"}, False, "/srv/r/.git/config (in .git)"))
        for name, change, extra, safe, why in cases:
            with self.subTest(name):
                table = dict(ok, **change)
                stubs = " ".join('"%s") echo "%s";;' % (k, v) for k, v in table.items())
                script = ('. "$LIB"; realpath(){ echo "${REALPATH:-/srv/r}"; }; _rg_owner_mode(){ case "$1" in %s esac; }; '
                          '_rg_is_real_dir(){ [ "${REALDIR:-yes}" = yes ]; }; _rg_loose_inside(){ echo "${LOOSE:-}"; }; '
                          'repo_git_root_safe' % stubs)
                done = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                      env=dict({"PATH": "/usr/bin:/bin", "LIB": LIB, "REPO": "/srv/r"}, **extra))
                self.assertEqual(done.returncode == 0, safe, done.stderr)
                if why:
                    self.assertIn(why, done.stderr)
                    self.assertIn("(#390)", done.stderr)

    def test_the_real_filesystem_questions(self):
        """The three helpers on real files: a real directory (not a link or a gitfile), and anything in .git that is not
        root's (here: everything, owned by this test's user) reported."""
        os.symlink(os.path.join(self.repo, ".git"), os.path.join(self.d, "linked"))
        with open(os.path.join(self.d, "gitfile"), "w") as f:
            f.write("gitdir: /elsewhere\n")
        script = ('. "$LIB"; _rg_is_real_dir "$REPO/.git" && echo real; _rg_is_real_dir "$D/linked" || echo link; '
                  '_rg_is_real_dir "$D/gitfile" || echo gitfile; [ -n "$(_rg_loose_inside "$REPO/.git")" ] && echo loose; '
                  '_rg_owner_mode "$REPO"')
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "LIB": LIB, "REPO": self.repo, "D": self.d})
        lines = done.stdout.split()
        self.assertEqual(lines[:4], ["real", "link", "gitfile", "loose"], done.stderr)
        self.assertEqual(lines[4], str(os.getuid()))

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
