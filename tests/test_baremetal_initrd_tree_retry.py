"""deploy/baremetal/initrd/tree-retry.sh (#503): build-initrd.sh and build-rootfs.sh build their trees through
retry_tree, which tries mmdebstrap again into a new tree when, and only when, apt failed to fetch.

A stand-in mmdebstrap (a script given the tree's target) answers as the real one does: run 37395663372's TLS reset, or
another failure, or a tree. It records each attempt, and whether the target still held the previous attempt's files
when it started, which a retry must never build on."""
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "deploy", "baremetal", "initrd", "tree-retry.sh")
RESET = ("E: Failed to fetch https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/s/systemd/"
         "libudev1_257.13-1%7edeb13u1_amd64.deb  OpenSSL system call error: error:00000000:lib(0)::reason(0) - openssl "
         "(104: Connection reset by peer) [IP: 146.75.38.132 443]\nE: Unable to fetch some archives, maybe run apt-get "
         "update or try with --fix-missing?\nE: mmdebstrap failed to run")
URL = ("https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/s/systemd/"
       "libudev1_257.13-1%7edeb13u1_amd64.deb")

STAND_IN = r'''#!/bin/bash
# the stand-in mmdebstrap: $1 the target; answers $ANSWERS' next line (ok, reset, archives, other)
target="$1"
n=$(( $(wc -l < "$LEDGER") + 1 ))
leftover=no; [ -e "$target/half-fetched" ] && leftover=yes
echo "attempt $n leftover=$leftover" >> "$LEDGER"
mkdir -p "$target" && touch "$target/half-fetched"
answer="$(sed -n "${n}p" "$ANSWERS")"
case "$answer" in
  ok) touch "$target/tree-done"; echo "I: success"; exit 0 ;;
  reset) printf '%s\n' "$RESET" >&2; exit 1 ;;
  archives) echo "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?" >&2; exit 1 ;;
  *) echo "E: Package 'no-such-package' has no installation candidate" >&2; exit 1 ;;
esac
'''


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class RetryTree(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.stand_in = os.path.join(self.d, "mmdebstrap")
        with open(self.stand_in, "w") as f:
            f.write(STAND_IN)
        os.chmod(self.stand_in, 0o755)
        self.ledger, self.answers = os.path.join(self.d, "ledger"), os.path.join(self.d, "answers")
        open(self.ledger, "w").close()
        self.target, self.log = os.path.join(self.d, "root"), os.path.join(self.d, "mmdebstrap.log")

    def run_tree(self, answers, target=None):
        """retry_tree as build-initrd.sh calls it, under its set -euo pipefail: (exit, stderr, the attempts)."""
        with open(self.answers, "w") as f:
            f.write("\n".join(answers) + "\n")
        script = ('set -euo pipefail; . "$LIB"; retry_tree "$LOG" "$TARGET" "$STAND_IN" "$TARGET" '
                  '|| { echo "die: mmdebstrap failed" >&2; exit 2; }; echo built')
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={
            "PATH": "/usr/bin:/bin", "LIB": LIB, "LOG": self.log, "TARGET": self.target if target is None else target,
            "STAND_IN": self.stand_in, "LEDGER": self.ledger, "ANSWERS": self.answers, "RESET": RESET,
            "TREE_RETRY_WAITS": "0 0"})
        with open(self.ledger) as f:
            return done.returncode, done.stderr, f.read().splitlines()

    def test_one_tls_reset_is_tried_again_into_a_new_tree(self):
        code, err, attempts = self.run_tree(["reset", "ok"])
        self.assertEqual(code, 0, err)
        self.assertEqual(attempts, ["attempt 1 leftover=no", "attempt 2 leftover=no"])   # the failed tree was removed
        self.assertIn("retry_tree: attempt 1 failed to fetch %s; attempt 2 of 3 in 0s, into a new tree" % URL, err)
        self.assertTrue(os.path.exists(os.path.join(self.target, "tree-done")))

    def test_unable_to_fetch_alone_is_a_fetch_failure_too(self):
        """apt's summary line without a 'Failed to fetch' before it: retried, and the message says no URL was named."""
        code, err, attempts = self.run_tree(["archives", "ok"])
        self.assertEqual((code, len(attempts)), (0, 2), err)
        self.assertIn("attempt 1 failed to fetch an archive;", err)

    def test_any_other_failure_is_refused_at_once(self):
        code, err, attempts = self.run_tree(["other", "ok"])
        self.assertEqual(code, 2, err)
        self.assertIn("die: mmdebstrap failed", err)
        self.assertEqual(attempts, ["attempt 1 leftover=no"])                   # never tried again
        self.assertNotIn("retry_tree:", err)
        with open(self.log) as f:
            self.assertIn("has no installation candidate", f.read())          # the caller's tail shows the real error

    def test_three_fetch_failures_end_the_build(self):
        code, err, attempts = self.run_tree(["reset", "reset", "reset", "ok"])
        self.assertEqual(code, 2, err)
        self.assertEqual(len(attempts), 3)                                       # bounded: never a fourth
        self.assertEqual(err.count("retry_tree: attempt"), 2)

    def test_a_target_that_is_not_an_absolute_path_other_than_root_is_refused_before_anything_runs(self):
        for target in ("", "/", "relative/root"):
            with self.subTest(target=target):
                open(self.ledger, "w").close()
                code, err, attempts = self.run_tree(["ok"], target=target)
                self.assertEqual(code, 2, err)
                self.assertIn("the tree's target must be an absolute path other than /", err)
                self.assertEqual(attempts, [])


if __name__ == "__main__":
    unittest.main()
