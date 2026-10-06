"""deploy/baremetal/initrd/fetch-retry.sh (#503): an mmdebstrap tree build is retried only when a download from the
snapshot failed on the network, into a fresh target each time; a verification failure (a hash mismatch, a bad
signature) or any other failure is final at once. Run through bash with a stand-in mmdebstrap."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HELPER = ROOT / "deploy" / "baremetal" / "initrd" / "fetch-retry.sh"

# the evidence of #503 (run 37395663372, job 112050888583), as apt and mmdebstrap printed it
RESET = """E: Failed to fetch https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/s/systemd/libudev1_257.13-1%7edeb13u1_amd64.deb  OpenSSL system call error: error:00000000:lib(0)::reason(0) - openssl (104: Connection reset by peer) [IP: 146.75.38.132 443]
E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
E: mmdebstrap failed to run
"""
HASH = """E: Failed to fetch https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/s/systemd/libudev1_257.13-1%7edeb13u1_amd64.deb  Hash Sum mismatch
   Hashes of expected file:
E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
E: mmdebstrap failed to run
"""
SIGNATURE = """W: GPG error: https://snapshot.debian.org/archive/debian/20261003T121500Z trixie InRelease: The following signatures were invalid: BADSIG 6ED0E7B82643E131
E: The repository 'https://snapshot.debian.org/archive/debian/20261003T121500Z trixie InRelease' is not signed.
E: mmdebstrap failed to run
"""
OTHER = """E: Unable to locate package no-such-package
E: mmdebstrap failed to run
"""
TIMEOUT_WRAPPED = """E: Failed to fetch https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/c/curl/curl.deb
   Could not connect to snapshot.debian.org:443 (146.75.38.132), connection timed out
E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
E: mmdebstrap failed to run
"""
# a reset, while apt also warns that the index's signature is bad: the warning alone makes it final
RESET_AND_BADSIG = ("W: GPG error: https://snapshot.debian.org/archive/debian/20261003T121500Z trixie InRelease: "
                    "The following signatures were invalid: BADSIG 6ED0E7B82643E131\n" + RESET)
# a file the pinned snapshot does not have: no network cause, so final (a retry would fetch the same 404)
NOT_FOUND = """E: Failed to fetch https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/s/systemd/libudev1_9.deb  404  Not Found [IP: 146.75.38.132 443]
E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
E: mmdebstrap failed to run
"""
PROGRESS_SAYS_SIGNATURE = "I: verifying the Release file signature\n" + RESET


class FetchRetry(unittest.TestCase):
    def run_helper(self, outputs):
        """fetch_retry_tree over a stand-in that, on its Nth call, prints outputs[N] and fails (or succeeds on "ok"),
        writing a marker into the target to show whether it started fresh. Returns (status, calls, target fresh each
        time, stdout)."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", "--", str(d)])
        for i, text in enumerate(outputs):
            (d / ("out%d" % i)).write_text(text)
        fake = d / "fake-mmdebstrap"
        fake.write_text("""#!/bin/bash
n=$(cat "%(d)s/calls" 2>/dev/null || echo 0); echo $((n + 1)) > "%(d)s/calls"
target="%(d)s/target"
[ -e "$target/marker" ] && echo stale >> "%(d)s/stale"
mkdir -p "$target"; touch "$target/marker"
out="%(d)s/out$n"
[ "$(cat "$out")" = ok ] && exit 0
cat "$out"; exit 100
""" % {"d": d})
        fake.chmod(0o755)
        script = 'set -euo pipefail; . "%s"; FETCH_RETRY_DELAYS=(0 0); fetch_retry_tree test "%s/log" "%s/target" -- "%s"' % (HELPER, d, d, fake)
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        calls = int((d / "calls").read_text())
        return done.returncode, calls, not (d / "stale").exists(), done.stdout

    def test_the_reset_of_503_is_retried_into_a_fresh_tree_and_the_build_goes_on(self):
        status, calls, fresh, out = self.run_helper([RESET, "ok"])
        self.assertEqual((status, calls, fresh), (0, 2, True))
        self.assertIn("libudev1_257.13", out)                    # the retry names the URL
        self.assertIn("Connection reset by peer", out)

    def test_a_timeout_whose_cause_apt_wraps_onto_the_next_line_is_retried(self):
        self.assertEqual(self.run_helper([TIMEOUT_WRAPPED, "ok"])[:2], (0, 2))

    def test_at_most_three_attempts(self):
        status, calls, fresh, _ = self.run_helper([RESET, RESET, RESET, "ok"])
        self.assertEqual((status, calls, fresh), (100, 3, True))  # the command's own status, after the third

    def test_a_verification_failure_is_never_retried(self):
        for name, log in (("hash mismatch", HASH), ("bad signature", SIGNATURE), ("a reset and a mismatch", RESET + HASH),
                          ("a reset beside a bad signature", RESET_AND_BADSIG)):
            with self.subTest(name):
                self.assertEqual(self.run_helper([log, "ok"])[:2], (100, 1))

    def test_any_other_failure_is_final(self):
        self.assertEqual(self.run_helper([OTHER, "ok"])[:2], (100, 1))
        self.assertEqual(self.run_helper([NOT_FOUND, "ok"])[:2], (100, 1))  # a fetch that failed for no network cause
        self.assertEqual(self.run_helper(["", "ok"])[:2], (100, 1))        # no apt error at all
        self.assertEqual(self.run_helper([RESET.replace("E: mmdebstrap failed to run", "E: Unable to correct problems, you have held broken packages."), "ok"])[:2], (100, 1))

    def test_progress_output_does_not_decide(self):
        """Only apt's E:/W: lines are judged: a progress line that says "signature" leaves a reset retried."""
        self.assertEqual(self.run_helper([PROGRESS_SAYS_SIGNATURE, "ok"])[:2], (0, 2))

    def test_both_builders_use_it_and_hash_it(self):
        for script in ("deploy/baremetal/image/build-rootfs.sh", "deploy/baremetal/initrd/build-initrd.sh"):
            text = (ROOT / script).read_text()
            with self.subTest(script):
                self.assertIn('. "$REPO/deploy/baremetal/initrd/fetch-retry.sh"', text)
                self.assertIn("deploy/baremetal/initrd/fetch-retry.sh", text.split("REPO_FILES=(", 1)[1].split(")", 1)[0])
                self.assertIn("fetch_retry_tree ", text)
                self.assertIn('Acquire::Retries::Delay "true"', text)


if __name__ == "__main__":
    unittest.main()
