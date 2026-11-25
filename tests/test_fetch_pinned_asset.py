"""regalia-kms-dq7: CI's pinned tool downloads survive a github.com release-asset outage.

CI fetched promtool, etcd and sops from github.com/<o>/<r>/releases/download at job time, and an
intermittent 504 on that host turned main red with no code failure. The pattern adopted from
openmix-1q7te (Flynn#2129): each attempt round tries the release URL, then the REST asset API
(api.github.com/repos/<o>/<r>/releases/assets/<pinned id>, Accept: application/octet-stream, the
job's token), with bounded backoff. The sha256 pin is unchanged and a mismatch is never retried.
"""
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "fetch-pinned-asset.sh"
WORKFLOWS = ROOT / ".github" / "workflows"

PAYLOAD = b"pinned tool bytes\n"
PAYLOAD_SHA = "c4a1e1e1d5d0c8c0e1d1e0d8f2b9c2b6d1a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9"  # replaced in setUp

FAKE_CURL = r"""#!/usr/bin/env bash
# Records each call; the answer per host comes from FAKE_BROWSER / FAKE_API:
# ok | wrong (200, other bytes) | 504 | 429 | 404 | 403 | timeout (no HTTP answer).
out=""; url=""; accept=""; auth=""; wout=""
while [ $# -gt 0 ]; do
  case $1 in
    --output|-o) out=$2; shift 2;;
    --write-out|-w) wout=$2; shift 2;;
    --header|-H) case $2 in Accept:*) accept=$2;; Authorization:*) auth=present;; esac; shift 2;;
    --config|-K) grep -q '^header = "Authorization: ' "$2" && auth=present; shift 2;;
    --max-time|--connect-timeout|--proto) shift 2;;
    https://*) url=$1; shift;;
    *) shift;;
  esac
done
case $url in https://api.github.com/*) mode=$FAKE_API; host=api;; *) mode=$FAKE_BROWSER; host=browser;; esac
echo "$host accept=${accept:-none} auth=${auth:-none}" >> "$FAKE_LOG"
code() { [ -n "$wout" ] && printf '%s' "$1"; }
case $mode in
  ok) printf 'pinned tool bytes\n' > "$out"; code 200; exit 0;;
  wrong) printf 'tampered\n' > "$out"; code 200; exit 0;;
  timeout) echo "curl: (28) Operation timed out" >&2; code 000; exit 28;;
  *) printf 'error body' > "$out"; code "$mode"; exit 0;;
esac
"""


class FetchPinnedAsset(unittest.TestCase):
    def setUp(self):
        import hashlib
        global PAYLOAD_SHA
        PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
        self.dir = Path(tempfile.mkdtemp())
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        curl = bin_dir / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
        (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "sleep").chmod(0o755)
        self.log = self.dir / "calls.log"
        self.env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_LOG": str(self.log),
                    "GH_TOKEN": "test-token-not-a-secret", "DEADLINE": "5"}

    def run_fetch(self, browser, api, sha=None):
        out = self.dir / "tool"
        env = {**self.env, "FAKE_BROWSER": browser, "FAKE_API": api}
        done = subprocess.run(
            ["bash", str(SCRIPT), "https://github.com/o/r/releases/download/v1/tool",
             "https://api.github.com/repos/o/r/releases/assets/123", sha or PAYLOAD_SHA, str(out)],
            env=env, capture_output=True, text=True)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return done, out, calls

    def test_the_release_url_serves_it(self):
        done, out, calls = self.run_fetch("ok", "504")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(out.read_bytes(), PAYLOAD)
        self.assertEqual(calls, ["browser accept=none auth=none"])

    def test_a_release_host_outage_falls_back_to_the_asset_api(self):
        done, out, calls = self.run_fetch("504", "ok")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(out.read_bytes(), PAYLOAD)
        self.assertEqual(calls[0], "browser accept=none auth=none")
        self.assertEqual(calls[1], "api accept=Accept: application/octet-stream auth=present")
        self.assertNotIn("test-token-not-a-secret", done.stdout + done.stderr)

    def test_a_full_outage_fails_after_bounded_rounds(self):
        done, out, calls = self.run_fetch("504", "timeout")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(out.exists())
        self.assertGreaterEqual(len(calls), 2)
        self.assertIn("within 5s", done.stderr)

    def test_a_checksum_mismatch_is_refused_and_never_retried(self):
        done, out, calls = self.run_fetch("wrong", "ok")
        self.assertEqual(done.returncode, 3)
        self.assertFalse(out.exists())
        self.assertEqual(len(calls), 1, calls)
        self.assertIn("sha256", done.stderr.lower())

    def test_a_rate_limit_or_timeout_on_the_release_url_falls_back(self):
        for mode in ("429", "timeout"):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                done, out, calls = self.run_fetch(mode, "ok")
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual([c.split()[0] for c in calls], ["browser", "api"])

    def test_a_4xx_on_the_release_url_is_fatal_with_no_fallback(self):
        # PR #784 GA review 6053675011 B1/B2: a 404 is a broken pin and a 403 a refusal, not an outage.
        for mode in ("404", "403"):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                done, out, calls = self.run_fetch(mode, "ok")
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertFalse(out.exists())
                self.assertFalse(Path(str(out) + ".part").exists())
                self.assertEqual(calls, ["browser accept=none auth=none"])
                self.assertIn(f"HTTP {mode}", done.stderr)

    def test_a_4xx_on_the_asset_api_is_fatal_and_not_retried(self):
        for mode in ("404", "403"):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                done, out, calls = self.run_fetch("504", mode)
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertEqual([c.split()[0] for c in calls], ["browser", "api"])

    def test_a_checksum_mismatch_on_the_fallback_is_refused_and_never_retried(self):
        done, out, calls = self.run_fetch("504", "wrong")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.assertFalse(out.exists())
        self.assertEqual([c.split()[0] for c in calls], ["browser", "api"])

    def test_a_rest_url_of_another_repository_is_refused(self):
        out = self.dir / "tool"
        done = subprocess.run(
            ["bash", str(SCRIPT), "https://github.com/o/r/releases/download/v1/tool",
             "https://api.github.com/repos/evil/r/releases/assets/123", PAYLOAD_SHA, str(out)],
            env={**self.env, "FAKE_BROWSER": "ok", "FAKE_API": "ok"}, capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertFalse(self.log.exists())

    def test_a_malformed_pin_is_refused_before_any_download(self):
        done, out, calls = self.run_fetch("ok", "ok", sha="abc")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(calls, [])


class WorkflowsUseTheFallback(unittest.TestCase):
    def test_no_workflow_curls_a_release_asset_directly(self):
        bare = []
        for path in sorted(WORKFLOWS.glob("*.y*ml")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if "/releases/download/" in line and "fetch-pinned-asset.sh" not in line:
                    prev = path.read_text().splitlines()[max(0, number - 6):number]
                    if not any("fetch-pinned-asset.sh" in p for p in prev):
                        bare.append(f"{path.name}:{number}")
        self.assertEqual(bare, [], "release assets fetched without the asset-API fallback")

    def test_each_pinned_asset_names_its_rest_asset_id(self):
        text = (WORKFLOWS / "ci.yml").read_text()
        calls = re.findall(r"fetch-pinned-asset\.sh(?:[^\n]*\n){4}", text)  # the call and its three continuation lines
        self.assertGreaterEqual(len(calls), 3)
        for call in calls:
            self.assertRegex(call, r"https://api\.github\.com/repos/[^/\s]+/[^/\s]+/releases/assets/\d+")


if __name__ == "__main__":
    unittest.main()
