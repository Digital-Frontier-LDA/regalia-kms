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
# Records each call; the behaviour per host comes from FAKE_BROWSER / FAKE_API (ok|fail|wrong).
out=""; url=""; accept=""; auth=""
while [ $# -gt 0 ]; do
  case $1 in
    --output|-o) out=$2; shift 2;;
    --header|-H) case $2 in Accept:*) accept=$2;; Authorization:*) auth=present;; esac; shift 2;;
    --config|-K) grep -q '^header = "Authorization: ' "$2" && auth=present; shift 2;;
    --max-time|--connect-timeout|--proto|--retry|--retry-delay|--tlsv1.2) case $1 in --tlsv1.2) shift;; *) shift 2;; esac;;
    https://*) url=$1; shift;;
    *) shift;;
  esac
done
case $url in https://api.github.com/*) mode=$FAKE_API; host=api;; *) mode=$FAKE_BROWSER; host=browser;; esac
echo "$host accept=${accept:-none} auth=${auth:-none}" >> "$FAKE_LOG"
case $mode in
  ok) printf 'pinned tool bytes\n' > "$out"; exit 0;;
  wrong) printf 'tampered\n' > "$out"; exit 0;;
  *) echo "curl: (22) The requested URL returned error: 504" >&2; exit 22;;
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
                    "GH_TOKEN": "test-token-not-a-secret"}

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
        done, out, calls = self.run_fetch("ok", "fail")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(out.read_bytes(), PAYLOAD)
        self.assertEqual(calls, ["browser accept=none auth=none"])

    def test_a_release_host_outage_falls_back_to_the_asset_api(self):
        done, out, calls = self.run_fetch("fail", "ok")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(out.read_bytes(), PAYLOAD)
        self.assertEqual(calls[0], "browser accept=none auth=none")
        self.assertEqual(calls[1], "api accept=Accept: application/octet-stream auth=present")
        self.assertNotIn("test-token-not-a-secret", done.stdout + done.stderr)

    def test_a_full_outage_fails_after_bounded_rounds(self):
        done, out, calls = self.run_fetch("fail", "fail")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(out.exists())
        self.assertGreaterEqual(len(calls), 4)
        self.assertLessEqual(len(calls), 10)

    def test_a_checksum_mismatch_is_refused_and_never_retried(self):
        done, out, calls = self.run_fetch("wrong", "ok")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(out.exists())
        self.assertEqual(len(calls), 1, calls)
        self.assertIn("sha256", done.stderr.lower())

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
        calls = re.findall(r"fetch-pinned-asset\.sh[^\n]*(?:\\\n[^\n]*){0,4}", text)
        self.assertGreaterEqual(len(calls), 3)
        for call in calls:
            self.assertRegex(call, r"https://api\.github\.com/repos/[^/\s]+/[^/\s]+/releases/assets/\d+")


if __name__ == "__main__":
    unittest.main()
