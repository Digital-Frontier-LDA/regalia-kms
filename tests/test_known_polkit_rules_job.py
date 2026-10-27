"""CI's job known-polkit-rules-debian13 (regalia-9qj, regalia-edr) is the only place os_probe.KNOWN_RULES_FILES are held to
Debian 13's real files: build-test's runner is Ubuntu, where the comparison skips. A unittest skip reads as success, so
this test, which runs on every runner, holds the job to the settings that make it compare: a Debian 13 image by digest,
REGALIA_EXPECT_DEBIAN13_RULES=1 on the step that runs the tests, and that step naming both of them."""
import os
import re
import unittest

import yaml

CI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows", "ci.yml")
JOB = "known-polkit-rules-debian13"
TESTS = ("tests.test_baremetal_os_probe.OnlyTheKMSReachesPcscd.test_the_known_digests_are_debian_13_s_files",
         "tests.test_baremetal_os_probe.OnlyTheKMSReachesPcscd.test_a_flipped_known_digest_fails_on_this_machine_s_files")


def job_findings(doc):
    """What keeps the job from comparing, as a list of reasons; empty when it compares."""
    job = (doc.get("jobs") or {}).get(JOB)
    if not isinstance(job, dict):
        return ["ci.yml has no job %s" % JOB]
    found = []
    image = (job.get("container") or {}).get("image", "") if isinstance(job.get("container"), dict) else job.get("container", "")
    if not re.fullmatch(r"debian:13(\.\d+)?@sha256:[0-9a-f]{64}", str(image)):
        found.append("its container is %r, not a debian:13 image by digest" % (image,))
    runners = [step for step in job.get("steps", []) if all(name in str(step.get("run", "")) for name in TESTS)]
    if not runners:
        found.append("no step runs both %s" % " and ".join(name.rsplit(".", 1)[1] for name in TESTS))
    for step in runners:
        env = dict(job.get("env") or {}, **(step.get("env") or {}))
        if str(env.get("REGALIA_EXPECT_DEBIAN13_RULES")) != "1":
            found.append("the step %r does not set REGALIA_EXPECT_DEBIAN13_RULES to 1" % step.get("name"))
        if step.get("continue-on-error") or job.get("continue-on-error"):
            found.append("the step %r may fail without failing the job" % step.get("name"))
    if job.get("if") not in (None, True):
        found.append("the job runs only if %r" % (job.get("if"),))
    return found


class KnownPolkitRulesJob(unittest.TestCase):
    def test_the_job_compares(self):
        with open(CI) as f:
            self.assertEqual(job_findings(yaml.safe_load(f)), [])

    def test_each_way_out_is_found(self):
        with open(CI) as f:
            text = f.read()
        def broken(old, new):
            self.assertEqual(text.count(old), 1, old)
            return yaml.safe_load(text.replace(old, new))
        cases = {
            "the variable dropped": (broken('REGALIA_EXPECT_DEBIAN13_RULES: "1"', 'REGALIA_EXPECT_DEBIAN13_RULES: "0"'), "does not set"),
            "an image by tag": (broken("image: debian:13.6@sha256:", "image: debian:13.6-was-sha256:"), "not a debian:13 image by digest"),
            "the control left out": (broken(" " + TESTS[1], ""), "no step runs both"),
            "the step allowed to fail": (broken("      - name: the probe's known digests are these files\n",
                                                "      - name: the probe's known digests are these files\n        continue-on-error: true\n"),
                                         "may fail without failing the job"),
            "the job made conditional": (broken("  %s:\n" % JOB, "  %s:\n    if: false\n" % JOB), "the job runs only if"),
        }
        for name, (doc, reason) in cases.items():
            with self.subTest(name):
                self.assertTrue(any(reason in finding for finding in job_findings(doc)), job_findings(doc))
        doc = yaml.safe_load(text)
        del doc["jobs"][JOB]
        self.assertEqual(job_findings(doc), ["ci.yml has no job %s" % JOB])


if __name__ == "__main__":
    unittest.main()
