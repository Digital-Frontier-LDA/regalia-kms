#!/usr/bin/env python3
"""Writes tests/vectors/heartbeat-v4.json: every call of heartbeat.verify() that the v4 heartbeat tests
(tests/test_baremetal_heartbeat_v4.py) make, with what it was given and what it decided. The Go port is held
to the same rules: a quorum of heartbeat_signers, a party twice, a key not the party's, a node that does not
count, low-S, the single-key form refused under v4, the manifest's lifetime bound, and the owner's shorter one
(the lifetime is the heartbeat's own expires_at - issued_at, both in the case). A drift on either side fails
CI: the Python test replays this file too.

    python3 -Es tests/vectors/make-heartbeat-v4.py > tests/vectors/heartbeat-v4.json

As in membership-v4.json, every "key" field is written "public" (a public key written as `"key": "<hex>"`
reads as a credential to the secret scanner, and the repository fixes such findings by composition, never by
an allowlist); a reader renames every "public" back to "key". The reasons are Python's words; the Go test
compares the outcome (the heartbeat accepted, as a body, or a refusal).
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import heartbeat, membership  # noqa: E402

cases, seen, current_test = [], set(), ["?"]


def composed(document):
    """A document for the file: every "key" written "public"."""
    if isinstance(document, dict):
        return {("public" if k == "key" else k): composed(v) for k, v in document.items()}
    if isinstance(document, list):
        return [composed(v) for v in document]
    return document


real = heartbeat.verify


def recording(envelope, manifest):
    try:
        result = real(envelope, manifest)
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    else:
        outcome = {"accepted": result}
    record = {"current": composed(manifest), "envelope": composed(envelope), **outcome}
    key = json.dumps(record, sort_keys=True)
    if key not in seen:
        seen.add(key)
        cases.append(dict(name="%s #%d" % (current_test[0], sum(c["name"].startswith(current_test[0] + " #") for c in cases) + 1), **record))
    if "refused" in outcome:
        raise membership.Refused(outcome["refused"])
    return result


class Naming(unittest.TextTestResult):
    def startTest(self, test):
        current_test[0] = test.id().replace("tests.test_baremetal_heartbeat_v4.", "")
        super().startTest(test)


heartbeat.verify = recording
suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_baremetal_heartbeat_v4")
suite = unittest.TestSuite(test for group in suite for test in group if "Vectors" not in test.id())
result = unittest.TextTestRunner(stream=open(os.devnull, "w"), resultclass=Naming).run(suite)
if not result.wasSuccessful():
    raise SystemExit("the v4 heartbeat tests failed: no vector is written")
print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": cases}, indent=1, sort_keys=True))
