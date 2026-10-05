#!/usr/bin/env python3
"""Writes tests/vectors/activation-v2.json: every call of activation.verify() that the activation tests
(tests/test_baremetal_activation.py) make, with the current manifest, the envelope and what Python decided. The Go Gate
(#432 step 3, internal/fencing) is held to the same rules: the node threshold of activation_signers, the owner counted
only through a recovery authorization while the current manifest is its quarantine manifest, the lease bound to the
authorization's node, site, registry and window and signed by the survivor alone, an older manifest's lease counted
under the current signers, and every refusal. The time window is the Gate's own check and is not in these cases.
    python3 -Es tests/vectors/make-activation-v2.py > tests/vectors/activation-v2.json
Every "key" field is written "public" (as membership-v4.json does, so a public key never reads as a credential to the
secret scanner); a reader renames every "public" back to "key". The Go test compares the outcome only: the lease
accepted (by the SHA-256 of its signed message) or a refusal.
"""
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import activation, membership  # noqa: E402

cases, seen, current_test = [], set(), ["?"]


def composed(document):
    if isinstance(document, dict):
        return {("public" if k == "key" else k): composed(v) for k, v in document.items()}
    if isinstance(document, list):
        return [composed(v) for v in document]
    return document


real = activation.verify


def recording(envelope, current):
    try:
        lease = real(envelope, current)
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    else:
        outcome = {"accepted": hashlib.sha256(activation.message(lease)).hexdigest()}
    record = {"current": composed(current), "envelope": composed(envelope), **outcome}
    key = json.dumps(record, sort_keys=True)
    if key not in seen:
        seen.add(key)
        cases.append(dict(name="%s #%d" % (current_test[0], sum(c["name"].startswith(current_test[0] + " #") for c in cases) + 1), **record))
    if "refused" in outcome:
        raise membership.Refused(outcome["refused"])
    return lease


class Naming(unittest.TextTestResult):
    def startTest(self, test):
        current_test[0] = test.id().replace("tests.test_baremetal_activation.", "")
        super().startTest(test)


activation.verify = recording
loader = unittest.defaultTestLoader
suite = unittest.TestSuite(test for group in loader.loadTestsFromName("tests.test_baremetal_activation") for test in group
                           if "Vectors" not in test.id())
result = unittest.TextTestRunner(stream=open(os.devnull, "w"), resultclass=Naming).run(suite)
if not result.wasSuccessful():
    raise SystemExit("the activation tests failed: no vector is written")
print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": cases}, indent=1, sort_keys=True))
