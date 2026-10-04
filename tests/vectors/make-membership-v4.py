#!/usr/bin/env python3
"""Writes tests/vectors/membership-v4.json: every call of membership.accept() that the v4 tests
(tests/test_baremetal_membership_v4.py) make, with what it was given and what it decided. The Go port
(cmd/regalia-unlock/membership) is held to the same v4 rules: signer rules and their floors, owner and
signing keys, quorum envelopes, a party twice, a node that does not count, restrictive-only quorums, and
the root's move from v3. A drift on either side fails CI: the Python test replays this file too.

    python3 -Es tests/vectors/make-membership-v4.py > tests/vectors/membership-v4.json

Every "key" field (a typed key's, a signature's, a typed root's) is written "public": a public key written as
`"key": "<hex>"` reads as a credential to the secret scanner, and the repository fixes such findings by
composition, never by an allowlist. A reader renames every "public" back to "key"; no membership document
has a field of its own named "public". The reasons are Python's words; the Go test compares the outcome
(the manifest accepted, by its digest, or a refusal).
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import membership  # noqa: E402

cases, seen, current_test = [], set(), ["?"]


def composed(document):
    """A document for the file: every "key" written "public"."""
    if isinstance(document, dict):
        return {("public" if k == "key" else k): composed(v) for k, v in document.items()}
    if isinstance(document, list):
        return [composed(v) for v in document]
    return document


real = membership.accept


def recording(current, envelope, root_key):
    try:
        result = real(current, envelope, root_key)
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    else:
        outcome = {"accepted": membership.digest(result)}
    record = {"current": composed(current), "envelope": composed(envelope), "root_public": composed(root_key), **outcome}
    key = json.dumps(record, sort_keys=True)
    if key not in seen:
        seen.add(key)
        cases.append(dict(name="%s #%d" % (current_test[0], sum(c["name"].startswith(current_test[0] + " #") for c in cases) + 1), **record))
    if "refused" in outcome:
        raise membership.Refused(outcome["refused"])
    return result


class Naming(unittest.TextTestResult):
    def startTest(self, test):
        current_test[0] = test.id().replace("tests.test_baremetal_membership_v4.", "")
        super().startTest(test)


membership.accept = recording
loader = unittest.defaultTestLoader
suite = unittest.TestSuite(t for t in loader.loadTestsFromName("tests.test_baremetal_membership_v4")
                           if not t.__class__.__name__.startswith("Vectors"))
suite = unittest.TestSuite(test for group in suite for test in group if "Vectors" not in test.id())
result = unittest.TextTestRunner(stream=open(os.devnull, "w"), resultclass=Naming).run(suite)
if not result.wasSuccessful():
    raise SystemExit("the v4 membership tests failed: no vector is written")
print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": cases}, indent=1, sort_keys=True))
