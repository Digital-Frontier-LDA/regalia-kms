#!/usr/bin/env python3
"""Writes tests/vectors/membership-v5.json: every call of membership.accept() that the v5 tests
(tests/test_baremetal_membership_v5.py) make, with what it was given and what it decided. The Go port
(cmd/regalia-unlock/membership) is held to the same v5 rules (regalia-kms-dx7.1): the topology field, the floors
as a majority of the designed nodes, the single-node shape, a topology no signer changes, and the root's move
from v4. A drift on either side fails CI: the Python test replays this file too.

    python3 -Es tests/vectors/make-membership-v5.py tests/vectors/membership-v5.json

The file is replaced only once every test has passed (written beside it, then renamed), so a failing run leaves the
last good vector in place; the runner's report goes to stderr. With no path, the JSON goes to stdout.

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
        current_test[0] = test.id().replace("tests.test_baremetal_membership_v5.", "")
        super().startTest(test)


def leaves(suite):
    """Every test in a suite, at any depth (a module that failed to import is one synthetic test, not a group)."""
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from leaves(item)
        else:
            yield item


membership.accept = recording
loader = unittest.TestLoader()
loaded = loader.loadTestsFromName("tests.test_baremetal_membership_v5")
if loader.errors:
    raise SystemExit("the v5 membership tests did not load: no vector is written\n" + "\n".join(loader.errors))
suite = unittest.TestSuite(test for test in leaves(loaded) if "Vectors" not in test.id())
result = unittest.TextTestRunner(stream=sys.stderr, resultclass=Naming).run(suite)
if not result.wasSuccessful():
    raise SystemExit("the v5 membership tests failed: no vector is written")
text = json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": cases}, indent=1, sort_keys=True) + "\n"
if len(sys.argv) > 1:
    partial = sys.argv[1] + ".partial"
    with open(partial, "w") as out:
        out.write(text)
    os.replace(partial, sys.argv[1])
else:
    sys.stdout.write(text)
