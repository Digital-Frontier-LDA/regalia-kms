"""regalia-avz: regenerate tests/vectors/ownerauth-v1.json with regalia-ceremony's REAL writer (offline-keys ownerauth),
driven exactly as its test_offline_keys.OwnerAuth drives it: a fresh 2-of-3 lab root (ok.generate; its shares are not
kept), two software GnuPG homes standing in for the OWNER cards (D30.7), a card record naming them, then
ownerauth(nodes a, b, c). Kept: ownerauth.record.json byte-exact, the pinned root, and each node's value as the first
owner card decrypts it. Usage (Linux, the ceremony's runner image): python3 ownerauth-v1-gen.py CEREMONY_TESTS_DIR SHA OUT"""
import json
import os
import sys
import unittest

tests, sha, out = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, tests)
import test_offline_keys as t  # noqa: E402

assert not os.path.exists(out), "OUT must not exist: a regeneration never replaces the committed vector as a side effect"


class Gen(t.OwnerAuth):
    def runTest(self):
        self.run_oa()
        with open(os.path.join(self.oa, "ownerauth.record.json")) as f:
            record_file = f.read()
        root = t.ok.sealed_root(self.sealed)
        record = t.ok.verify_record(json.loads(record_file), root, t.ok.SCHEMA_OWNERAUTH)
        values = {node: self.gpg_decrypt(os.path.join(self.oa, "ownerauth-%s.yk.gpg" % node), self.homes[0]).decode()
                  for node in sorted(record["nodes"])}
        made_by = ("regalia-ceremony offline-keys.py at %s, by tests/vectors/ownerauth-v1-gen.py through that commit's "
                   "test_offline_keys.OwnerAuth setup: a fresh throwaway set, software GnuPG homes for the two owner cards" % sha)
        vector = {"about": "#242 step C: a throwaway ownerauth set made by the ceremony's real writer (regalia-avz: the record "
                           "signed under regalia.ownerauth-record/v1). Not secrets. record_file is ownerauth.record.json "
                           "byte-exact; root the pinned membership root (raw Ed25519, the record's root_entry); values each "
                           "node's decrypted envelope, 64 hex and a newline.",
                  "made_by": made_by, "record_file": record_file, "root": root, "values": values}
        with open(out, "w") as f:
            json.dump(vector, f, indent=1, sort_keys=True)
            f.write("\n")
        print("root", root, "nodes", sorted(values))


result = unittest.TextTestRunner(verbosity=2).run(Gen())
sys.exit(0 if result.wasSuccessful() else 1)
