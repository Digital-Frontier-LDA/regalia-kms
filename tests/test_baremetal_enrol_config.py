"""regalia-node enrol, phase 2's configuration (#190): node.json from the shipped example with this host's node
ID and root key, the site configuration and the measurements document, each refused if something else is
already there. Under a temporary prefix; no TPM."""
import json
import os
import shutil
import stat
import tempfile
import unittest

from deploy.baremetal import enrol, measurements, node

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(HERE, "..", "deploy", "baremetal")


def example(name):
    with open(os.path.join(EXAMPLES, name)) as f:
        return json.load(f)


class Config(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.prefix = self.d + "/root"
        os.makedirs(self.d + "/enrol", 0o700)
        self.journal = enrol.Journal(self.d + "/enrol", "a")
        self.site = example("site.example.json")
        entry = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}
        self.document = {"schema": measurements.SCHEMA, "name": "v1", "nodes": {"a": {"accepted": [entry]}}}
        self.root_key = "ab" * 32

    def install(self, **kw):
        args = dict(node_id="a", root_key=self.root_key, example=example("node.example.json"), site=self.site,
                    document=self.document, prefix=self.prefix)
        args.update(kw)
        return enrol.install_config(self.journal, **args)

    def test_the_three_files_are_written_and_node_json_loads(self):
        config = self.install()
        loaded = node.load(self.prefix + enrol.NODE_JSON)
        self.assertEqual((loaded["node_id"], loaded["root_key"]), ("a", self.root_key))
        for path in (enrol.NODE_JSON, config["site"], config["measurements"]):
            st = os.stat(self.prefix + path)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o644, path)
        with open(self.prefix + config["measurements"]) as f:
            self.assertEqual(json.load(f), self.document)
        recorded = self.journal.get("config")
        self.assertEqual(set(recorded) - {"state", "at"}, {enrol.NODE_JSON, config["site"], config["measurements"]})
        # again, as a resumed run: the same bytes are accepted, nothing is rewritten
        before = os.stat(self.prefix + enrol.NODE_JSON).st_mtime_ns
        self.install()
        self.assertEqual(os.stat(self.prefix + enrol.NODE_JSON).st_mtime_ns, before)

    def test_other_content_is_never_overwritten(self):
        config = self.install()
        target = self.prefix + config["site"]
        with open(target, "w") as f:
            f.write("{}\n")
        with self.assertRaisesRegex(enrol.Refused, "already exists with other content.*rm "):
            self.install()
        with open(target) as f:
            self.assertEqual(f.read(), "{}\n")
        # a different root key would write another node.json: refused, the first one kept
        os.unlink(target)
        with self.assertRaisesRegex(enrol.Refused, "node.json already exists with other content"):
            self.install(root_key="cd" * 32)

    def test_a_link_is_not_followed(self):
        config = self.install()
        target = self.prefix + config["measurements"]
        os.unlink(target)
        os.symlink(self.d + "/elsewhere", target)
        with self.assertRaisesRegex(enrol.Refused, "is not a regular file"):
            self.install()
        self.assertFalse(os.path.exists(self.d + "/elsewhere"))

    def test_an_invalid_configuration_writes_nothing(self):
        with self.assertRaises(Exception):
            self.install(root_key="not hex")
        self.assertFalse(os.path.exists(self.prefix))


if __name__ == "__main__":
    unittest.main()
