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
        self.addCleanup(os.umask, os.umask(0o022))     # root's umask on a host
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

    def test_the_four_files_are_written_and_node_json_loads(self):
        config = self.install()
        loaded = node.load(self.prefix + enrol.NODE_JSON)
        self.assertEqual((loaded["node_id"], loaded["root_key"]), ("a", self.root_key))
        for path in (enrol.NODE_JSON, config["site"], config["measurements"], enrol.CHRONY_CONF):
            st = os.stat(self.prefix + path)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o644, path)
        with open(self.prefix + config["measurements"]) as f:
            self.assertEqual(json.load(f), self.document)
        recorded = self.journal.get("config")
        self.assertEqual(set(recorded) - {"state", "at"}, {enrol.NODE_JSON, config["site"], config["measurements"], enrol.CHRONY_CONF})
        # again, as a resumed run: the same bytes are accepted, nothing is rewritten
        before = os.stat(self.prefix + enrol.NODE_JSON).st_mtime_ns
        self.install()
        self.assertEqual(os.stat(self.prefix + enrol.NODE_JSON).st_mtime_ns, before)

    def test_time_comes_from_the_site_s_one_list(self):
        """#303: node.json's time_servers (what authtime judges), chrony.conf (what chrony uses) and the firewall's
        time rules are all rendered from the site's time.nts, whatever the example says."""
        from deploy.baremetal import authtime, firewall, sitecfg
        self.site["time"]["nts"] = self.site["time"]["nts"][1:]                     # two servers, not the example's three
        names = [server["name"] for server in self.site["time"]["nts"]]
        self.assertNotEqual(names, example("node.example.json")["time_servers"])
        self.install()
        self.assertEqual(node.load(self.prefix + enrol.NODE_JSON)["time_servers"], names)
        with open(self.prefix + enrol.CHRONY_CONF) as f:
            conf = f.read()
        self.assertEqual(conf, authtime.conf(names))
        self.assertEqual([line.split()[1] for line in conf.splitlines() if line.startswith("server ")], names)
        rules = firewall.render(sitecfg.validate(self.site))
        self.assertEqual(sorted({line.split('"time: ')[1].split(",")[0] for line in rules.splitlines() if '"time: ' in line}), sorted(names))

    def test_a_chrony_conf_already_there_is_never_replaced(self):
        target = self.prefix + enrol.CHRONY_CONF
        os.makedirs(os.path.dirname(target))
        with open(target, "w") as f:
            f.write("pool pool.ntp.org iburst\n")
        with self.assertRaisesRegex(enrol.Refused, "/etc/chrony/regalia.conf already exists with other content"):
            self.install()
        with open(target) as f:
            self.assertEqual(f.read(), "pool pool.ntp.org iburst\n")

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


    def test_a_file_that_appears_before_the_publish_is_not_replaced(self):
        """link(2), not rename(2): a file created between the check and the publish is never overwritten."""
        real_link = os.link
        planted = {}

        def racing(src, dst, *a, **k):
            if dst.endswith("measurements.json") and not planted:
                with open(dst, "w") as f:
                    f.write("planted\n")
                planted["done"] = True
            return real_link(src, dst, *a, **k)
        import unittest.mock
        with unittest.mock.patch.object(enrol.os, "link", racing):
            with self.assertRaisesRegex(enrol.Refused, "already exists with other content"):
                self.install()
        with open(self.prefix + "/etc/regalia/measurements.json") as f:
            self.assertEqual(f.read(), "planted\n")
        self.assertEqual([n for n in os.listdir(self.prefix + "/etc/regalia") if n.endswith(".enrol-new")], [])

    def test_a_crash_leaves_only_its_own_journalled_temporary_file_which_the_rerun_removes(self):
        import unittest.mock

        class Crash(BaseException):
            pass

        real = os.fchmod

        def crash(fd, mode):
            if mode != 0o644:                                   # the directories on the way: made as usual
                return real(fd, mode)
            raise Crash()
        # a kill runs no `finally`: crash where nothing would clean up, after the temporary file was created
        with unittest.mock.patch.object(enrol.os, "fchmod", crash):
            with self.assertRaises(Crash):
                self.install()
        left = [n for n in os.listdir(self.prefix + "/etc/regalia") if n.endswith(".enrol-new")]
        self.assertEqual(len(left), 1)
        with open(self.prefix + "/etc/regalia/unrelated.enrol-new", "w") as f:
            f.write("not ours\n")
        self.install()
        rest = sorted(n for n in os.listdir(self.prefix + "/etc/regalia") if n.endswith(".enrol-new"))
        self.assertEqual(rest, ["unrelated.enrol-new"], "a temporary file not journalled by this step was removed")

    def test_the_configuration_is_written_only_under_etc_regalia(self):
        bad = example("node.example.json")
        bad["measurements"] = "/var/tmp/measurements.json"
        with self.assertRaisesRegex(enrol.Refused, "outside /etc/regalia/"):
            self.install(example=bad)


if __name__ == "__main__":
    unittest.main()


class TrustedDirectories(unittest.TestCase):
    """Every directory enrolment writes under, and every one above it, is reached one level at a time without
    following a link and must be closed to group and others (or sticky with our own entry below); missing ones
    are made inside the descriptor of the one above, never by os.makedirs (read of #256)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)

    def test_missing_directories_are_made_one_level_at_a_time(self):
        enrol._ensure_trusted_dir(self.d + "/etc/regalia")
        self.assertTrue(os.path.isdir(self.d + "/etc/regalia"))

    def test_a_link_anywhere_on_the_way_is_refused(self):
        elsewhere = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, elsewhere, True)
        os.symlink(elsewhere, self.d + "/etc")
        with self.assertRaisesRegex(enrol.Refused, "is not a real directory"):
            enrol._ensure_trusted_dir(self.d + "/etc/regalia")
        self.assertFalse(os.path.exists(elsewhere + "/regalia"), "nothing was made through the link")

    def test_a_directory_open_to_others_on_the_way_is_refused(self):
        os.mkdir(self.d + "/var", 0o755)
        os.chmod(self.d + "/var", 0o777)
        with self.assertRaisesRegex(enrol.Refused, "closed to group and others"):
            enrol._ensure_trusted_dir(self.d + "/var/lib/regalia")
        self.assertFalse(os.path.exists(self.d + "/var/lib"), "nothing was made under it")

    def test_the_state_directory_is_handed_over_once_and_resumed_only_at_0755(self):
        state = self.d + "/var/lib/regalia"
        enrol._hand_over(state, chown=False)
        self.assertEqual(stat.S_IMODE(os.stat(state).st_mode), 0o755)
        enrol._hand_over(state, chown=False)                  # resumed: already "regalia-sync's", at 0755
        os.chmod(state, 0o777)
        with self.assertRaisesRegex(enrol.Refused, "not 0755"):
            enrol._hand_over(state, chown=False)

    def test_a_state_directory_that_is_a_link_is_refused(self):
        enrol._ensure_trusted_dir(self.d + "/var/lib")
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, True)
        os.symlink(target, self.d + "/var/lib/regalia")
        with self.assertRaisesRegex(enrol.Refused, "is not a real directory"):
            enrol._hand_over(self.d + "/var/lib/regalia", chown=False)
