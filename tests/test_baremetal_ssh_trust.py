"""deploy/baremetal/ssh_trust.py and sshd-regalia-kms.conf.example (#143): an administrator's known_hosts
generated from the membership manifest, checked against OpenSSH itself, and a real sshd on the example
configuration (class OnSshd; e2e/ssh-trust-sshd.sh runs it where a skip is a failure)."""
import base64
import contextlib
import getpass
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import membership as m
from deploy.baremetal import ssh_trust
from tests.test_baremetal_membership import ROOT, ROOT_PUB, manifest, manifest2, node, sign, ssh

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, "..", "deploy", "baremetal", "sshd-regalia-kms.conf.example")


def four(keys=None):
    """a ACTIVE, b QUARANTINED, c RETIRED with its key, d retired under v1 (no key on record), e stolen with its key."""
    keys = keys or {name: ssh("abcde".index(name)) for name in "abce"}
    states = {"a": "ACTIVE", "b": "QUARANTINED", "c": "RETIRED", "d": "REVOKED_STOLEN", "e": "REVOKED_STOLEN"}
    return [dict(node(name, states[name], i), **({"ssh_host_pub": keys[name]} if name in keys else {})) for i, name in enumerate("abcde")]


def openssh(raw_hex):
    return "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes.fromhex(raw_hex)).decode()


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.man = manifest2(1, "", four())

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class HostKeys(Case):
    def test_the_openssh_form_is_the_one_openssh_writes(self):
        key = Ed25519PrivateKey.generate().public_key()
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        line = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(ssh_trust.host_key(raw), line)
        self.assertEqual(ssh_trust.raw_host_key(line), raw)
        self.assertEqual(ssh_trust.raw_host_key(line + " root@kms-a\n"), raw)                  # as in ssh_host_ed25519_key.pub
        for bad in ("d0" * 31, "D0" * 32, None, b"\xd0" * 32):
            with self.subTest(ssh_host_pub=bad):
                self.refused("ssh_host_pub must be 64 lowercase hex", ssh_trust.host_key, bad)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
    def test_a_key_made_by_ssh_keygen_round_trips(self):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.d + "/host"], check=True)
        with open(self.d + "/host.pub") as f:
            line = f.read()
        raw = ssh_trust.raw_host_key(line)
        self.assertEqual(ssh_trust.host_key(raw), " ".join(line.split()[:2]))

    def test_any_other_key_line_is_refused(self):
        good = openssh("d0" * 32).split()[1]
        blob = base64.b64decode(good)
        ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA=="
        cases = (
            ("the SSH host key must be ssh-ed25519", ecdsa),
            ("the SSH host key must be ssh-ed25519", "ssh-rsa " + good),
            ("the SSH host key must be ssh-ed25519", "ssh-ed25519"),
            ("the SSH host key must be ssh-ed25519", ""),
            ("the SSH host key must be ssh-ed25519", "@revoked ssh-ed25519 " + good),
            ("the SSH host key is not base64", "ssh-ed25519 not*base64"),
            ("the SSH host key is not base64", "ssh-ed25519 " + good[:-1]),
            ("not a canonical ssh-ed25519 key", "ssh-ed25519 " + base64.b64encode(blob[:-1]).decode()),          # 31 bytes
            ("not a canonical ssh-ed25519 key", "ssh-ed25519 " + base64.b64encode(blob + b"\0").decode()),       # trailing byte
            ("not a canonical ssh-ed25519 key", "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25518" + blob[15:]).decode()),      # another type inside, the same length
            ("the SSH host key is not base64", "ssh-ed25519 " + good[:10] + "*" + good[10:]),                     # a lenient decoder would skip the "*" and find a key
            ("an SSH public key is a line of text", None),
            ("an SSH public key is a line of text", openssh("d0" * 32).encode()),
        )
        for reason, line in cases:
            with self.subTest(line=line):
                self.refused(reason, ssh_trust.raw_host_key, line)


class KnownHosts(Case):
    def test_one_line_per_live_node_and_a_revocation_per_retired_key(self):
        digest = m.digest(self.man)
        self.assertEqual(ssh_trust.known_hosts(self.man),
                         "# Generated by deploy/baremetal/ssh_trust.py from membership epoch 1, manifest %s. Do not edit by hand.\n"
                         "a %s regalia-kms epoch 1 ACTIVE\n"
                         "b %s regalia-kms epoch 1 QUARANTINED\n"
                         "@revoked * %s regalia-kms epoch 1 c RETIRED\n"
                         "@revoked * %s regalia-kms epoch 1 e REVOKED_STOLEN\n" % (digest, openssh(ssh(0)), openssh(ssh(1)), openssh(ssh(2)), openssh(ssh(4))))
        # d was retired before it had a key on record: nothing is invented for it, and it is not a host
        self.assertNotIn("\nd ", ssh_trust.known_hosts(self.man))
        self.assertEqual(ssh_trust.known_hosts(dict(self.man, nodes=list(reversed(self.man["nodes"])))).splitlines()[1:],
                         ssh_trust.known_hosts(self.man).splitlines()[1:])          # the order of the manifest's list does not matter

    def test_a_v1_manifest_or_an_invalid_one_is_refused(self):
        self.refused("a regalia.membership/v1 manifest names no SSH host keys", ssh_trust.known_hosts, manifest(1, "", [node("a")]))
        self.refused("a regalia.membership/v1 manifest names no SSH host keys", ssh_trust.ssh_config, manifest(1, "", [node("a")]), {}, "/k")
        broken = manifest2(1, "", four())
        broken["nodes"][1]["ssh_host_pub"] = broken["nodes"][0]["ssh_host_pub"]
        for fn, args in ((ssh_trust.known_hosts, ()), (ssh_trust.ssh_config, ({}, "/k"))):
            self.refused("ssh_host_pub of b is already used", fn, broken, *args)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
    def test_ssh_keygen_finds_each_live_node_under_its_own_name_only(self):
        path = self.d + "/known_hosts"
        with open(path, "w") as f:
            f.write(ssh_trust.known_hosts(self.man))
        found = lambda name: subprocess.run(["ssh-keygen", "-F", name, "-f", path], capture_output=True, text=True)
        for name, key in (("a", ssh(0)), ("b", ssh(1))):
            hit = found(name)
            self.assertEqual(hit.returncode, 0, hit.stderr)
            self.assertEqual([line.split()[:3] for line in hit.stdout.splitlines() if not line.startswith(("#", "@revoked"))], [[name] + openssh(key).split()])
        for name in ("c", "d", "e", "192.0.2.10"):
            hit = found(name)                                              # a retired node is not a host; its key is only ever @revoked
            self.assertEqual([line for line in hit.stdout.splitlines() if not line.startswith(("#", "@revoked"))], [], name)


class SshConfig(Case):
    ADDRESSES = {"a": "192.0.2.10", "b": "192.0.2.11"}

    def test_each_host_is_checked_under_its_node_id_against_the_generated_file_only(self):
        text = ssh_trust.ssh_config(self.man, self.ADDRESSES, "/home/admin/.ssh/regalia_known_hosts", 2222)
        strict = ["    HostKeyAlgorithms ssh-ed25519", "    UserKnownHostsFile /home/admin/.ssh/regalia_known_hosts", "    GlobalKnownHostsFile /dev/null",
                  "    StrictHostKeyChecking yes", "    UpdateHostKeys no", "    CheckHostIP no", "    ForwardAgent no"]
        self.assertEqual(text.splitlines(), [
            "# Generated by deploy/baremetal/ssh_trust.py from membership epoch 1, manifest %s. Do not edit by hand." % m.digest(self.man),
            "# For `ssh -F <this file>` only. Never Include it: the last block applies to every host.",
            "Host a", "    HostName 192.0.2.10", "    Port 2222", "    HostKeyAlias a"] + strict + [
            "Host b", "    HostName 192.0.2.11", "    Port 2222", "    HostKeyAlias b"] + strict + [
            "Host *"] + strict)                                              # the catch-all comes LAST: ssh keeps the first value it reads
        self.assertEqual(ssh_trust.ssh_config(self.man, {"a": "192.0.2.10"}, "/k").count("Port 22\n"), 1)
        self.assertEqual(ssh_trust.ssh_config(self.man, {}, "/k").splitlines()[2:3], ["Host *"])     # no address at all: still strict for every name

    @unittest.skipUnless(shutil.which("ssh"), "needs ssh")
    def test_a_name_without_a_block_of_its_own_is_held_to_the_same_file_and_strictness(self):
        """1e's finding: a retired node, a live node left out of the addresses, and a bare IP address fell
        through to ssh's defaults: the user's own known_hosts and a trust-on-first-use prompt, with the
        generated @revoked lines not consulted. That is the state right after a revocation."""
        path = self.d + "/config"
        with open(path, "w") as f:
            f.write(ssh_trust.ssh_config(self.man, {"a": "192.0.2.10"}, self.d + "/known_hosts"))
        for name in ("b", "c", "e", "192.0.2.11", "192.0.2.10", "kms-a.example", "A"):
            with self.subTest(name=name):
                shown = subprocess.run(["ssh", "-G", "-F", path, name], capture_output=True, text=True, check=True).stdout.lower()
                effective = dict(line.split(" ", 1) for line in shown.splitlines() if " " in line)
                self.assertEqual({k: effective[k] for k in ("userknownhostsfile", "globalknownhostsfile", "updatehostkeys", "hostkeyalgorithms")},
                                 {"userknownhostsfile": (self.d + "/known_hosts").lower(), "globalknownhostsfile": "/dev/null",
                                  "updatehostkeys": "false", "hostkeyalgorithms": "ssh-ed25519"})
                self.assertIn(effective["stricthostkeychecking"], ("true", "yes"))
                self.assertNotIn("hostkeyalias", effective)

    @unittest.skipUnless(shutil.which("ssh"), "needs ssh")
    def test_ssh_reads_it_as_meant(self):
        path = self.d + "/config"
        with open(path, "w") as f:
            f.write(ssh_trust.ssh_config(self.man, self.ADDRESSES, self.d + "/known_hosts"))
        shown = subprocess.run(["ssh", "-G", "-F", path, "b"], capture_output=True, text=True, check=True).stdout.lower()
        effective = dict(line.split(" ", 1) for line in shown.splitlines() if " " in line)
        self.assertEqual({k: effective[k] for k in ("hostname", "port", "hostkeyalias", "userknownhostsfile", "globalknownhostsfile",
                                                    "updatehostkeys", "checkhostip", "forwardagent", "hostkeyalgorithms")},
                         {"hostname": "192.0.2.11", "port": "22", "hostkeyalias": "b", "userknownhostsfile": (self.d + "/known_hosts").lower(),
                          "globalknownhostsfile": "/dev/null", "updatehostkeys": "false", "checkhostip": "no", "forwardagent": "no",
                          "hostkeyalgorithms": "ssh-ed25519"})
        self.assertIn(effective["stricthostkeychecking"], ("true", "yes"))

    def test_refusals(self):
        ok = "/k"
        cases = (
            ("'z' has an address but is not in the manifest", ({"z": "192.0.2.9"}, ok)),
            ("c is RETIRED: it gets no ssh_config entry", ({"c": "192.0.2.9"}, ok)),
            ("d is REVOKED_STOLEN: it gets no ssh_config entry", ({"d": "192.0.2.9"}, ok)),
            ("two nodes cannot have one address", ({"a": "192.0.2.9", "b": "192.0.2.9"}, ok)),
            ("addresses must map node IDs to IPv4 addresses", ([["a", "192.0.2.9"]], ok)),
            ("the SSH port must be 1 to 65535", (self.ADDRESSES, ok, 0)),
            ("the SSH port must be 1 to 65535", (self.ADDRESSES, ok, 65536)),
            ("the SSH port must be 1 to 65535", (self.ADDRESSES, ok, True)),
            ("the SSH port must be 1 to 65535", (self.ADDRESSES, ok, "22")),
        )
        for reason, args in cases:
            with self.subTest(reason=reason, args=args):
                self.refused(reason, ssh_trust.ssh_config, self.man, *args)
        for address in ("192.0.2.010", "192.0.2", "2001:db8::1", "192.0.2.9\n    ProxyCommand evil", " 192.0.2.9", "kms-a.example", 3221225994, None):
            with self.subTest(address=address):
                self.refused("the address of a must be a plain IPv4 address", ssh_trust.ssh_config, self.man, {"a": address}, ok)
        for path in ("known_hosts", "~/.ssh/k", "/home/a b/k", "/k\n    ProxyCommand evil", "/k %h", '/"k"', "/a/../k", "/a/..", "", None, "/" + "k" * 256):
            with self.subTest(path=path):
                self.refused("the known_hosts path must be an absolute path", ssh_trust.ssh_config, self.man, self.ADDRESSES, path)
        self.assertIn("UserKnownHostsFile /a..b/k.d/x_y-z\n", ssh_trust.ssh_config(self.man, self.ADDRESSES, "/a..b/k.d/x_y-z"))


class Current(Case):
    def setUp(self):
        super().setUp()
        self.e1 = sign(self.man, ROOT)
        live = four()
        live[1]["state"] = "RETIRED"                                        # b is retired at epoch 2
        self.e2 = sign(manifest2(2, m.digest(self.man), live), ROOT)

    def test_the_newest_manifest_of_a_verified_chain(self):
        self.assertEqual(ssh_trust.current([self.e1, self.e2], ROOT_PUB, 2)["epoch"], 2)
        self.assertEqual(ssh_trust.current([self.e1, self.e2], ROOT_PUB, 1)["epoch"], 2)
        self.assertEqual(ssh_trust.current([self.e1], ROOT_PUB, 1)["epoch"], 1)

    def test_an_older_chain_is_a_rollback(self):
        # the chain from before b was retired still verifies; only the expected epoch tells it is old
        self.refused("ROLLBACK: the chain ends at epoch 1 and at least epoch 2 is expected", ssh_trust.current, [self.e1], ROOT_PUB, 2)
        self.refused("ROLLBACK: the chain ends at epoch 2 and at least epoch 3 is expected", ssh_trust.current, [self.e1, self.e2], ROOT_PUB, 3)

    def test_refusals(self):
        forged = dict(self.e2, signature=dict(self.e2["signature"], sig="00" * 64))
        for reason, args in (("at_least_epoch must be an integer >= 1", ([self.e1], ROOT_PUB, 0)),
                             ("at_least_epoch must be an integer >= 1", ([self.e1], ROOT_PUB, True)),
                             ("at_least_epoch must be an integer >= 1", ([self.e1], ROOT_PUB, "1")),
                             ("at_least_epoch must be an integer >= 1", ([self.e1], ROOT_PUB, None)),
                             ("a chain is a non-empty list of envelopes", ([], ROOT_PUB, 1)),
                             ("a chain is a non-empty list of envelopes", ({"manifest": self.man}, ROOT_PUB, 1)),
                             ("the chain repeats epoch 1", ([self.e1, self.e1], ROOT_PUB, 1)),
                             ("the first manifest must be the root-signed epoch 1", ([self.e2], ROOT_PUB, 1)),
                             ("the manifest signature does not verify", ([self.e1, forged], ROOT_PUB, 1)),
                             ("the signature names a root key that is not the pinned root", ([self.e1], "ab" * 32, 1))):
            with self.subTest(reason=reason):
                self.refused(reason, ssh_trust.current, *args)


class Program(Current):
    def run_main(self, *extra, chain=None, epoch="2"):
        with open(self.d + "/chain.json", "wb") as f:
            f.write(m.canonical([self.e1, self.e2] if chain is None else chain))
        return ssh_trust.main(["--chain", self.d + "/chain.json", "--root-key", ROOT_PUB, "--at-least-epoch", epoch,
                               "--known-hosts", self.d + "/known_hosts", *extra])

    def test_it_writes_both_files_from_the_current_manifest(self):
        with open(self.d + "/addresses.json", "w") as f:
            json.dump({"a": "192.0.2.10"}, f)
        # over what the previous epoch left: replaced whole, nothing of the old file survives (b was a host then)
        self.assertEqual(self.run_main("--addresses", self.d + "/addresses.json", "--ssh-config", self.d + "/config", chain=[self.e1], epoch="1"), 0)
        with open(self.d + "/known_hosts") as f:
            self.assertIn("\nb ssh-ed25519 ", f.read())
        self.assertEqual(self.run_main("--addresses", self.d + "/addresses.json", "--ssh-config", self.d + "/config", "--port", "2222"), 0)
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), ssh_trust.known_hosts(self.e2["manifest"]))
        with open(self.d + "/config") as f:
            self.assertEqual(f.read(), ssh_trust.ssh_config(self.e2["manifest"], {"a": "192.0.2.10"}, self.d + "/known_hosts", 2222))
        self.assertEqual([os.stat(self.d + "/" + name).st_mode & 0o777 for name in ("known_hosts", "config")], [0o600, 0o600])
        self.assertEqual([name for name in os.listdir(self.d) if name.startswith(".regalia-ssh-")], [])

    def test_an_older_chain_never_replaces_a_newer_file(self):
        """1e's finding: the floor was only what was typed. A run with the old chain and --at-least-epoch 1
        replaced a newer known_hosts and listed the revoked node as a host again."""
        self.assertEqual(self.run_main(), 0)                                # epoch 2: b is retired
        with open(self.d + "/known_hosts") as f:
            newer = f.read()
        self.assertIn("@revoked * %s regalia-kms epoch 2 b RETIRED" % openssh(ssh(1)), newer)
        with contextlib.redirect_stderr(io.StringIO()) as said:
            self.assertEqual(self.run_main(chain=[self.e1], epoch="1"), 1)
        self.assertIn("ROLLBACK: %s/known_hosts was generated from epoch 2 and the chain given ends at epoch 1" % self.d, said.getvalue())
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), newer)
        self.assertEqual(self.run_main(), 0)                                # the same manifest again: fine
        other = four()
        other[1]["state"] = "RETIRED"
        other[0]["state"] = "MAINTENANCE"
        rival2 = sign(manifest2(2, m.digest(self.man), other), ROOT)       # another root-signed manifest at epoch 2
        with contextlib.redirect_stderr(io.StringIO()) as said:
            self.assertEqual(self.run_main(chain=[self.e1, rival2]), 1)
        self.assertIn("CONFLICT: %s/known_hosts was generated from another manifest at epoch 2" % self.d, said.getvalue())
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), newer)
        # the config file is held to the same rule, by itself
        with open(self.d + "/addresses.json", "w") as f:
            json.dump({"a": "192.0.2.10"}, f)
        os.unlink(self.d + "/known_hosts")
        self.assertEqual(self.run_main("--addresses", self.d + "/addresses.json", "--ssh-config", self.d + "/config"), 0)
        os.unlink(self.d + "/known_hosts")
        with contextlib.redirect_stderr(io.StringIO()) as said:
            self.assertEqual(self.run_main("--addresses", self.d + "/addresses.json", "--ssh-config", self.d + "/config", chain=[self.e1], epoch="1"), 1)
        self.assertIn("ROLLBACK: %s/config was generated from epoch 2" % self.d, said.getvalue())
        self.assertFalse(os.path.exists(self.d + "/known_hosts"))

    def test_a_file_in_the_way_that_this_program_did_not_write_is_not_replaced(self):
        header = "# Generated by deploy/baremetal/ssh_trust.py from membership epoch 1, manifest %s. Do not edit by hand." % m.digest(self.man)
        for label, content in (("somebody's known_hosts", "github.com ssh-ed25519 AAAA\n"), ("empty", ""), ("epoch 0", header.replace("epoch 1,", "epoch 0,") + "\n"),
                               ("a header with something after it", header + " x\n"), ("an uppercase digest", header.replace(m.digest(self.man), "AB" * 32) + "\n"),
                               ("not text", b"\xff\xfe\n")):
            with self.subTest(label):
                with open(self.d + "/known_hosts", "wb") as f:
                    f.write(content if isinstance(content, bytes) else content.encode())
                with contextlib.redirect_stderr(io.StringIO()) as said:
                    self.assertEqual(self.run_main(), 1)
                self.assertIn("known_hosts exists and was not generated by this program: it is not replaced", said.getvalue())
                with open(self.d + "/known_hosts", "rb") as f:
                    self.assertEqual(f.read(), content if isinstance(content, bytes) else content.encode())
        self.assertEqual(ssh_trust.generated_from(self.d + "/absent"), None)
        with open(self.d + "/known_hosts", "w") as f:
            f.write(header + "\nanything below the first line\n")
        self.assertEqual(ssh_trust.generated_from(self.d + "/known_hosts"), (1, m.digest(self.man)))

    def test_neither_file_is_replaced_unless_both_can_be(self):
        """1e's finding: with --ssh-config in a directory that does not exist, the program exited 1 with the
        known_hosts already replaced."""
        self.assertEqual(self.run_main(chain=[self.e1], epoch="1"), 0)
        with open(self.d + "/known_hosts") as f:
            before = f.read()
        with open(self.d + "/addresses.json", "w") as f:
            json.dump({"a": "192.0.2.10"}, f)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_main("--addresses", self.d + "/addresses.json", "--ssh-config", self.d + "/no-such-directory/config"), 1)
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual([name for name in os.listdir(self.d) if name.startswith(".regalia-ssh-")], [])     # and no staged file is left behind

    def test_a_symbolic_link_at_the_destination_is_replaced_not_written_through(self):
        with open(self.d + "/elsewhere", "w") as f:
            f.write("somebody else's file\n")
        self.assertEqual(self.run_main(chain=[self.e1], epoch="1"), 0)
        os.unlink(self.d + "/known_hosts")
        shutil.copy(self.d + "/elsewhere", self.d + "/target")
        with open(self.d + "/target", "w") as f:                            # a generated file, reached through a link
            f.write(ssh_trust.known_hosts(self.man))
        os.symlink(self.d + "/target", self.d + "/known_hosts")
        self.assertEqual(self.run_main(), 0)
        self.assertFalse(os.path.islink(self.d + "/known_hosts"))
        with open(self.d + "/target") as f:
            self.assertEqual(f.read(), ssh_trust.known_hosts(self.man))       # the link's target is as it was
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), ssh_trust.known_hosts(self.e2["manifest"]))

    def test_a_refusal_writes_nothing_and_leaves_the_old_file(self):
        with open(self.d + "/known_hosts", "w") as f:
            f.write("previous\n")
        with open(self.d + "/addresses.json", "w") as f:
            json.dump({"b": "192.0.2.11"}, f)                               # b is retired at epoch 2: the config is refused
        attempts = (
            ((), {"chain": [self.e1]}),                                     # a rollback
            ((), {"chain": [self.e1, dict(self.e2, signature=dict(self.e2["signature"], sig="00" * 64))]}),
            ((), {"epoch": "0"}),
            (("--addresses", self.d + "/addresses.json", "--ssh-config", self.d + "/config"), {}),
            (("--addresses", self.d + "/absent.json", "--ssh-config", self.d + "/config"), {}),
            (("--addresses", self.d + "/addresses.json"), {}),              # one without the other
            (("--ssh-config", self.d + "/config"), {}),
        )
        for extra, kw in attempts:
            with self.subTest(extra=extra, kw=sorted(kw)):
                self.assertEqual(self.run_main(*extra, **kw), 1)
                with open(self.d + "/known_hosts") as f:
                    self.assertEqual(f.read(), "previous\n")
                self.assertFalse(os.path.exists(self.d + "/config"))
        with open(self.d + "/chain.json", "wb") as f:
            f.write(m.canonical([self.e1, self.e2]))
        base = ["--chain", self.d + "/chain.json", "--at-least-epoch", "2", "--known-hosts", self.d + "/known_hosts"]
        self.assertEqual(ssh_trust.main(base + ["--root-key", "ab" * 32]), 1)      # a well-formed key that is not the root
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), "previous\n")


def settings(text):
    """The keyword lines of an sshd configuration, in order, keywords lower-cased."""
    return [(line.split(None, 1)[0].lower(), line.split(None, 1)[1].strip()) for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class ExampleConfiguration(unittest.TestCase):
    """What sshd-regalia-kms.conf.example must go on saying, whatever else is edited in it."""

    def test_the_lines_that_carry_the_design(self):
        with open(EXAMPLE) as f:
            lines = settings(f.read())
        self.assertEqual(len({k for k, _ in lines}), len(lines), "a keyword is set twice: sshd would use the first")
        got = dict(lines)
        expect = {
            "hostkey": "/etc/ssh/ssh_host_ed25519_key", "hostkeyalgorithms": "ssh-ed25519",
            "passwordauthentication": "no", "kbdinteractiveauthentication": "no", "hostbasedauthentication": "no",
            "permitemptypasswords": "no", "authenticationmethods": "publickey",
            "authorizedkeysfile": "none", "authorizedkeyscommand": "none",
            "trustedusercakeys": "/etc/ssh/regalia-user-ca.pub", "authorizedprincipalsfile": "/etc/ssh/regalia-principals/%u",
            "pubkeyacceptedalgorithms": "sk-ssh-ed25519-cert-v01@openssh.com", "casignaturealgorithms": "sk-ssh-ed25519@openssh.com",
            "pubkeyauthoptions": "touch-required verify-required",
            "revokedkeys": "/etc/ssh/regalia-revoked-keys", "permitrootlogin": "no",
            "allowagentforwarding": "no", "allowtcpforwarding": "no", "allowstreamlocalforwarding": "no", "x11forwarding": "no",
            "permittunnel": "no", "gatewayports": "no", "permituserenvironment": "no",
        }
        self.assertEqual({k: got.get(k) for k in expect}, expect)


def find_sshd():
    for candidate in (os.environ.get("REGALIA_SSHD"), shutil.which("sshd"), "/usr/sbin/sshd"):
        if candidate and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
    return None


class OnSshd(unittest.TestCase):
    """A real sshd on the example configuration, and a real ssh on the generated known_hosts and ssh_config.
    No port: ssh's ProxyCommand runs `sshd -i`, one per connection, as this user. Where sshd is provisioned
    (REGALIA_EXPECT_SSHD=1) a missing one is a failure, not a skip.

    Two things differ from a KMS host, both stated in SSH.md: the paths are in a temporary directory, and
    the keys are software keys (no FIDO token here), so the two "sk-" lines are widened, except in the one
    test that proves the example as written refuses a software key."""

    USER = getpass.getuser()

    def setUp(self):
        self.sshd = find_sshd()
        if not (self.sshd and shutil.which("ssh") and shutil.which("ssh-keygen")):
            if os.environ.get("REGALIA_EXPECT_SSHD") == "1":
                self.fail("sshd, ssh and ssh-keygen are expected here and were not found")
            self.skipTest("needs sshd, ssh and ssh-keygen")
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        raw = {}
        for name in ("a", "b", "c", "e"):                  # one host key per node; c is the retired one, e the stolen one
            self.keygen("-t", "ed25519", "-C", "host-" + name, "-f", "%s/host_%s" % (self.d, name))
            with open("%s/host_%s.pub" % (self.d, name)) as f:
                raw[name] = ssh_trust.raw_host_key(f.read())
        self.manifest = manifest2(1, "", four(raw))
        with open(self.d + "/known_hosts", "w") as f:
            f.write(ssh_trust.known_hosts(self.manifest))
        with open(self.d + "/ssh_config", "w") as f:
            f.write(ssh_trust.ssh_config(self.manifest, {"a": "192.0.2.10", "b": "192.0.2.11"}, self.d + "/known_hosts"))
        for name in ("ca", "backup_ca", "other_ca", "user"):
            self.keygen("-t", "ed25519", "-C", name, "-f", "%s/%s" % (self.d, name))
        os.mkdir(self.d + "/regalia-principals")
        with open("%s/regalia-principals/%s" % (self.d, self.USER), "w") as f:
            f.write("admin-one\n")
        with open(self.d + "/regalia-user-ca.pub", "w") as trusted:         # the two CA tokens of SSH.md: either may sign
            for name in ("ca", "backup_ca"):
                with open("%s/%s.pub" % (self.d, name)) as f:
                    trusted.write(f.read())
        with open(self.d + "/regalia-revoked-keys", "w"):
            pass
        self.serial = 0

    def keygen(self, *args):
        done = subprocess.run(["ssh-keygen", "-q", "-N", "", *args] if "-t" in args else ["ssh-keygen", "-q", *args],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)

    def certificate(self, ca="ca", principal="admin-one", validity="+12h"):
        """A certificate for the user key, as SSH.md issues one. Returns its path."""
        self.serial += 1
        path = "%s/cert%d" % (self.d, self.serial)
        shutil.copy(self.d + "/user.pub", path + ".pub")
        self.keygen("-s", "%s/%s" % (self.d, ca), "-I", "test-%d" % self.serial, "-n", principal, "-V", validity,
                    "-z", str(self.serial), "-O", "clear", "-O", "permit-pty", path + ".pub")
        return path + "-cert.pub"

    def sshd_config(self, host, widen=True):
        """The example, for the node whose host key is `host`: /etc/ssh/ becomes the temporary directory,
        and three lines are added that only running sshd as an ordinary user needs."""
        with open(EXAMPLE) as f:
            text = f.read()
        text = text.replace("/etc/ssh/ssh_host_ed25519_key", "%s/host_%s" % (self.d, host)).replace("/etc/ssh/", self.d + "/")
        if widen:
            for old, new in (("PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com", "PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com"),
                             ("CASignatureAlgorithms sk-ssh-ed25519@openssh.com", "CASignatureAlgorithms ssh-ed25519")):
                self.assertEqual(text.count(old), 1, old)
                text = text.replace(old, new)
        text += "\nUsePAM no\nStrictModes no\nPidFile none\n"
        session = os.path.join(os.path.dirname(self.sshd), "..", "lib", "openssh", "sshd-session")
        if os.path.dirname(self.sshd) != "/usr/sbin" and os.path.exists(session):       # an sshd unpacked outside /usr (a developer's machine)
            text += "SshdSessionPath %s\nSshdAuthPath %s\n" % (os.path.abspath(session), os.path.abspath(session[:-len("session")] + "auth"))
        path = "%s/sshd_config_%s_%s" % (self.d, host, "widened" if widen else "as_written")
        with open(path, "w") as f:
            f.write(text)
        return path

    def login(self, name, served_by, certificate=None, widen=True, options=()):
        """ssh to node `name` (through the generated ssh_config), answered by the sshd of node `served_by`."""
        argv = ["ssh", "-F", self.d + "/ssh_config", "-o", "ProxyCommand=%s -i -e -f %s" % (self.sshd, self.sshd_config(served_by, widen)),
                "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
                "-o", "IdentityFile=%s/user" % self.d]
        if certificate:
            argv += ["-o", "CertificateFile=" + certificate]
        for option in options:
            argv += ["-o", option]
        done = subprocess.run(argv + ["%s@%s" % (self.USER, name), "echo logged-in-to-$0"], capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL)
        return done.returncode, done.stdout, done.stderr

    def assertLoggedIn(self, result):
        self.assertEqual((result[0], result[1][:13]), (0, "logged-in-to-"), result[2])

    def assertRefused(self, result, reason):
        self.assertNotEqual(result[0], 0, result)
        self.assertNotIn("logged-in", result[1])
        self.assertIn(reason, result[2])

    def test_the_example_is_a_configuration_sshd_accepts(self):
        done = subprocess.run([self.sshd, "-T", "-f", self.sshd_config("a", widen=False)], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        effective = settings(done.stdout)
        self.assertEqual([v for k, v in effective if k == "hostkey"], [self.d + "/host_a"])       # one host key, and no other
        got = dict(effective)
        self.assertEqual({k: got[k] for k in ("passwordauthentication", "kbdinteractiveauthentication", "hostbasedauthentication",
                                              "authorizedkeysfile", "permitrootlogin", "pubkeyacceptedalgorithms", "casignaturealgorithms",
                                              "hostkeyalgorithms", "allowtcpforwarding", "allowagentforwarding", "authenticationmethods",
                                              "permitemptypasswords", "pubkeyauthoptions")},
                         {"passwordauthentication": "no", "kbdinteractiveauthentication": "no", "hostbasedauthentication": "no",
                          "authorizedkeysfile": "none", "permitrootlogin": "no", "pubkeyacceptedalgorithms": "sk-ssh-ed25519-cert-v01@openssh.com",
                          "casignaturealgorithms": "sk-ssh-ed25519@openssh.com", "hostkeyalgorithms": "ssh-ed25519",
                          "allowtcpforwarding": "no", "allowagentforwarding": "no", "authenticationmethods": "publickey",
                          "permitemptypasswords": "no", "pubkeyauthoptions": "touch-required verify-required"})
        # and as sshd would decide it for a login: Match is evaluated only with -C (plain -T prints the global values)
        matched = subprocess.run([self.sshd, "-T", "-f", self.sshd_config("a", widen=False), "-C", "user=%s,addr=192.0.2.200,host=a" % self.USER],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(matched.returncode, 0, matched.stderr)
        self.assertEqual(dict(settings(matched.stdout))["passwordauthentication"], "no")

    def test_a_certificate_from_the_ca_logs_in_to_the_node_it_names(self):
        cert = self.certificate()
        self.assertLoggedIn(self.login("a", "a", cert))
        self.assertLoggedIn(self.login("b", "b", cert))

    def test_either_of_the_two_ca_tokens_can_issue_and_a_third_cannot(self):
        """One CA token lost must not end every login: the nodes trust two. Anything else is refused."""
        self.assertLoggedIn(self.login("a", "a", self.certificate(ca="ca")))
        self.assertLoggedIn(self.login("a", "a", self.certificate(ca="backup_ca")))
        self.assertRefused(self.login("a", "a", self.certificate(ca="other_ca")), "Permission denied")
        # the first token is lost and taken out of the file: its certificates stop, the backup's go on
        shutil.copy(self.d + "/backup_ca.pub", self.d + "/regalia-user-ca.pub")
        self.assertRefused(self.login("a", "a", self.certificate(ca="ca")), "Permission denied")
        self.assertLoggedIn(self.login("a", "a", self.certificate(ca="backup_ca")))

    def test_a_node_cannot_answer_for_another(self):
        cert = self.certificate()
        self.assertRefused(self.login("b", "a", cert), "Host key verification failed")           # a's key, asked for b
        self.assertRefused(self.login("a", "b", cert), "Host key verification failed")
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), ssh_trust.known_hosts(self.manifest))                      # and ssh added nothing to the file

    def test_a_retired_nodes_key_is_refused_under_every_name(self):
        cert = self.certificate()
        for gone in ("c", "e"):                             # retired, and revoked as stolen
            for name in ("a", "b"):
                with self.subTest(name=name, key_of=gone):
                    refused = self.login(name, gone, cert)
                    self.assertRefused(refused, "Host key verification failed")
                    self.assertIn("REVOKED", refused[2].upper())
            # and asked for by its own old name, or by an address: no block of its own in the generated ssh_config,
            # and still this known_hosts and no other (1e's finding: these used to fall to ssh's defaults)
            for name in (gone, "192.0.2.12"):
                with self.subTest(name=name, key_of=gone):
                    refused = self.login(name, gone, cert)
                    self.assertRefused(refused, "Host key verification failed")
                    self.assertIn("REVOKED", refused[2].upper())
        # a LIVE node asked for by its address and not its node ID: its key is filed under the node ID only
        self.assertRefused(self.login("192.0.2.10", "a", cert), "Host key verification failed")
        with open(self.d + "/known_hosts") as f:
            self.assertEqual(f.read(), ssh_trust.known_hosts(self.manifest))                      # nothing was learned on the way

    def test_a_host_that_is_not_in_the_manifest_is_refused(self):
        self.keygen("-t", "ed25519", "-C", "stranger", "-f", self.d + "/host_x")
        self.assertRefused(self.login("a", "x", self.certificate()), "Host key verification failed")

    def test_only_a_certificate_logs_in(self):
        # the bare key, which the CA has certified elsewhere. "(publickey)" is the list of methods the SERVER
        # still offers: no password, no keyboard-interactive (1e's finding: BatchMode alone would also have
        # produced "Permission denied" against a server that offered passwords)
        self.assertRefused(self.login("a", "a"), "Permission denied (publickey).")
        self.assertRefused(self.login("a", "a", options=("PasswordAuthentication=yes", "PreferredAuthentications=password,keyboard-interactive,publickey")),
                           "Permission denied (publickey).")
        relaxed = self.sshd_config("a")
        with open(relaxed) as f:
            text = f.read()
        self.assertEqual(text.count("PasswordAuthentication no"), 1)
        with open(relaxed, "w") as f:                       # the control: a server that DOES offer passwords says so in that list
            f.write(text.replace("PasswordAuthentication no", "PasswordAuthentication yes").replace("AuthenticationMethods publickey", "AuthenticationMethods any"))
        with mock.patch.object(self, "sshd_config", return_value=relaxed):
            self.assertRefused(self.login("a", "a"), "Permission denied (publickey,password).")

    def test_certificates_that_are_not_good_are_refused(self):
        good = self.certificate()
        self.assertLoggedIn(self.login("a", "a", good))
        cases = (("another CA", self.certificate(ca="other_ca")),
                 ("expired", self.certificate(validity="-2h:-1h")),
                 ("not yet valid", self.certificate(validity="+1h:+2h")),
                 ("a principal the account does not list", self.certificate(principal="admin-two")),
                 ("the account's own name, which is not a listed principal", self.certificate(principal=self.USER)))
        for label, cert in cases:
            with self.subTest(label):
                self.assertRefused(self.login("a", "a", cert), "Permission denied")

    def test_a_revoked_certificate_is_refused_and_the_others_are_not(self):
        first, second = self.certificate(), self.certificate()
        self.assertLoggedIn(self.login("a", "a", first))
        with open(self.d + "/revoked.spec", "w") as f:
            f.write("serial: %d\n" % (self.serial - 1))                                           # the first one's
        self.keygen("-k", "-f", self.d + "/regalia-revoked-keys", "-s", self.d + "/ca.pub", "-z", "1", self.d + "/revoked.spec")
        self.assertRefused(self.login("a", "a", first), "Permission denied")
        self.assertLoggedIn(self.login("a", "a", second))
        # serial numbers belong to the CA that signed: the backup CA's certificate with the same number is another certificate
        self.serial -= 2
        twin = self.certificate(ca="backup_ca")                                                  # the backup CA's certificate with that serial
        self.serial += 1
        self.assertLoggedIn(self.login("a", "a", twin))
        self.keygen("-k", "-u", "-f", self.d + "/regalia-revoked-keys", "-s", self.d + "/backup_ca.pub", "-z", "2", self.d + "/revoked.spec")
        self.assertRefused(self.login("a", "a", twin), "Permission denied")                        # added to the list (-u)
        self.assertRefused(self.login("a", "a", first), "Permission denied")                       # and the first is still on it
        self.assertLoggedIn(self.login("a", "a", second))

    def test_without_the_revocation_list_nobody_logs_in(self):
        cert = self.certificate()
        os.unlink(self.d + "/regalia-revoked-keys")
        self.assertRefused(self.login("a", "a", cert), "Permission denied")

    def test_an_account_without_a_principals_file_accepts_nobody(self):
        cert = self.certificate()
        os.unlink("%s/regalia-principals/%s" % (self.d, self.USER))
        self.assertRefused(self.login("a", "a", cert), "Permission denied")

    def test_the_example_as_written_refuses_a_software_key(self):
        # the widening is the only reason the other tests log in: undo it and the same certificate is refused
        cert = self.certificate()
        self.assertLoggedIn(self.login("a", "a", cert))
        self.assertRefused(self.login("a", "a", cert, widen=False), "Permission denied")


if __name__ == "__main__":
    unittest.main()
