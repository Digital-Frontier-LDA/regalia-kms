"""A KMS host BOOTS through a peer (regalia-kms#66 PoC 6.1, 6.2, 6.5; #67 PoC 7.1, 7.4): a QEMU guest with a
software TPM, a real initrd built by dracut with deploy/baremetal/initrd/dracut/90regalia-unlock, and its
whole disk a LUKS2 volume. Run by e2e/unlock-boot-qemu.sh, which builds the guest and names its directory
in REGALIA_BOOT_DIR. Nowhere else: it needs root, QEMU, and network namespaces.

The peers are those of tests/test_baremetal_unlock.py's OnSwtpm (real EKs and AKs, responses signed by
their software TPMs), here each in a network namespace of its own with the host firewall and the boot
mesh of e2e/wg-boot-netns.sh. The guest's TPM is the software TPM `a`, handed to QEMU."""
import hashlib
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest

from deploy.baremetal import attest, bootnet, firewall, sitecfg, unlock
import tests.test_baremetal_unlock as tub

BOOT = os.environ.get("REGALIA_BOOT_DIR", "")
UNDERLAY = {"a": "192.0.2.10", "b": "198.51.100.7", "c": "198.51.100.9"}
TUNNEL = {"a": "10.89.0.1", "b": "10.89.0.2", "c": "10.89.0.3"}
# systemd sees the systemd-recovery token in the header and asks for the recovery key by that name
# ("recovery key" when that is the only kind of keyslot it knows of, "passphrase or recovery key" otherwise)
PROMPT = re.compile(rb"Please enter (?:passphrase or )?(?:recovery key|passphrase) for disk root")
CMDLINE = ("root=/dev/mapper/root rw console=ttyS0,115200 net.ifnames=0 systemd.journald.forward_to_console=1 "
           "rd.shell=0 rd.emergency=poweroff panic=30 loglevel=4")
run = tub.run


@unittest.skipUnless(os.environ.get("REGALIA_EXPECT_QEMU") == "1", "needs a guest built by e2e/unlock-boot-qemu.sh")
class OnQemu(tub.OnSwtpm):
    # the fixtures of OnSwtpm are reused, not its tests
    test_tpm_plus_one_peer_opens_the_disk_and_a_retired_image_a_stolen_disk_or_a_revoked_node_does_not = None
    test_systemd_cryptsetup_takes_the_key_from_the_socket_and_gets_nothing_when_no_peer_helps = None

    def setUp(self):
        self.assertTrue(os.path.exists(BOOT + "/disk.img"), "REGALIA_BOOT_DIR must hold the guest e2e/unlock-boot-qemu.sh built")
        self.keys = {}
        for node in "abc":                                  # a WG-BOOT and a WG-SERVICE pair each, as the manifest lists them
            for kind in ("boot", "service"):
                private = run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
                public = run(["wg", "pubkey"], input=private.encode(), capture_output=True, check=True).stdout.strip()
                self.keys[node, kind] = (private, __import__("base64").b64decode(public).hex())
        super().setUp()                                     # the three TPMs with their AKs, the manifest, the peers b and c
        with open(BOOT + "/uuid") as f:
            self.uuid = f.read().strip()
        self.disk = BOOT + "/disk.img"
        # the guest's TPM is `a`: provisioned above through its socket, from here on QEMU's
        self.on("a", attest.tpm2, "shutdown", "-c")
        os.kill(self.pids.pop("a"), 15)
        self.namespaces, self.processes = [], []
        self.addCleanup(self.teardown_network)
        self.network()

    def manifest(self, previous, **states):
        manifest = super().manifest(previous, **states)
        for node in manifest["nodes"]:
            node["wg_boot_pub"], node["wg_service_pub"] = self.keys[node["node_id"], "boot"][1], self.keys[node["node_id"], "service"][1]
        return manifest

    def site(self, node):
        return sitecfg.validate({
            "schema": sitecfg.SCHEMA, "site": "site-" + node, "host_ipv4": UNDERLAY[node], "kms_port": 8443, "ssh_port": 22,
            "client_cidrs": ["198.18.0.0/24"], "monitoring_cidrs": ["198.18.1.1/32"], "admin_cidrs": ["198.18.2.0/28"],
            "outbound": [{"name": "audit", "cidr": "198.18.3.1/32", "proto": "tcp", "port": 6514}, {"name": "ntp", "cidr": "198.18.3.2/32", "proto": "udp", "port": 123}],
            "boot_mesh": {"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": TUNNEL[node], "unlock_port": 7443,
                          "peers": [{"node_id": p, "underlay": UNDERLAY[p], "address": TUNNEL[p]} for p in "abc" if p != node]},
            "service_mesh": None})

    # -- the network: a bridge and QEMU's tap in one namespace, each peer in its own --
    def ip(self, *argv, ns=None, stdin=None):
        done = run((["ip", "netns", "exec", ns] if ns else []) + list(argv), input=stdin, capture_output=True)
        self.assertEqual(done.returncode, 0, "%s: %s" % (" ".join(argv), done.stderr.decode(errors="replace")))
        return done.stdout

    def network(self):
        tag = "%d" % os.getpid()
        self.switch = "ru-sw-" + tag
        self.ip("ip", "netns", "add", self.switch)
        self.namespaces.append(self.switch)
        self.ip("ip", "link", "add", "br0", "type", "bridge", ns=self.switch)
        self.ip("ip", "link", "set", "br0", "up", ns=self.switch)
        self.ip("ip", "tuntap", "add", "tap0", "mode", "tap", ns=self.switch)
        self.ip("ip", "link", "set", "tap0", "master", "br0", "up", ns=self.switch)
        self.peer_ns = {}
        for peer in ("b", "c"):
            ns = self.peer_ns[peer] = "ru-%s-%s" % (peer, tag)
            self.ip("ip", "netns", "add", ns)
            self.namespaces.append(ns)
            veth = "v%s%s" % (peer, tag[-8:])
            self.ip("ip", "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", ns)
            self.ip("ip", "link", "set", veth, "netns", self.switch)
            self.ip("ip", "link", "set", veth, "master", "br0", "up", ns=self.switch)
            for argv in (["ip", "link", "set", "lo", "up"], ["ip", "link", "set", "eth0", "up"], ["ip", "addr", "add", UNDERLAY[peer] + "/32", "dev", "eth0"],
                         ["ip", "route", "add", "default", "dev", "eth0"], ["ip", "link", "add", "wg-unlock", "type", "wireguard"]):
                self.ip(*argv, ns=ns)
            cfg = self.site(peer)
            self.apply_wireguard(peer)
            for argv in (["ip", "addr", "add", TUNNEL[peer] + "/32", "dev", "wg-unlock"], ["ip", "link", "set", "wg-unlock", "up"],
                         ["ip", "route", "add", "10.89.0.0/24", "dev", "wg-unlock"]):
                self.ip(*argv, ns=ns)
            self.ip("nft", "-f", "-", ns=ns, stdin=firewall.render(cfg).encode())
            listener = self.listen_in(ns, TUNNEL[peer], cfg["boot_mesh"]["unlock_port"])
            self.addCleanup(listener.close)
            threading.Thread(target=unlock.serve, args=(self.served[peer], listener), daemon=True,
                             kwargs={"caller": lambda address, peer=peer, cfg=cfg: bootnet.caller_of(cfg, self.stores[peer].load())(address)}).start()

    def apply_wireguard(self, peer):
        """The peer's WireGuard list under the manifest it holds now, with its key added in memory."""
        conf = bootnet.with_key(bootnet.peer_wg_conf(self.site(peer), self.stores[peer].load()), self.keys[peer, "service"][0])
        self.ip("wg", "syncconf", "wg-unlock", "/dev/stdin", ns=self.peer_ns[peer], stdin=conf.encode())

    def listen_in(self, ns, address, port):
        """A listening socket made inside a network namespace (a thread joins it, makes the socket, and ends)."""
        made = []

        def make():
            with open("/run/netns/" + ns) as f:
                os.setns(f.fileno(), os.CLONE_NEWNET)
            made.append(socket.create_server((address, port)))
        thread = threading.Thread(target=make)
        thread.start()
        thread.join()
        self.assertTrue(made, "no listener in " + ns)
        return made[0]

    def teardown_network(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
        for ns in self.namespaces:
            pids = run(["ip", "netns", "pids", ns], capture_output=True, text=True).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), 9)
                except OSError:
                    pass
            run(["ip", "netns", "del", ns], capture_output=True)

    # -- the guest --
    def initrd(self, label, files):
        """The initrd dracut built, with the files that differ per host and per manifest appended as a
        second archive (on a host they are under /etc/regalia when the initrd is built)."""
        tree = "%s/cpio-%s" % (self.d, label)
        for path, content in files.items():
            os.makedirs(os.path.dirname(tree + "/" + path), exist_ok=True)
            with open(os.open(tree + "/" + path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
                f.write(content)
        names = run(["find", ".", "-mindepth", "1", "-print0"], cwd=tree, capture_output=True, check=True).stdout
        archive = run(["cpio", "--null", "-o", "-H", "newc", "--owner", "0:0", "--quiet"], cwd=tree, input=names, capture_output=True, check=True).stdout
        out = "%s/initrd-%s" % (self.d, label)
        with open(BOOT + "/initrd", "rb") as base, open(out, "wb") as f:
            shutil.copyfileobj(base, f)
            # the kernel looks for the next archive at a 4-byte boundary and skips zeros before it: without
            # the padding it reads "invalid magic at start of compressed archive" and drops the second one
            f.write(bytes(-f.tell() % 4))
            f.write(archive)
        return out

    def boot(self, label, initrd, enrol_disk=None, recovery=False, timeout=None):
        """One boot of the guest, to power-off. Returns what its console said. With `recovery`, the recovery
        key is typed whenever the console asks for a passphrase."""
        kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
        timeout = timeout or (600 if kvm else 2400)
        ctrl = self.d + "/a.ctrl"
        if os.path.exists(ctrl):
            os.unlink(ctrl)
        tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=%s/tpm-a" % self.d, "--ctrl", "type=unixio,path=" + ctrl],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(tpm)
        for _ in range(100):
            if os.path.exists(ctrl):
                break
            time.sleep(0.1)
        argv = ["ip", "netns", "exec", self.switch, "qemu-system-x86_64", "-machine", "q35,accel=" + ("kvm" if kvm else "tcg"),
                "-cpu", "host" if kvm else "max", "-m", "1536", "-smp", "2", "-display", "none", "-no-reboot", "-serial", "stdio",
                "-kernel", BOOT + "/vmlinuz", "-initrd", initrd, "-append", CMDLINE,
                "-drive", "file=%s,format=raw,if=virtio" % self.disk,
                "-netdev", "tap,id=n0,ifname=tap0,script=no,downscript=no", "-device", "virtio-net-pci,netdev=n0",
                "-chardev", "socket,id=chrtpm,path=" + ctrl, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"]
        if enrol_disk:
            argv += ["-drive", "file=%s,format=raw,if=virtio" % enrol_disk]
        qemu = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.processes.append(qemu)
        said, answered, deadline = b"", 0, time.monotonic() + timeout
        with open("%s/console-%s.log" % (BOOT, label), "wb") as log:
            while True:
                ready, _, _ = select.select([qemu.stdout], [], [], 1)
                if ready:
                    chunk = os.read(qemu.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    said += chunk
                    log.write(chunk)
                    log.flush()
                    prompts = len(PROMPT.findall(said))
                    if recovery and prompts > answered:
                        answered = prompts
                        time.sleep(1)
                        qemu.stdin.write(tub.RECOVERY + b"\n")
                        qemu.stdin.flush()
                elif qemu.poll() is not None:
                    break
                if time.monotonic() > deadline:
                    qemu.kill()
                    said += b"\n[the test's time limit of %d s was reached: the guest was killed]\n" % timeout
                    break
        qemu.wait(30)
        tpm.terminate()
        tpm.wait(30)
        text = said.decode(errors="replace")
        print("\n----- boot %s (%s): %d lines of console; the lines that matter:" % (label, "KVM" if kvm else "TCG", text.count("\n")), file=sys.stderr)
        for line in text.splitlines():
            if re.search(r"REGALIA-E2E|regalia-unlock|wg-boot|Please enter|time limit|cryptsetup\[", line):
                print("    " + line.strip()[:300], file=sys.stderr)
        return text

    def enrolment_disk(self, local, wg_private):
        """The second disk of the enrolment boot: what the running guest seals to its own TPM."""
        image, mnt = self.d + "/enrol.img", self.d + "/enrol"
        with open(image, "wb") as f:
            f.truncate(16 * 1024 * 1024)
        os.mkdir(mnt)
        self.addCleanup(lambda: run(["umount", mnt], capture_output=True))     # if a failure leaves it mounted
        for argv in (["mkfs.ext4", "-q", image], ["mount", "-o", "loop", image, mnt]):
            self.assertEqual(run(argv, capture_output=True).returncode, 0, argv)
        for name, content in (("local.bin", local), ("wg-boot.key", wg_private.encode() + b"\n")):
            with open(os.open("%s/%s" % (mnt, name), os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
                f.write(content)
        self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        return image, mnt

    def test_a_host_boots_through_a_peer_and_with_no_peer_it_asks_for_the_recovery_key(self):
        crypttab = "root UUID=%s %%s luks,x-initrd.attach\n" % self.uuid

        # boot 1, ENROLMENT: nothing is enrolled. The console asks, the recovery key opens the volume
        # (PoC 6.5: the manual path needs no peer and no credential), and the running guest seals the two
        # boot credentials to its own TPM and reports the PCRs this image boots with.
        local = os.urandom(32)
        image, mnt = self.enrolment_disk(local, self.keys["a", "boot"][0])
        said = self.boot("1-enrolment", self.initrd("1", {"etc/crypttab": crypttab % "none"}), enrol_disk=image, recovery=True)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertIn("REGALIA-E2E-ENROLLED", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        self.assertEqual(run(["mount", "-o", "loop,ro", image, mnt], capture_output=True).returncode, 0)
        def text(name):
            with open("%s/%s" % (mnt, name)) as f:
                return "".join(f.read().split())
        sealed = {name: text(name) for name in ("unlock-local.cred", "wg-boot.cred")}
        pcrs = {str(i): text("pcr%d" % i).lower() for i in (7, 11)}
        self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        self.assertEqual(unlock.local_key_type(sealed["unlock-local.cred"]), "tpm2")
        print("the guest's PCRs: 7=%s 11=%s" % (pcrs["7"], pcrs["11"]), file=sys.stderr)

        # the peers take the guest's real measurements as reference, and each gives a path its half
        self.reference = {"tpm_firmware_version": self.reference["tpm_firmware_version"], "pcrs": pcrs}
        for peer in ("b", "c"):
            enrolment = unlock.Enrolment("a")
            wrapped = unlock.contribute(self.contributions[peer], self.m1, peer, "a", enrolment.public, enrolment.fingerprint)
            epoch, secret = enrolment.open(wrapped, peer)
            unlock.enrol_path(self.disk, "a", peer, epoch, local, sealed["unlock-local.cred"], secret, tub.RECOVERY, run)
        del local, secret
        self.assertTrue(unlock.judge_tokens(unlock.luks_meta(self.disk, run), "a", ["b", "c"])[0])

        # what the initrd holds from now on (on a host: /etc/regalia, written after each accepted manifest)
        cfg = self.site("a")
        files = {"etc/crypttab": crypttab % unlock.KEY_SOCKET,
                 "etc/regalia/unlock.json": json.dumps(unlock.boot_config(self.m1, "a", "/dev/vda", [7, 11], bootnet.unlock_endpoints(cfg, self.m1))),
                 "etc/regalia/unlock-local.cred": sealed["unlock-local.cred"] + "\n", "etc/regalia/wg-boot.cred": sealed["wg-boot.cred"] + "\n",
                 "etc/regalia/wg-boot.conf": bootnet.boot_wg_conf(cfg, self.m1), "etc/regalia/boot.nft": bootnet.boot_ruleset(cfg, self.m1),
                 "etc/regalia/boot.env": "BOOT_NIC=eth0\nBOOT_ADDRESS=%s/32\nBOOT_GATEWAY=\nBOOT_TUNNEL=%s\n" % (UNDERLAY["a"], TUNNEL["a"])}
        initrd = self.initrd("2", files)

        # boot 2, UNATTENDED: nobody types anything
        since = len(self.events)
        said = self.boot("2-unattended", initrd)
        self.assertNotRegex(said, PROMPT.pattern.decode())
        gave = re.search(r"regalia-unlock: gave the key of /dev/vda for keyslot ([12]), through ([bc])", said)
        self.assertIsNotNone(gave, "the client did not give the key")
        slot, through = gave.group(1), gave.group(2)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        allowed = [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:] if e["event"] == "unlock"]
        self.assertEqual(allowed, [("unlock", "a", "ALLOW")])
        # after switch-root the running system finds the session the peer recorded, in a directory only root writes
        left = re.search(r"REGALIA-E2E-SESSION dir=(\S+) id=([0-9a-f]{64}) through=(\S+) (\d+)", said)
        self.assertIsNotNone(left, "the booted guest did not report the boot session")
        self.assertEqual((left.group(1), left.group(3), left.group(4)), ("root:root:755", through, slot))
        self.assertEqual(hashlib.sha256(bytes.fromhex(left.group(2))).hexdigest(), self.recorded_session(through)[0])
        # the long-running client did not outlive the initrd: systemd stopped it (the unit's Conflicts=), before the socket closed
        self.assertIn("REGALIA-E2E-CLIENT processes=0", said)
        stopped, closed = said.find("Stopped regalia-unlock.service"), said.find("Closed regalia-unlock.socket")
        self.assertTrue(0 <= stopped < closed, "the client was not stopped before the root filesystem took over")

        # boot 3, NO PEER: the client gives nothing after its bounded rounds, the console asks, the recovery key opens
        for peer in ("b", "c"):
            self.ip("ip", "link", "set", "eth0", "down", ns=self.peer_ns[peer])
        since = len(self.events)
        said = self.boot("3-no-peer", initrd, recovery=True)
        self.assertIn("the disk stays locked: no peer helped in 5 rounds", said)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertLess(said.index("the disk stays locked"), re.search(PROMPT.pattern.decode(), said).start())
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertEqual(self.events[since:], [])


if __name__ == "__main__":
    unittest.main()
