"""A KMS host BOOTS through a peer (regalia-kms#66 PoC 6.1, 6.2, 6.5; #67 PoC 7.1, 7.4): a QEMU guest under
UEFI (OVMF) with a software TPM, MEASURED BOOT of a unified kernel image built and signed by
deploy/baremetal/uki.py, whose initrd is built by dracut with deploy/baremetal/initrd/dracut/90regalia-unlock
(the same for every host). Its disk: an ESP with the image and the host's credentials (loader/credentials,
measured by systemd-stub into PCR 12) and a GPT partition labelled regalia-root, a LUKS2 volume. The peers
expect PCR 7, PCR 11 per boot phase (the build record) and PCR 12 (deploy/baremetal/espcreds.py). Run by e2e/unlock-boot-qemu.sh, which builds the guest and names its directory
in REGALIA_BOOT_DIR. Nowhere else: it needs root, QEMU, and network namespaces.

The peers are those of tests/test_baremetal_unlock.py's OnSwtpm (real EKs and AKs, responses signed by
their software TPMs), here each in a network namespace of its own with the host firewall and the boot
mesh of e2e/wg-boot-netns.sh. The guest's TPM is the software TPM `a`, handed to QEMU."""
import base64
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

from deploy.baremetal import attest, bootnet, espcreds, firewall, sitecfg, uki, unlock
import tests.test_baremetal_unlock as tub

BOOT = os.environ.get("REGALIA_BOOT_DIR", "")
UNDERLAY = {"a": "192.0.2.10", "b": "198.51.100.7", "c": "198.51.100.9"}
TUNNEL = {"a": "10.89.0.1", "b": "10.89.0.2", "c": "10.89.0.3"}
# systemd sees the systemd-recovery token in the header and asks for the recovery key by that name, naming
# the disk by its label when it has one ("for disk regalia-root (root)")
# ("recovery key" when that is the only kind of keyslot it knows of, "passphrase or recovery key" otherwise)
PROMPT = re.compile(rb"Please enter (?:passphrase or )?(?:recovery key|passphrase) for disk (?:root|regalia-root \(root\))")
OVMF = os.environ.get("REGALIA_OVMF", "/usr/share/OVMF")
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
                self.keys[node, kind] = (private, base64.b64decode(public).hex())
        super().setUp()                                     # the three TPMs with their AKs, the manifest, the peers b and c
        self.image = BOOT + "/disk.img"
        self.disk = None                                    # the LUKS2 partition, through a loop device while the guest is off
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
    def partition(self, number):
        """A partition of the guest's disk as a block device on this machine, while the guest is off. The caller
        detaches it; a cleanup does too, only if it is still this image's (a freed loop name may be another's)."""
        loop = run(["losetup", "--find", "--show", "--partscan", self.image], capture_output=True, text=True, check=True).stdout.strip()
        def detach():
            if os.path.realpath(run(["losetup", "-n", "-O", "BACK-FILE", loop], capture_output=True, text=True).stdout.strip() or "/") == os.path.realpath(self.image):
                run(["losetup", "-d", loop], capture_output=True)
        self.addCleanup(detach)
        for _ in range(50):
            if os.path.exists("%sp%d" % (loop, number)):
                break
            time.sleep(0.1)
        return loop, "%sp%d" % (loop, number)

    def esp(self, named):
        """Puts exactly these credentials ({name: bytes}) in the ESP's loader/credentials, as <name>.cred, and
        returns the files as systemd-stub will read them. Nothing else changes on the ESP."""
        loop, part = self.partition(1)
        mnt = self.d + "/esp"
        os.makedirs(mnt, exist_ok=True)
        mounted = run(["mount", "-t", "vfat", part, mnt], capture_output=True).returncode == 0
        try:
            self.assertTrue(mounted, "the ESP did not mount")
            where = mnt + "/loader/credentials"
            for name in os.listdir(where):
                os.unlink(os.path.join(where, name))
            files = {name + ".cred": content for name, content in named.items()}
            for name, content in files.items():
                with open(os.path.join(where, name), "wb") as f:
                    f.write(content)
        finally:
            unmounted = not mounted or run(["umount", mnt], capture_output=True).returncode == 0
            run(["losetup", "-d", loop], capture_output=True)
        self.assertTrue(unmounted, "the ESP did not unmount")
        return files

    def boot(self, label, credentials=None, enrol_disk=None, recovery=False, timeout=None, smbios=None):
        """One boot of the guest under OVMF, to power-off, with `credentials` on its ESP. Returns what its
        console said. With `recovery`, the recovery key is typed whenever the console asks for a passphrase."""
        self.on_esp = self.esp(credentials or {})
        variables = "%s/vars-%s.fd" % (self.d, label)
        shutil.copyfile(OVMF + "/OVMF_VARS_4M.fd", variables)
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
                "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=%s/OVMF_CODE_4M.fd" % OVMF,
                "-drive", "if=pflash,format=raw,unit=1,file=" + variables,
                "-drive", "file=%s,format=raw,if=virtio" % self.image,
                "-netdev", "tap,id=n0,ifname=tap0,script=no,downscript=no", "-device", "virtio-net-pci,netdev=n0",
                "-chardev", "socket,id=chrtpm,path=" + ctrl, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"]
        if enrol_disk:
            argv += ["-drive", "file=%s,format=raw,if=virtio" % enrol_disk]
        for name, content in sorted((smbios or {}).items()):        # SMBIOS type 11: a channel the firmware owns
            path = "%s/smbios-%s-%s" % (self.d, label, name)
            with open(path, "w") as f:
                f.write("io.systemd.credential.binary:%s=%s" % (name, base64.b64encode(content).decode()))
            argv += ["-smbios", "type=11,path=" + path]
        qemu = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.processes.append(qemu)
        said, answered, started = b"", 0, time.monotonic()
        deadline, self.prompted_after = started + timeout, None
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
                    if prompts and self.prompted_after is None:
                        self.prompted_after = time.monotonic() - started
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
        with open(BOOT + "/initrd.pub", "rb") as f:
            initrd_public = f.read()
        for name, content in (("local.bin", local), ("wg-boot.key", wg_private.encode() + b"\n"), ("initrd.pub", initrd_public)):
            with open(os.open("%s/%s" % (mnt, name), os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
                f.write(content)
        self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        return image, mnt

    def test_a_host_boots_through_a_peer_and_with_no_peer_it_asks_for_the_recovery_key(self):
        # boot 1, ENROLMENT: nothing is enrolled and no credential is given. The client has no configuration and
        # gives nothing, the console asks, the recovery key opens the volume (PoC 6.5: the manual path needs no
        # peer and no credential), and the running guest seals the two boot credentials to its own TPM and
        # reports the PCRs this image boots with.
        local = os.urandom(32)
        image, mnt = self.enrolment_disk(local, self.keys["a", "boot"][0])
        said = self.boot("1-enrolment", enrol_disk=image, recovery=True)
        self.assertRegex(said, PROMPT.pattern.decode())
        # with no file on the ESP the two units do not start (a path that is not there is fatal), and the console
        # asks promptly: nothing waits on the socket for a client that never came
        print("boot 1: the console asked %.0f s after the guest started" % self.prompted_after, file=sys.stderr)
        self.assertLess(self.prompted_after, 120)
        self.assertIn("REGALIA-E2E-ENROLLED", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        self.assertEqual(run(["mount", "-o", "loop,ro", image, mnt], capture_output=True).returncode, 0)
        def text(name):
            with open("%s/%s" % (mnt, name)) as f:
                return "".join(f.read().split())
        sealed = {name: text(name) for name in ("unlock-local.cred", "wg-boot.cred")}
        pcrs = {str(i): text("pcr%d" % i).lower() for i in (7, 11, 12)}
        self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        # sealed to PCR 7 and to the image's signed PCR 11 policy: systemd's key type for the TPM with a public key
        self.assertEqual(unlock.local_key_type(sealed["unlock-local.cred"]), "tpm2-with-public-key")
        print("the guest's PCRs once booted: 7=%s 11=%s 12=%s" % (pcrs["7"], pcrs["11"], pcrs["12"]), file=sys.stderr)
        # MEASURED BOOT: the stub and systemd measured what the build record says, and an empty ESP left PCR 12 alone
        with open(BOOT + "/e2e.record.json") as f:
            record = json.load(f)
        # the image's own command line (signed, in PCR 11) stops systemd importing any credential, from any source
        with open(BOOT + "/e2e.efi", "rb") as f:
            cmdline = dict(uki.sections(f.read()))[".cmdline"].decode()
        self.assertIn("systemd.import_credentials=no", cmdline.split())
        self.assertEqual(pcrs["11"], record["pcr11"]["system"])
        self.assertEqual(pcrs["12"], espcreds.ZERO)

        # the peers take the guest's PCR 7, the image's PCR 11 per phase and the PCR 12 of the host's credentials
        # as reference, and each gives a path its half
        def reference(pcr12):
            # one accepted set, as measurements.bind() gives it: PCR 7 and 12 in every phase, PCR 11 per phase
            return {"accepted": [{"label": "e2e", "tpm_firmware_version": self.reference["tpm_firmware_version"],
                                  "pcrs": {"7": pcrs["7"], "12": pcr12}, "phases": {phase: {"11": record["pcr11"][phase]} for phase in attest.PHASES}}]}
        loop, self.disk = self.partition(2)
        for peer in ("b", "c"):
            enrolment = unlock.Enrolment("a")
            wrapped = unlock.contribute(self.contributions[peer], self.m1, peer, "a", enrolment.public, enrolment.fingerprint)
            epoch, secret = enrolment.open(wrapped, peer)
            unlock.enrol_path(self.disk, "a", peer, epoch, local, sealed["unlock-local.cred"], secret, tub.RECOVERY, run)
        del local, secret
        self.assertTrue(unlock.judge_tokens(unlock.luks_meta(self.disk, run), "a", ["b", "c"])[0])
        run(["losetup", "-d", loop], capture_output=True)

        # what the host gives its initrd from now on, as system credentials (on a host: on the ESP, written
        # after each accepted manifest; the image itself is unchanged)
        cfg = self.site("a")
        device = "/dev/disk/by-partlabel/regalia-root"
        credentials = {
            "regalia.unlock-local": sealed["unlock-local.cred"].encode() + b"\n", "regalia.wg-boot-key": sealed["wg-boot.cred"].encode() + b"\n",
            "regalia.unlock-config": json.dumps(unlock.boot_config(self.m1, "a", device, [7, 11, 12], bootnet.unlock_endpoints(cfg, self.m1))).encode(),
            "regalia.wg-boot-conf": bootnet.boot_wg_conf(cfg, self.m1).encode(), "regalia.boot-nft": bootnet.boot_ruleset(cfg, self.m1).encode(),
            "regalia.boot-env": ("BOOT_NIC=eth0\nBOOT_ADDRESS=%s/32\nBOOT_GATEWAY=\nBOOT_TUNNEL=%s\n" % (UNDERLAY["a"], TUNNEL["a"])).encode()}

        expected = espcreds.record({name + ".cred": content for name, content in credentials.items()})

        # boot 1b, A SEALED CREDENTIAL THAT DOES NOT DECRYPT (another machine's, or damaged): the real client cannot
        # start, the relay on the key socket gives nothing, and the console asks, promptly (#66)
        broken = dict(credentials, **{"regalia.unlock-local": b"bm90IGEgY3JlZGVudGlhbA==\n"})
        self.reference = reference(espcreds.pcr12({n + ".cred": c for n, c in broken.items()}))
        said = self.boot("1b-undecryptable", broken, recovery=True)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertIn("nothing is given, and the console asks for the recovery key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        print("boot 1b: the console asked %.0f s after the guest started" % self.prompted_after, file=sys.stderr)
        self.assertLess(self.prompted_after, 120)

        # boot 2, UNATTENDED: nobody types anything
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2-unattended", credentials)
        self.assertNotRegex(said, PROMPT.pattern.decode())
        gave = re.search(r"regalia-unlock: gave the key of %s for keyslot ([12]), through ([bc])" % re.escape(device), said)
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
        # PCR 12 is what espcreds computes from the ESP's files, and nothing moved it after the initrd
        booted = re.search(r"REGALIA-E2E-PCRS 7=(\S+) 11=(\S+) 12=(\S+)", said)
        self.assertIsNotNone(booted)
        self.assertEqual([v.lower() for v in booted.groups()], [pcrs["7"], record["pcr11"]["system"], expected["pcr12"]])
        print("PCR 12 with the host's six credentials: %s, as espcreds computes it" % expected["pcr12"], file=sys.stderr)

        # boot 2b, A CREDENTIAL FROM SMBIOS (which the firmware owns, and nothing the peers attest measures): a drop-in
        # for the unlock client that would print a marker. systemd imports no credential, so it is not acted on, and
        # the unlock goes on as in boot 2 (PCR 12 does not see SMBIOS: this boot is NOT refused by the peers).
        dropin = b"[Service]\nExecStartPre=/bin/sh -c 'echo REGALIA-E2E-PLANTED-RAN > /dev/console'\n"
        said = self.boot("2b-smbios", credentials, smbios={"systemd.unit-dropin.regalia-unlock.service": dropin})
        self.assertNotIn("REGALIA-E2E-PLANTED-RAN", said)
        self.assertIsNotNone(re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said))
        self.assertNotRegex(said, PROMPT.pattern.decode())
        if "skipping importing of credentials" in said:
            print("boot 2b: systemd said it imports no credential", file=sys.stderr)

        # boots 3-5, A PLANTED CREDENTIAL: each adds one file to the ESP under a name systemd in the initrd acts on
        # (these are plain, so systemd ignores them as undecryptable; what matters here is that ANY extra file
        # changes PCR 12). PCR 7 and 11 are unchanged, PCR 12 is what espcreds computes for the seven files, every
        # peer refuses the quote, nothing is given, the console asks.
        planted = {"systemd.unit-dropin.regalia-unlock.service": b"[Service]\nEnvironment=PLANTED=1\n",
                   "systemd.extra-unit.regalia-planted.service": b"[Service]\nExecStart=/bin/true\n",
                   "tmpfiles.extra": b"f /run/regalia-planted - - - - planted\n"}
        for n, (name, content) in enumerate(sorted(planted.items()), 3):
            with self.subTest(planted=name):
                since = len(self.events)
                said = self.boot("%d-planted" % n, dict(credentials, **{name: content}), recovery=True)
                self.assertIn("the disk stays locked", said)
                shown = re.search(r"REGALIA-E2E-PCRS 7=(\S+) 11=(\S+) 12=(\S+)", said)
                self.assertIsNotNone(shown)
                self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], record["pcr11"]["system"], espcreds.pcr12(self.on_esp)])
                self.assertNotEqual(shown.group(3).lower(), expected["pcr12"])
                self.assertRegex(said, PROMPT.pattern.decode())
                outcomes = {(e["event"], e["outcome"]) for e in self.events[since:]}
                self.assertNotIn(("unlock", "ALLOW"), outcomes)
                refusals = [e["reason"] for e in self.events[since:] if e["outcome"] == "DENY"]
                self.assertTrue(refusals and all("PCR" in r for r in refusals), refusals)
                print("planted %s: refused (%s)" % (name, refusals[0]), file=sys.stderr)

        # boot 6, NO PEER: the client gives nothing after its bounded rounds, the console asks, the recovery key opens
        for peer in ("b", "c"):
            self.ip("ip", "link", "set", "eth0", "down", ns=self.peer_ns[peer])
        since = len(self.events)
        said = self.boot("6-no-peer", credentials, recovery=True)
        self.assertIn("the disk stays locked: no peer helped in 5 rounds", said)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertLess(said.index("the disk stays locked"), re.search(PROMPT.pattern.decode(), said).start())
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertEqual(self.events[since:], [])


if __name__ == "__main__":
    unittest.main()
