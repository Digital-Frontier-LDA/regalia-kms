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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import attest, bootcreds, bootnet, espcreds, firewall, membership, sitecfg, uki, unlock
import tests.test_baremetal_unlock as tub

BOOT = os.environ.get("REGALIA_BOOT_DIR", "")
UNDERLAY = {"a": "192.0.2.10", "b": "198.51.100.7", "c": "198.51.100.9"}
TUNNEL = {"a": "10.89.0.1", "b": "10.89.0.2", "c": "10.89.0.3"}
# the guest's card, by an address that is NOT QEMU's default for a first card (52:54:00:12:34:56): the boot
# passes only if wg-boot finds the card by its address, not by being the first one
GUEST_MAC = "52:54:00:ab:cd:02"
# systemd sees the systemd-recovery token in the header and asks for the recovery key by that name, naming
# the disk by its label when it has one ("for disk regalia-root (root)")
# ("recovery key" when that is the only kind of keyslot it knows of, "passphrase or recovery key" otherwise)
PROMPT = re.compile(rb"Please enter (?:passphrase or )?(?:recovery key|passphrase) for disk (?:root|regalia-root \(root\))")
OVMF = os.environ.get("REGALIA_OVMF", "/usr/share/OVMF")
run = tub.run


def booted_pcrs(said):
    """The REGALIA-E2E-PCRS line's match, read only after systemd-pcrphase.service measured `ready` (#310): the
    guest says what it saw, and a read before `ready` (the sysinit value, one phase short of the record) fails
    here by name, not later as a PCR 11 mismatch. This proves ORDERING only: the unit runs systemd-pcrextend
    --graceful, which exits successfully without a TPM, so "success" is not proof of the extend; the PCR 11
    comparison that follows is."""
    shown = re.search(r"REGALIA-E2E-PCRS 7=(\S+) 11=(\S+) 12=(\S+)", said)
    if shown:
        phase = re.search(r"REGALIA-E2E-PCRPHASE systemd-pcrphase.service=(.*)", said)
        if not (phase and phase.group(1).split() == ["active", "success"]):       # not `assert`: python -O would drop it
            raise AssertionError("the PCRs were read before systemd-pcrphase measured ready (#310): %s"
                                 % (phase.group(1).strip() if phase else "no phase line"))
    return shown


def after_attempt(n):
    """For boot(recovery=): the recovery key is typed once the client has said how attempt `n` went, so the peers were
    asked before the console's answer opens the volume."""
    return lambda said, elapsed: "regalia-unlock: attempt %d: " % n in said


INITRD_PCR11 = re.compile(r"regalia-unlock: initrd PCR 11 \(sha256\) = ([0-9a-f]{64})")


def initrd_pcr11(said):
    """The initrd-phase PCR 11 the client said on the console (#412), or None."""
    shown = INITRD_PCR11.findall(said)
    return shown[0] if shown else None


def no_shell(test, said):
    """Nothing in the initrd offered a shell (rd.shell=0, rd.emergency=reboot): the console only ever asks for the key."""
    test.assertNotRegex(said, r"Emergency Shell|Rescue Shell|Give root password|emergency mode")


def unattended(test, said):
    """Nobody typed (boot() was given no recovery), yet the root came up: the client's answer opened it. The prompt is
    up all the same, from the start (#70: the client answers beside the console, never in front of it)."""
    test.assertRegex(said, PROMPT.pattern.decode())
    test.assertIn("regalia-unlock: gave the key of ", said)
    test.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)


@unittest.skipUnless(os.environ.get("REGALIA_EXPECT_QEMU") == "1", "needs a guest built by e2e/unlock-boot-qemu.sh")
class OnQemu(tub.OnSwtpm):
    # the fixtures of OnSwtpm are reused, not its tests
    test_tpm_plus_one_peer_opens_the_disk_and_a_retired_image_a_stolen_disk_or_a_revoked_node_does_not = None
    test_systemd_cryptsetup_asks_the_client_answers_and_the_console_is_never_taken_away = None

    # The membership root the image trusts (#156): e2e/unlock-boot-qemu.sh builds the initrd with the TEST root of
    # tests/vectors/highwater-v1.json, whose private key is fixed there (make-highwater-v1.py); the chain on the
    # guest's ESP is signed with it (#66 B3)
    ROOT = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    def signed(self, manifest):
        """An envelope of `manifest`, signed by the root the image trusts."""
        from cryptography.hazmat.primitives import serialization
        public = self.ROOT.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        return {"manifest": manifest, "signature": {"signer": "root", "key": public,
                                                    "sig": self.ROOT.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}

    def setUp(self):
        self.assertTrue(os.path.exists(BOOT + "/disk.img"), "REGALIA_BOOT_DIR must hold the guest e2e/unlock-boot-qemu.sh built")
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "highwater-v1.json")) as f:
            vector_root = json.load(f)["root_public"]
        self.assertEqual(self.signed({})["signature"]["key"], vector_root, "the test root is not the vector's: the image would refuse the chain")
        self.keys = {}
        for node in "abc":                                  # a WG-BOOT and a WG-SERVICE pair each, as the manifest lists them
            for kind in ("boot", "service"):
                private = run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
                public = run(["wg", "pubkey"], input=private.encode(), capture_output=True, check=True).stdout.strip()
                self.keys[node, kind] = (private, base64.b64decode(public).hex())
        super().setUp()                                     # the three TPMs with their AKs, the manifest, the peers b and c
        self.image = BOOT + "/disk.img"
        self.disk = None                                    # the LUKS2 partition, through a loop device while the guest is off
        # #66 B3: the chain the guest's ESP carries, signed by the root the image trusts, and the guest's TPM anchored
        # to it (as enrolment leaves a host: the high-water at the chain's epoch, its manifest recorded), so the
        # initrd's render verifies it against the TPM and refuses any other chain, however well signed
        self.chain = [self.signed(self.m1)]
        anchor = membership.HighWater("0x1500016", tcti=self.tcti["a"], lock_path=self.d + "/a-hw.lock")
        anchor.define()
        anchor.anchor(1, membership.Store._digests([membership.accept_chain(None, self.chain, self.signed({})["signature"]["key"])]))
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
            "outbound": [{"name": "audit", "cidr": "198.18.3.1/32", "proto": "tcp", "port": 6514}],
            "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["198.18.3.2/32"]}, {"name": "nts-b.lab", "cidrs": ["198.18.3.3/32"]}]},
            "boot_mesh": {"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": TUNNEL[node], "unlock_port": 7443,
                          "nic_mac": GUEST_MAC, "prefix": 32, "gateway": None,
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

    def esp(self, named, image="e2e"):
        """Puts exactly these credentials ({name: bytes}) in the ESP's loader/credentials, as <name>.cred, and
        `image` (<image>.efi of REGALIA_BOOT_DIR, signed by e2e/unlock-boot-qemu.sh) as the one boot image, and
        the membership chain (self.chain, #66 B3) at EFI/regalia/membership.json, and returns the credential
        files as systemd-stub will read them. Nothing else changes on the ESP."""
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
            shutil.copyfile("%s/%s.efi" % (BOOT, image), mnt + "/EFI/BOOT/BOOTX64.EFI")
            os.makedirs(mnt + "/EFI/regalia", exist_ok=True)
            with open(mnt + "/" + bootcreds.CHAIN_ON_ESP, "wb") as f:
                f.write(membership.canonical(self.chain))
        finally:
            unmounted = not mounted or run(["umount", mnt], capture_output=True).returncode == 0
            run(["losetup", "-d", loop], capture_output=True)
        self.assertTrue(unmounted, "the ESP did not unmount")
        return files

    def boot(self, label, credentials=None, enrol_disk=None, recovery=False, timeout=None, smbios=None, smbios_strings=(), image="e2e",
             watch=None):
        """One boot of the guest under OVMF, to power-off, with `credentials` and `image` on its ESP. Returns what its
        console said. With `recovery`, the recovery key is typed whenever the console asks for a passphrase; when it is
        a function of (console so far, seconds since start), only once that says so (and what it returns, when that is
        bytes, is typed instead). `watch`, a function of the same, is
        called as the console grows (to change the network under the guest), and the times it returned true are kept in
        self.watched."""
        self.on_esp = self.esp(credentials or {}, image)
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
                "-netdev", "tap,id=n0,ifname=tap0,script=no,downscript=no", "-device", "virtio-net-pci,netdev=n0,mac=%s" % GUEST_MAC,
                "-chardev", "socket,id=chrtpm,path=" + ctrl, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"]
        if enrol_disk:
            argv += ["-drive", "file=%s,format=raw,if=virtio" % enrol_disk]
        for name, content in sorted((smbios or {}).items()):        # SMBIOS type 11: a channel the firmware owns
            path = "%s/smbios-%s-%s" % (self.d, label, name)
            with open(path, "w") as f:
                f.write("io.systemd.credential.binary:%s=%s" % (name, base64.b64encode(content).decode()))
            argv += ["-smbios", "type=11,path=" + path]
        for n, string in enumerate(smbios_strings):                  # SMBIOS type 11 strings as they are, e.g. for systemd-stub
            path = "%s/smbios-%s-string-%d" % (self.d, label, n)
            with open(path, "w") as f:
                f.write(string)
            argv += ["-smbios", "type=11,path=" + path]
        qemu = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.processes.append(qemu)
        said, answered, started = b"", 0, time.monotonic()
        deadline, self.prompted_after, self.watched = started + timeout, None, []
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
                    elapsed = time.monotonic() - started
                    text = said.decode(errors="replace") if watch or callable(recovery) else ""   # what boot() returns
                    if watch and watch(text, elapsed):
                        self.watched.append(elapsed)
                    typed = recovery and prompts > answered and (recovery is True or recovery(text, elapsed))
                    if typed:
                        answered = prompts
                        time.sleep(1)
                        qemu.stdin.write((typed if isinstance(typed, bytes) else tub.RECOVERY) + b"\n")
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
        firmware = self.reference["tpm_firmware_version"]          # (the reference is replaced below; its firmware stays)

        with open(BOOT + "/e2e-old.record.json") as f:
            older = json.load(f)                                    # the second signed image of the same build (#135)
        self.assertNotEqual(older["pcr11"], record["pcr11"])

        def reference(pcr12, images=(("e2e", record),)):
            # an accepted set per image, as measurements.bind() gives it: PCR 7 and 12 in every phase, PCR 11 per phase
            return {"accepted": [{"label": label, "tpm_firmware_version": firmware,
                                  "pcrs": {"7": pcrs["7"], "12": pcr12}, "phases": {phase: {"11": built["pcr11"][phase]} for phase in attest.PHASES}}
                                 for label, built in images]}
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
            # the one measured file of the host's own (#66 B3): its site; the rest the initrd renders from the chain
            "regalia.site": bootcreds.site_document(cfg, device)}

        expected = espcreds.record({name + ".cred": content for name, content in credentials.items()})

        # boot 1b, A SEALED CREDENTIAL THAT DOES NOT DECRYPT (another machine's, or damaged): the client cannot
        # start, and the console asks, promptly: it asks from the start whatever the client does (#66, #70)
        broken = dict(credentials, **{"regalia.unlock-local": b"bm90IGEgY3JlZGVudGlhbA==\n"})
        self.reference = reference(espcreds.pcr12({n + ".cred": c for n, c in broken.items()}))
        said = self.boot("1b-undecryptable", broken, recovery=True)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        print("boot 1b: the console asked %.0f s after the guest started" % self.prompted_after, file=sys.stderr)
        self.assertLess(self.prompted_after, 120)

        # boot 2, UNATTENDED: nobody types anything
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2-unattended", credentials)
        unattended(self, said)
        # #75 tier Q, Q1: the client says the initrd-phase PCR 11 before it quotes (#412), and it is the value the HOST
        # computed from the image's build record, never one the guest computes. Equality, not just a line: a phase that
        # did not run (systemd-pcrphase-initrd) would show the pre-phase value
        self.assertEqual(initrd_pcr11(said), record["pcr11"]["initrd"])
        gave = re.search(r"regalia-unlock: gave the key of %s for keyslot ([12]), through ([bc])" % re.escape(device), said)
        self.assertIsNotNone(gave, "the client did not give the key")
        slot, through = gave.group(1), gave.group(2)
        # #66 B3: the boot configuration was rendered in the initrd, from the chain on the ESP, verified against the TPM
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 1 (TPM high-water 1)", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertIn("REGALIA-E2E-IMPORT credentials-imported=no", said)      # the first layer, seen working
        allowed = [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:] if e["event"] == "unlock"]
        self.assertEqual(allowed, [("unlock", "a", "ALLOW")])
        # after switch-root the running system finds the session the peer recorded, in a directory only root writes
        left = re.search(r"REGALIA-E2E-SESSION dir=(\S+) id=([0-9a-f]{64}) through=(\S+) (\d+)", said)
        self.assertIsNotNone(left, "the booted guest did not report the boot session")
        self.assertEqual((left.group(1), left.group(3), left.group(4)), ("root:root:755", through, slot))
        self.assertEqual(hashlib.sha256(bytes.fromhex(left.group(2))).hexdigest(), self.recorded_session(through)[0])
        # the client did not outlive the initrd: it stood down when the volume opened, or systemd stopped it (Conflicts=)
        self.assertIn("REGALIA-E2E-CLIENT processes=0", said)
        # and the pages it used are zeroed when freed (#221): the words are signed into the image, and the
        # kernel says it enabled them (a kernel without the options would ignore the words)
        with open(BOOT + "/e2e.efi", "rb") as f:
            signed = dict(uki.sections(f.read()))[".cmdline"].decode().split()
        self.assertIn("init_on_free=1", signed)
        self.assertIn("init_on_alloc=1", signed)
        meminit = next((l for l in said.splitlines() if "REGALIA-E2E-MEMINIT" in l), "")
        print("boot 2: %s" % meminit.strip(), file=sys.stderr)
        self.assertRegex(meminit, r"heap alloc:on")
        self.assertRegex(meminit, r"heap free:on")
        self.assertRegex(said, r"regalia-unlock: /dev/mapper/root is open: standing down|Stopped regalia-unlock\.service")
        # PCR 12 is what espcreds computes from the ESP's files, and nothing moved it after the initrd
        booted = booted_pcrs(said)
        self.assertIsNotNone(booted)
        self.assertEqual([v.lower() for v in booted.groups()], [pcrs["7"], record["pcr11"]["system"], expected["pcr12"]])
        print("PCR 12 with the host's six credentials: %s, as espcreds computes it" % expected["pcr12"], file=sys.stderr)

        # boot 2e, A FORKED CHAIN (#66 B3): another epoch 1, validly signed by the root the image trusts, in place of the
        # one the TPM recorded (a substituted ESP). The render verifies it against the TPM's anchor and refuses it:
        # nothing is rendered, no peer is asked, and the console's prompt takes the recovery key. PCR 12 is unchanged
        # (the chain is not measured): it is the anchor, not the peers, that refuses it.
        good = self.chain
        self.chain = [self.signed(dict(self.m1, policy_version="forked"))]
        since = len(self.events)
        said = self.boot("2e-forked-chain", credentials, recovery=True)
        self.chain = good
        self.assertRegex(said, r"regalia-unlock: the boot configuration cannot be rendered: CONFLICT")
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        self.assertEqual([e for e in self.events[since:] if e.get("event") == "unlock"], [])

        # boot 2c, AN OLDER SIGNED IMAGE, APPROVED (#135): the same build with one word more on its command line, so
        # another PCR 11, signed by the same keys. The peers' document lists both images; it boots unattended.
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-old", older)))
        since = len(self.events)
        said = self.boot("2c-older-approved", credentials, image="e2e-old")
        unattended(self, said)
        self.assertIsNotNone(re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said))
        self.assertIn("regalia.e2e-image=old", re.search(r"REGALIA-E2E-CMDLINE (.*)", said).group(1).split())
        shown = booted_pcrs(said)
        self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], older["pcr11"]["system"], expected["pcr12"]])
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])

        # boot 2k, #75 TIER Q, Q1: AN IMAGE WHOSE KERNEL DIFFERS (the same kernel with bytes appended: it boots
        # identically, and only its measurement differs). Before it boots: its .linux is e2e's plus the bytes, and they
        # alone change its predicted PCR 11 (not only its command line). Not approved, both peers refuse it for PCR 11;
        # approved as NEXT beside CURRENT, it boots unattended; the client says the initrd-phase PCR 11 its OWN record predicts, and
        # it is booted on the system-phase one. Its signed command line has no journald forwarding (#413): the
        # client's lines reach the console through its unit alone (#412), as on a production console.
        with open(BOOT + "/e2e-k2.record.json") as f:
            other_kernel = json.load(f)
        with open(BOOT + "/e2e.efi", "rb") as f:
            first_parts = uki.measured(f.read())
        with open(BOOT + "/e2e-k2.efi", "rb") as f:
            k2_parts = uki.measured(f.read())
        # e2e-k2 differs from e2e in its kernel AND its command line (no journald forwarding), and PCR 11 measures both. So
        # that the kernel's change is what is under test (regalia-kms-d9 on #415): the appended bytes ARE in the measured
        # .linux section, and they alone change the prediction: with e2e's kernel put back, e2e-k2's PCR 11 is another
        self.assertEqual(k2_parts["linux"], first_parts["linux"] + b"R" * 4096, "the Q1 image's .linux is not e2e's kernel with the 4096 bytes")
        for phase, path in uki.PHASE_PATHS.items():
            self.assertEqual(uki.pcr11(k2_parts, path), other_kernel["pcr11"][phase])           # computed here as uki.py does
            self.assertNotEqual(uki.pcr11(dict(k2_parts, linux=first_parts["linux"]), path), other_kernel["pcr11"][phase],
                                "the kernel's bytes do not change the Q1 image's PCR 11 (%s)" % phase)
            self.assertNotEqual(other_kernel["pcr11"][phase], record["pcr11"][phase], "Q1's image predicts the first image's PCR 11 (%s)" % phase)
        self.assertNotIn("systemd.journald.forward_to_console=1", k2_parts["cmdline"].decode().split())

        # first NOT approved: the document lists the current image only. Both peers refuse it, naming PCR 11 (the
        # security half: a different kernel is refused until the root approves it; 2d refuses a RETIRED image)
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2k-other-kernel-unapproved", credentials, recovery=after_attempt(1), image="e2e-k2")
        print("boot 2k-unapproved: the peers' decisions: %s" % [(e.get("event"), e.get("peer"), e.get("outcome"), (e.get("reason") or "")[:160])
                                                                 for e in self.events[since:]], file=sys.stderr)
        self.assertEqual(initrd_pcr11(said), other_kernel["pcr11"]["initrd"])
        self.assertRegex(said, r"regalia-unlock: attempt 1: .*; asking again in ")
        self.assertRegex(said, PROMPT.pattern.decode())
        no_shell(self, said)
        events = self.events[since:]
        self.assertNotIn(("unlock", "ALLOW"), {(e["event"], e["outcome"]) for e in events})
        refused = {e["peer"]: e["reason"] for e in events if e["event"] == "unlock" and e["outcome"] == "DENY"}
        self.assertEqual(sorted(refused), ["b", "c"], events)
        for peer, reason in refused.items():
            self.assertIn("PCR 11 is %s, expected %s" % (other_kernel["pcr11"]["initrd"], record["pcr11"]["initrd"]), reason)
            self.assertNotRegex(reason, r"PCR (7|12) is")

        # then approved as NEXT beside CURRENT (a node's document holds at most two sets, attest.MAX_SETS: CURRENT and
        # NEXT; listing a third refuses every request before a nonce): it boots unattended
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-k2", other_kernel)))
        since = len(self.events)
        said = self.boot("2k-other-kernel", credentials, image="e2e-k2")
        # what the peers decided, said whatever happens (a refusal at hello names its reason only here)
        print("boot 2k: the peers' decisions: %s" % [(e.get("event"), e.get("peer"), e.get("outcome"), (e.get("reason") or "")[:160])
                                                      for e in self.events[since:]], file=sys.stderr)
        unattended(self, said)                                      # the client's "gave the key" line, through its unit only
        self.assertEqual(initrd_pcr11(said), other_kernel["pcr11"]["initrd"])
        # the test's report lines go to /dev/console themselves (e2e/lib/boot-guest/e2e-report), with no forwarding (#413)
        reported = re.search(r"REGALIA-E2E-CMDLINE (.*)", said)
        self.assertIsNotNone(reported, "no REGALIA-E2E-CMDLINE on the console (the report writes to /dev/console, #413)")
        self.assertNotIn("systemd.journald.forward_to_console=1", reported.group(1).split())
        shown = booted_pcrs(said)
        self.assertIsNotNone(shown, "no REGALIA-E2E-PCRS on the console (#413)")
        self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], other_kernel["pcr11"]["system"], expected["pcr12"]])
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])

        # boot 2d, THE SAME IMAGE, RETIRED (#135): the document lists the current image only. The guest's TPM still
        # releases the local half, as it does for every image the PCR-signing key signed (a signed policy has no
        # counter): the client starts, which it cannot without that half (boot 1b), and asks both peers. Both refuse
        # the quote, each naming PCR 11 and nothing else; nothing is given. The client keeps asking, at backoff's
        # cadence; the console asked from the start, and the recovery key typed there (once both refused) opens.
        # A refusal never ends in a shell (rd.shell=0, rd.emergency=reboot).
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2d-older-retired", credentials, recovery=after_attempt(1), image="e2e-old")
        self.assertRegex(said, r"regalia-unlock: attempt 1: .*; asking again in ")
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertLess(self.prompted_after, 120)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        shown = booted_pcrs(said)
        self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], older["pcr11"]["system"], expected["pcr12"]])
        events = self.events[since:]
        self.assertNotIn(("unlock", "ALLOW"), {(e["event"], e["outcome"]) for e in events})
        refused = {e["peer"]: e["reason"] for e in events if e["event"] == "unlock" and e["outcome"] == "DENY"}
        self.assertEqual(sorted(refused), ["b", "c"], events)
        for peer, reason in refused.items():
            self.assertIn("PCR 11 is %s, expected %s" % (older["pcr11"]["initrd"], record["pcr11"]["initrd"]), reason)
            self.assertNotRegex(reason, r"PCR (7|12) is")
            print("boot 2d: %s refused the retired image: %s" % (peer, reason), file=sys.stderr)

        # boot 2b, CREDENTIALS FROM SMBIOS (which the firmware owns, and nothing the peers attest measures): an extra
        # unit that would print a marker on the console, and a drop-in that makes the initrd want it. systemd imports
        # no credential (it says so in the journal, reported once booted), so neither is acted on, and the unlock
        # goes on as in boot 2 (PCR 12 does not see SMBIOS: this boot is NOT refused by the peers). It is also the
        # current image's first boot after 2d retired the older one: retiring an image strands nothing (#135).
        planted = {"systemd.extra-unit.regalia-planted.service":
                   b"[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/sh -c 'echo \"<2>REGALIA-E2E-PLANTED-RAN\" > /dev/kmsg'\n",
                   "systemd.unit-dropin.initrd.target": b"[Unit]\nWants=regalia-planted.service\n"}
        said = self.boot("2b-smbios", credentials, smbios=planted)
        self.assertNotIn("REGALIA-E2E-PLANTED-RAN", said)
        self.assertIn("REGALIA-E2E-IMPORT credentials-imported=no", said)
        self.assertIsNotNone(re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said))
        unattended(self, said)
        if "skipping importing of credentials" in said:
            print("boot 2b: systemd said it imports no credential", file=sys.stderr)

        # boots 3-5, A PLANTED CREDENTIAL: each adds one file to the ESP under a name systemd in the initrd acts on
        # (these are plain, so systemd ignores them as undecryptable; what matters here is that ANY extra file
        # changes PCR 12). PCR 7 and 11 are unchanged, PCR 12 is what espcreds computes for the seven files, every
        # peer refuses the quote, nothing is given, the console asks.
        planted = {"systemd.unit-dropin.regalia-unlock.service": b"[Service]\nEnvironment=PLANTED=1\n",
                   "systemd.extra-unit.regalia-planted.service": b"[Service]\nExecStart=/bin/true\n",
                   "tmpfiles.extra": b"f /run/regalia-planted - - - - planted\n",
                   # an EMPTY file: the stub packs it (systemd 257 skips no zero-length file), so PCR 12 moves too
                   "regalia.empty": b""}
        for n, (name, content) in enumerate(sorted(planted.items()), 3):
            with self.subTest(planted=name):
                since = len(self.events)
                said = self.boot("%d-planted" % n, dict(credentials, **{name: content}), recovery=after_attempt(1))
                self.assertRegex(said, r"regalia-unlock: attempt 1: .*; asking again in ")
                shown = booted_pcrs(said)
                self.assertIsNotNone(shown)
                self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], record["pcr11"]["system"], espcreds.pcr12(self.on_esp)])
                self.assertNotEqual(shown.group(3).lower(), expected["pcr12"])
                self.assertRegex(said, PROMPT.pattern.decode())
                outcomes = {(e["event"], e["outcome"]) for e in self.events[since:]}
                self.assertNotIn(("unlock", "ALLOW"), outcomes)
                refusals = [e["reason"] for e in self.events[since:] if e["outcome"] == "DENY"]
                self.assertTrue(refusals and all("PCR" in r for r in refusals), refusals)
                print("planted %s: refused (%s)" % (name, refusals[0]), file=sys.stderr)

        # boot 7, A COMMAND LINE FROM SMBIOS: systemd-stub reads io.systemd.stub.kernel-cmdline-extra from SMBIOS type 11
        # and, where it honours it, appends it to the command line and measures it into PCR 12. Here it would switch
        # credential import back on, with an extra unit passed beside it. Either the stub ignores it (the command line
        # and PCR 12 are unchanged, systemd still imports nothing, and the unlock goes on), or it is appended (PCR 12
        # moves and every peer refuses). In neither case does anything planted run: even with import switched back on,
        # the second layer (no debug generator, every credential import reset, #219) keeps the extra unit from being
        # made, so import=yes is not harmless by itself, the two layers are. The local half alone opens nothing (it is
        # sealed to PCR 7 and the signed PCR 11, which this does not change).
        since = len(self.events)
        extra_unit = {"systemd.extra-unit.regalia-planted.service":
                      b"[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/sh -c 'echo \"<2>REGALIA-E2E-PLANTED-RAN\" > /dev/kmsg'\n",
                      "systemd.unit-dropin.initrd.target": b"[Unit]\nWants=regalia-planted.service\n"}
        said = self.boot("7-cmdline-extra", credentials, recovery=after_attempt(1), smbios=extra_unit,
                         smbios_strings=["io.systemd.stub.kernel-cmdline-extra=systemd.import_credentials=yes"])
        self.assertNotIn("REGALIA-E2E-PLANTED-RAN", said)
        cmdline = re.search(r"REGALIA-E2E-CMDLINE (.*)", said).group(1)
        shown = booted_pcrs(said).groups()
        allowed = ("unlock", "ALLOW") in {(e["event"], e["outcome"]) for e in self.events[since:]}
        if "systemd.import_credentials=yes" in cmdline.split():
            self.assertNotEqual(shown[2].lower(), expected["pcr12"])             # appended: measured, and refused
            self.assertFalse(allowed)
            self.assertRegex(said, PROMPT.pattern.decode())
            print("boot 7: the stub appended the SMBIOS command line; PCR 12 moved and the peers refused", file=sys.stderr)
        else:
            self.assertEqual(shown[2].lower(), expected["pcr12"])                # ignored: nothing changed, and still no import
            self.assertIn("REGALIA-E2E-IMPORT credentials-imported=no", said)
            self.assertTrue(allowed)                                             # nothing changed: the unlock goes on
            print("boot 7: the stub ignored the SMBIOS command line; the unlock went on (%s)" % ("allowed" if allowed else "refused"),
                  file=sys.stderr)

        # boot 8, NO PEER, FOR LONGER THAN ANY DEFAULT TIMEOUT (#70): the client keeps asking, at the backoff's schedule
        # and past its cap (attempt 6), and the console, which asked from the start, still takes the recovery key after
        # 150 s: neither systemd-cryptsetup (timeout=0) nor the root's device wait (rootflags=x-systemd.device-timeout=0;
        # 90 s by default) gave up meanwhile. A WRONG key typed first only brings the prompt back (tries=0): no
        # emergency, no reboot. Nothing ends in a shell. Under TCG the long boots 8 and 9 would outlast the job, so they
        # need KVM; with REGALIA_EXPECT_KVM=1 (CI) its absence FAILS. The skip RETURNS: boots 8 and 9 stay the last ones,
        # and a boot added after them goes before this line, or it would be skipped with them.
        kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
        if not kvm:
            self.assertNotEqual(os.environ.get("REGALIA_EXPECT_KVM"), "1", "REGALIA_EXPECT_KVM=1 and no usable /dev/kvm: boots 8 and 9 cannot run")
            print("boots 8 and 9 SKIPPED: they wait 150 s each, which needs KVM", file=sys.stderr)
            return
        for peer in ("b", "c"):
            self.ip("ip", "link", "set", "eth0", "down", ns=self.peer_ns[peer])
        since = len(self.events)
        attempts, mistyped = {}, []           # attempt -> (seconds since start when its line arrived, the pause it announced)
        def seen(said, elapsed):
            for m in re.finditer(r"regalia-unlock: attempt (\d+): .*; asking again in (?:(\d+)m)?(\d+)s\b", said):
                attempts.setdefault(int(m.group(1)), (elapsed, int(m.group(2) or 0) * 60 + int(m.group(3))))
            return False
        def wrong_then_right(said, elapsed):
            if elapsed <= 150 or "regalia-unlock: attempt 6: " not in said:
                return False
            if not mistyped:
                mistyped.append(len(said))
                return b"not-the-recovery-key"
            return True
        said = self.boot("8-no-peer", credentials, recovery=wrong_then_right, watch=seen, timeout=1200)
        self.assertEqual(len(mistyped), 1, "the wrong key was never typed")
        self.assertRegex(said[mistyped[0]:], PROMPT.pattern.decode(), "the prompt did not come back after a wrong key")
        self.assertLess(self.prompted_after, 120)
        print("boot 8: attempts (arrived at, announced pause): %s" % sorted(attempts.items()), file=sys.stderr)
        self.assertTrue(all(n in attempts for n in range(1, 7)), sorted(attempts))
        for n in range(1, 7):
            arrived, pause = attempts[n]
            nominal = min(2 * 2 ** (n - 1), 60)                  # 2 s doubling, capped at 60 s, then x[0.8, 1.2)
            self.assertTrue(0.8 * nominal - 1 <= pause <= 1.2 * nominal + 1, "attempt %d announced %d s, nominal %d s" % (n, pause, nominal))
            if n + 1 in attempts:                                # and it did pause that long: no hot loop
                self.assertGreaterEqual(attempts[n + 1][0] - arrived, pause - 2, "attempt %d came early" % (n + 1))
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertRegex(said, r"regalia-unlock: /dev/mapper/root is open: standing down|Stopped regalia-unlock\.service")
        no_shell(self, said)
        self.assertEqual(self.events[since:], [])

        # boot 9, THE PEERS COME BACK (#70, the blackout): nobody types anything; the peers are unreachable until the
        # client is past the backoff's cap and 150 s have passed, then they return, and the host unlocks by itself
        def back(said, elapsed):
            if self.watched or elapsed <= 150 or "regalia-unlock: attempt 6: " not in said:
                return False
            for peer in ("b", "c"):            # the link back, and its route: setting eth0 down deleted the default route
                self.ip("ip", "link", "set", "eth0", "up", ns=self.peer_ns[peer])
                self.ip("ip", "route", "replace", "default", "dev", "eth0", ns=self.peer_ns[peer])
            return True
        since = len(self.events)
        said = self.boot("9-peers-return", credentials, watch=back, timeout=1200)
        self.assertEqual(len(self.watched), 1, "the peers were never brought back")
        print("boot 9: the peers came back %.0f s after the guest started" % self.watched[0], file=sys.stderr)
        gave = re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said)
        self.assertIsNotNone(gave, "the client did not give the key once the peers came back")
        self.assertIn("regalia-unlock: attempt 6: ", said[:gave.start()])
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])
        no_shell(self, said)

        # boots 10-12, A NEW MANIFEST (#66 B3, the ESP advance): regalia-sync never moves the TPM anchor;
        # regalia-esp-advance writes the chain to the ESP, THEN anchors it. These boots come last: they leave the
        # guest's anchor at epoch 2. The peers still hold epoch 1, so the unlock itself is not what is shown here
        # (the recovery key is typed if asked): only what the initrd renders from, or refuses.
        m2 = dict(self.m1, epoch=2, prev_digest=membership.digest(self.m1), issued_at="2026-10-04T00:00:00Z")
        two = [self.chain[0], self.signed(m2)]
        # boot 10, THE ESP AHEAD OF THE ANCHOR: the ESP written and the anchor not yet (a crash between the two
        # steps, or a reboot before the service ran): accepted, and rendered under the new epoch
        self.chain = two
        said = self.boot("10-esp-ahead", credentials, recovery=True)
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 2 (TPM high-water 1)", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        # boot 11, BOTH ADVANCED: the anchor moved to the chain the ESP holds, as regalia-esp-advance leaves a host
        self.anchor_guest(two)
        said = self.boot("11-advanced", credentials, recovery=True)
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 2 (TPM high-water 2)", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        # boot 12, THE ORDER REVERSED: an ESP left at epoch 1 under an anchor at 2 (what a sync that anchored first
        # would leave after a crash) is a ROLLBACK to the initrd: nothing rendered, no peer asked, the recovery key
        self.chain = two[:1]
        since = len(self.events)
        said = self.boot("12-esp-behind", credentials, recovery=True)
        self.assertRegex(said, r"regalia-unlock: the boot configuration cannot be rendered: ROLLBACK")
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        self.assertEqual([e for e in self.events[since:] if e.get("event") == "unlock"], [])

        # boot 13, #75 TIER Q, Q2: NEXT BOOTS UNDER A NEW EPOCH, AND THE PEERS UNLOCK IT. The root's epoch 2 approves
        # CURRENT and NEXT (the other kernel of boot 2k); the peers take it (their stores and a heartbeat for it); the
        # guest's ESP holds it, its anchor already at 2 (boot 11). NEXT then boots unattended: the initrd renders under
        # epoch 2 with the TPM high-water at 2, the client says NEXT's own initrd-phase PCR 11, and a peer under epoch 2
        # gives the key. (Q3, NEXT not approved, is boot 2k-unapproved.)
        for peer in ("b", "c"):
            self.stores[peer].commit(two[1])
            self.fresh[peer].accept(tub.hbt.beat(m2, 2, issued=self.now), m2)
        self.assertTrue(all(self.stores[p].load()["epoch"] == 2 for p in ("b", "c")))
        self.chain = two
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-k2", other_kernel)))
        since = len(self.events)
        said = self.boot("13-next-under-epoch-2", credentials, image="e2e-k2")
        print("boot 13: the peers' decisions: %s" % [(e.get("event"), e.get("peer"), e.get("outcome"), (e.get("reason") or "")[:160])
                                                     for e in self.events[since:]], file=sys.stderr)
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 2 (TPM high-water 2)", said)
        unattended(self, said)
        self.assertEqual(initrd_pcr11(said), other_kernel["pcr11"]["initrd"])
        allowed = [e for e in self.events[since:] if e.get("event") == "unlock" and e.get("outcome") == "ALLOW"]
        self.assertTrue(allowed and all(e.get("epoch") == 2 for e in allowed), "no peer under epoch 2 gave the key: %s" % allowed)
        no_shell(self, said)

    def anchor_guest(self, envelopes):
        """The guest's TPM anchor moved to the tip of `envelopes` while the guest is off (what regalia-esp-advance
        does on a running host, after the ESP holds the chain: node.esp_advance)."""
        sock = self.d + "/a-off.sock"
        tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=%s/tpm-a" % self.d, "--server", "type=unixio,path=" + sock,
                                "--ctrl", "type=unixio,path=%s.ctrl" % sock, "--flags", "not-need-init,startup-clear"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if os.path.exists(sock):
                    break
                time.sleep(0.1)
            tcti = "swtpm:path=" + sock
            membership.accept_chain(None, envelopes, self.signed({})["signature"]["key"])
            manifests = [e["manifest"] for e in envelopes]
            anchor = membership.HighWater("0x1500016", tcti=tcti, lock_path=self.d + "/a-hw.lock")
            anchor.anchor(len(manifests), membership.Store._digests(manifests))
            anchor.check(len(manifests))
            run(["tpm2_shutdown", "-c", "-T", tcti], capture_output=True, check=True)
        finally:
            tpm.terminate()
            tpm.wait(30)


if __name__ == "__main__":
    unittest.main()
