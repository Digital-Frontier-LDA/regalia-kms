#!/usr/bin/env python3
"""Measure a bare-metal KMS host's platform, TPM and OS controls from the host itself (ADR-0002 D21).

The KMS runs on dedicated bare metal with a discrete TPM 2.0 (regalia#46: HPE DL360 Gen9). This probe
reads the running host and reports each control with the reason for its verdict; with an evidence
file it also checks the SIGNED commissioning evidence (deploy/baremetal/evidence.py: schema,
signature, every attested firmware setting) and refuses one that disagrees with the host. The OS
probes (core dumps, hibernation, swap, an unprivileged service) are deploy/baremetal/os_probe.py's.
Token clients are checked by token_clients_root_only (below): on bare metal the host itself seals and
re-seals the PINs and so needs opensc-tool and pkcs11-tool.

    sudo python3 -Es deploy/baremetal/host_probe.py --import-key-sha256 HEX     # exit 1 unless every control is true
    sudo python3 -Es deploy/baremetal/host_probe.py --evidence E.json --signature E.json.sig \
        --evidence-key commissioning-p256.pem --evidence-key-sha256 HEX      # the commissioning pass criterion

PLATFORM AND TPM, measured:
  uefi_boot                 booted through UEFI (/sys/firmware/efi): TPM 2.0 measured boot needs it
  secure_boot_enabled       the SecureBoot EFI variable is 1
  tpm2_present              a TPM whose major version is 2, behind the kernel resource manager
                            (/dev/tpmrm0): seal-hsm-pin.sh refuses the raw /dev/tpm0
  tpm_sha256_bank           the TPM exposes an active SHA-256 PCR bank (/sys/class/tpm/tpm0/pcr-sha256)
  tpm_lockout_policy        the TPM's dictionary-attack settings are the commissioned ones (32 failed
                            tries, one forgiven every 600 s, lockout-hierarchy recovery 86400 s), its
                            lockout hierarchy has an authorization value, and it is not in lockout. A
                            power cut after the PIN was unsealed counts as a failed try (#57), so these
                            settings decide how many cuts in a row a host survives unattended
  root_disk_tpm_unlocked    a dm-crypt device is among the root filesystem's block-device ancestors
                            (lsblk -s: LUKS directly or under LVM), and its crypttab entry unlocks with
                            the TPM (a tpm2-device=<value> option, parsed exactly)
  root_disk_unlock_revocable
                            NO keyslot of a volume that holds this host's secrets is released by the
                            local TPM on a policy that cannot retire a boot image (#135). The volumes
                            judged are every dm-crypt device under "/", under the host key and under the
                            credstore (all members of a multi-device btrfs). A systemd-tpm2 token bound
                            to PCR values, or to a signed PCR policy, is such a policy: PCR 7 does not
                            change with the kernel, and a signed policy accepts every image its key ever
                            signed. An old signed image then unlocks the disk, reads the host key and
                            opens the HSM PIN. What passes, on EVERY judged volume: at least one
                            NV-backed systemd-tpm2 token (tpm2_pcrlock), and no token naming a keyslot
                            that is anything but such a token or the systemd-recovery token; each names
                            keyslots that exist; and /var/lib/systemd/pcrlock.json, the policy systemd
                            keeps for the NV index, binds PCR 7 and a PCR that tells boot images apart
                            (11 or 4), each with measured values (an all-zero value binds nothing); and
                            every keyslot of those volumes is named by exactly one such token. A token of any other type (clevis, an unknown name) fails: this
                            check cannot say what releases its keyslot. NOT measured: that the NV index
                            holds that file's policy, and that a retired image is in fact refused on this
                            host (#65 checklist, section D). THE SECOND PASSING SHAPE is peer-assisted
                            unlock (#67, deploy/baremetal/unlock.py): regalia-peer-unlock tokens and no
                            systemd-tpm2 token at all, judged by unlock.judge_tokens against --node-id
                            and --unlock-peer (this node, and exactly the peers that hold a path), each
                            path's local share sealed to the TPM alone under the binding RECORDED for the
                            PIN credentials (PCR 7, and the signed PCR 11 policy when the PINs have it).
                            Its crypttab entry takes the key from the unlock client's socket
                            (/run/regalia-unlock/key.sock), carries only options known to leave the
                            unlock alone, and the kernel command line has no rd.luks.* setting. NOT
                            measured: the root volume is opened in the initrd, by the crypttab the
                            initrd was BUILT with; /etc/crypttab is what that was copied from, not
                            necessarily what it holds (an edit with no initrd rebuild is invisible here),
                            and dracut in host-only mode can put rd.luks.* settings in the initrd's own
                            /etc/cmdline.d, which /proc/cmdline does not show.
                            On the root volume only: the unlock client opens no other. A second volume
                            that holds a secret needs an NV-backed token of its own. root_disk_tpm_unlocked
                            accepts the same shape, with no tpm2-device in crypttab. A HOST ENROLLED WITH --tpm2-pcrs=7 FAILS THIS, BY
                            DESIGN: it is the known blocker for production, and there is no option to
                            skip it. Signed commissioning evidence records every measured control as
                            true, so no evidence can be signed for such a host either.
  root_disk_recovery_keyslot
                            the same LUKS2 header carries the per-host RECOVERY keyslot (#77): exactly
                            one systemd-recovery token, naming one keyslot that no other token names,
                            and no keyslot that no token names (a leftover installer passphrase). Read
                            from the header alone: the recovery key itself is never asked for or read.
                            It is a ceremony secret on paper and in the escrow, enrolled by
                            deploy/baremetal/recovery-key.sh; whether the paper copy OPENS that keyslot
                            is recovery-key.sh --check, a rehearsal step, not a probe
  ima_policy_loaded         the IMA policy has an executable-measurement rule (measure func=BPRM_CHECK,
                            or MMAP_CHECK with MAY_EXEC), AND the newest IMA log entry for the
                            regalia-kms binary carries the digest of the bytes at that path NOW (a
                            stale entry for a since-replaced binary fails). For attestation (quotes):
                            the PIN is not sealed to the IMA PCR (README, section 3)
  pin_import_key_present    the persistent key at the import handle (default 0x81000101) IS the one
                            recorded at --init-import-key: the sha256 of its DER public key starts with
                            --import-key-sha256 (or the evidence's host.pin_import_key_sha256), and it
                            is RSA-3072 with EXACTLY the attributes --init-import-key sets:
                            fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda
  pin_credentials_sealed_as_recorded
                            every /etc/credstore.encrypted/regalia-kms-*.pin is sealed to the TPM AND the
                            host key together (not the TPM alone, not the host key alone, not a null key:
                            #75, below), and its header carries exactly the
                            recorded binding: the PCRs bound directly, the PCRs bound through a signed
                            policy, and that policy's signing key (--credential-pcrs,
                            --credential-signed-pcrs, --credential-pcr-key-pkfp, or the evidence's
                            host.credential_tpm2_*), in the SHA-256 PCR bank. The header is authenticated
                            with the secret and names the PCRs systemd asks the TPM for, so it is the
                            binding the blob has. Each blob must also OPEN on this boot, under the name
                            the unit loads it by (systemd-creds decrypt, the secret to /dev/null). And the
                            host key (/var/lib/systemd/credential.secret) is root's, mode 0400, on a
                            filesystem with a dm-crypt device beneath it.
                            WHY NOT THE TPM ALONE: a signed PCR 11 policy has no counter, so every image
                            the PCR-signing key ever signed opens a TPM-only credential for ever. With
                            the host key in the seal, an image must also unlock the root disk
  hsm_token_attached        a Nitrokey HSM 2 (USB 20a0:4230) is on the bus (sysfs; no token client
                            needed); its USB path is reported so the evidence can pin the INTERNAL port
  firewall_default_deny     the table `inet regalia_kms` (deploy/baremetal/firewall.py) is loaded, with its
                            input, output and forward base chains all on policy drop. nftables runs every
                            base chain of a hook, and a drop in any one is final, so no other table's
                            accept can weaken it. What the table lets through is checked by behaviour:
                            network_probe.py from each zone (e2e/baremetal-firewall-netns.sh in the lab)
  token_clients_root_only   every token client tool on
                            PATH is root:root and not executable by group or others, so the KMS user
                            cannot run them, and every process connected to pcscd runs the KMS binary

ATTESTED, NOT MEASURED (what the OS cannot read; in the signed evidence, deploy/baremetal/evidence.py):
  ilo_isolated_or_disabled, ac_power_recovery, chassis_intrusion_armed, used_hardware_intake,
  runtime_credentials_excluded_from_backup; and the records the measurements are checked against:
  pin_import_key_sha256, hsm_usb_path, credential_tpm2_pcrs (never PCR 10, never PCR 11 directly),
  credential_tpm2_signed_pcrs and credential_tpm2_pcr_key_pkfp (the signed PCR 11 policy, #57),
  node_id and unlock_peers (what a root disk enrolled for peer-assisted unlock is judged against, #67).

The KMS unit's sandbox, capabilities and AppArmor confinement (#61) are os_probe.py's too.

NOT MEASURED YET: a signed PCR 11 policy on the ROOT DISK. root_disk_tpm_unlocked still requires a
LUKS2 token bound to PCR 7 exactly; the signed policy covers the PIN credentials only.

Standard library only, plus the tpm2-tools and openssl binaries the host already needs.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import os_probe  # noqa: E402  (the Host and the OS-hardening probes)
import evidence as evidence_mod  # noqa: E402

SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMPORT_HANDLE = os.environ.get("REGALIA_PIN_IMPORT_HANDLE", "0x81000101")
IMA_LOG = "/sys/kernel/security/ima/ascii_runtime_measurements"
KMS_BINARY = os_probe.ALLOWED_TOKEN_CLIENT_EXES[0]
NITROKEY_HSM = ("20a0", "4230")
SYSTEM_BIN_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/opt/bin")
IMPORT_KEY_ATTRS = {"fixedtpm", "fixedparent", "sensitivedataorigin", "userwithauth", "decrypt", "noda"}
# The TPM's dictionary-attack settings, as deploy/baremetal/tpm-lockout.sh sets them (#57): 32 failed
# tries before lockout, one try forgiven every 600 s, and 86400 s before the lockout hierarchy can be
# used again after ITS authorization was got wrong.
LOCKOUT_POLICY = {"TPM2_PT_MAX_AUTH_FAIL": 32, "TPM2_PT_LOCKOUT_INTERVAL": 600, "TPM2_PT_LOCKOUT_RECOVERY": 86400}
CREDSTORE = "/etc/credstore.encrypted"
PIN_CREDENTIAL = re.compile(r"regalia-kms-[a-z0-9]+(-[a-z0-9]+)*\.pin")   # what seal-hsm-pin.sh installs
# The 16-byte key-type id that opens a systemd encrypted credential (measured, systemd 257, one blob of
# each type made against swtpm). Only the two host-key-AND-TPM types are a commissioned PIN (#75).
CRED_HOST_TPM2, CRED_HOST_TPM2_PK = "93a894094874449090caf2fc93cab553", "af4950a849134eb1a73846304ff30c05"
TPM_ALONE = "the TPM alone, with no host key: every image the PCR-signing key ever signed opens it without the " \
    "root disk (#75). Reseal it from the PIN card with seal-hsm-pin.sh --replace"
CRED_REFUSED = {"5a1c6a86df9d4096b1d5a65e0862f19a": "the host key alone (bench only)",
                "0c7cc07b117645919c4b0bea08bc20fe": TPM_ALONE,
                "faf7eb9341e3412ca1a436f95a29362f": TPM_ALONE,
                "058469daf6f54324800549da0f8ea2fb": "a null key (no protection at all)"}
HOST_KEY = "/var/lib/systemd/credential.secret"
TPM2_ALG_SHA256 = 0x000B
RSA_ALGORITHM = bytes.fromhex("300d06092a864886f70d0101010500")   # AlgorithmIdentifier: rsaEncryption, NULL
PLATFORM = ("uefi_boot", "secure_boot_enabled", "tpm2_present", "tpm_sha256_bank", "tpm_lockout_policy",
            "root_disk_tpm_unlocked", "root_disk_unlock_revocable", "root_disk_recovery_keyslot", "ima_policy_loaded",
            "pin_import_key_present",
            "pin_credentials_sealed_as_recorded", "hsm_token_attached",
            "token_clients_root_only", "firewall_default_deny")
MEASURED = PLATFORM + os_probe.MEASURED
UNMEASURED = evidence_mod.ATTESTED + evidence_mod.RECORDS


class Host(os_probe.Host):
    def read_bytes(self, path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError:
            return None

    def exists(self, path):
        return os.path.exists(path)

    def which_all(self, tool):
        """Every executable named tool on PATH or in the standard system directories, by real path."""
        dirs = os.environ.get("PATH", "").split(os.pathsep) + list(SYSTEM_BIN_DIRS)
        found = []
        for d in dirs:
            p = os.path.join(d, tool)
            if d and os.path.isfile(p) and os.access(p, os.X_OK):
                real = os.path.realpath(p)
                if real not in found:
                    found.append(real)
        return found

    def stat(self, path):
        try:
            st = os.stat(path)
            return st.st_uid, st.st_gid, st.st_mode
        except OSError:
            return None


def uefi_boot(host):
    return (True, "booted through UEFI") if host.exists("/sys/firmware/efi") else \
        (False, "no /sys/firmware/efi: booted in legacy BIOS mode; TPM 2.0 measured boot needs UEFI")


def secure_boot(host):
    raw = host.read_bytes(SECURE_BOOT_VAR)
    if not raw:
        return False, "the SecureBoot EFI variable is unreadable or absent"
    # efivarfs: 4 bytes of attributes, then the value byte
    return (True, "SecureBoot = 1") if raw[-1:] == b"\x01" else (False, "SecureBoot = %d" % raw[-1])


def tpm2(host):
    major = (host.read("/sys/class/tpm/tpm0/tpm_version_major") or "").strip()
    if major != "2":
        return False, "no TPM 2.0 (tpm_version_major=%r)" % major
    if not host.exists("/dev/tpmrm0"):
        return False, "TPM 2.0 present but no /dev/tpmrm0 (kernel resource manager)"
    return True, "TPM 2.0 behind /dev/tpmrm0"


def sha256_bank(host):
    pcrs = host.listdir("/sys/class/tpm/tpm0/pcr-sha256")
    return (True, "SHA-256 PCR bank active (%d PCRs)" % len(pcrs)) if pcrs else \
        (False, "no /sys/class/tpm/tpm0/pcr-sha256: enable the SHA-256 bank in the firmware (RBSU)")


def root_crypt_devices(host):
    """The dm-crypt names under the root filesystem (LUKS directly, or LVM on LUKS), or (None, why)."""
    rc, out = host.run(["findmnt", "-n", "-o", "SOURCE", "/"])
    src = re.sub(r"\[.*\]$", "", out.strip())          # btrfs: /dev/mapper/x[/@]
    if rc != 0 or not src:
        return None, "cannot find the root filesystem's device"
    # The device and its ancestors (inverse tree): LUKS directly, or LVM on LUKS, both resolve here.
    rc, out = host.run(["lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", src])
    crypts = [f[0] for f in (l.split() for l in out.splitlines()) if len(f) == 2 and f[1] == "crypt"]
    if rc != 0 or not crypts:
        return None, "the root filesystem (%s) is not on dm-crypt" % src
    return crypts, ""


def luks_header(host, name):
    """(device, LUKS2 JSON metadata) of the volume under dm-crypt name, or (None, why)."""
    rc, status = host.run(["cryptsetup", "status", name])
    dev = next((l.split(":", 1)[1].strip() for l in status.splitlines() if l.strip().startswith("device:")), "")
    if rc != 0 or not dev:
        return None, "cannot find the LUKS device under %s (cryptsetup status)" % name
    rc, meta = host.run(["cryptsetup", "luksDump", "--dump-json-metadata", dev])
    try:
        parsed = json.loads(meta) if rc == 0 else None
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        return None, "cannot read the LUKS2 header of %s (cryptsetup luksDump --dump-json-metadata)" % dev
    # Every check below walks tokens and keyslots as objects of objects. Anything else is not a header
    # cryptsetup wrote, and is refused here once instead of raising somewhere later.
    for part in ("tokens", "keyslots"):
        value = parsed.setdefault(part, {})
        if not isinstance(value, dict) or not all(isinstance(v, dict) for v in value.values()):
            return None, "the LUKS2 header of %s is malformed: %s is not an object of objects" % (dev, part)
    for token_id, token in parsed["tokens"].items():
        slots = token.get("keyslots", [])
        if not isinstance(slots, list) or not all(isinstance(slot, str) for slot in slots):
            return None, "the LUKS2 header of %s is malformed: token %s names keyslots %r, not a list of keyslot IDs" % (dev, token_id, slots)
    return dev, parsed


def token_keyslots(token, meta):
    """The keyslots a token names, as a list of IDs, if it is a list of strings that all exist in the
    header; None otherwise (a stale token naming a wiped keyslot unlocks nothing, whatever it claims)."""
    slots = token.get("keyslots")
    if not isinstance(slots, list) or not all(isinstance(s, str) for s in slots) or not set(slots) <= set(meta["keyslots"]):
        return None
    return slots


PEER_TOKEN = "regalia-peer-unlock"      # deploy/baremetal/unlock.py: one token per peer path
# The socket the unlock client gives the volume key on: the key-file field of the root volume's crypttab
# entry (unlock.KEY_SOCKET, and the ListenStream of initrd/regalia-unlock.socket; a test holds the two equal).
PEER_KEY_SOCKET = "/run/regalia-unlock/key.sock"
# The crypttab options a peer-shaped volume may carry: the ones known to leave WHAT opens the volume, and
# where its key goes, alone. An allowlist, because the other kind keeps growing: tpm2-device, fido2-device
# and pkcs11-uri open it another way; header= makes systemd-cryptsetup read keyslots and tokens from a
# detached header, not the one on the device that this probe judges; link-volume-key= (systemd 257) puts the
# volume key in a kernel keyring; plain, tcrypt, bitlk, swap and tmp are not LUKS at all; try-empty-password
# and noauto change whether and how it is opened. headless is left out on purpose too: with it, a boot with no
# key from the socket gives up instead of asking at the console, and the console is where the recovery key
# is typed after a total outage (#77).
PEER_CRYPTTAB_OPTIONS = frozenset({
    "luks", "x-initrd.attach", "discard", "tries", "timeout", "token-timeout",
    "no-read-workqueue", "no-write-workqueue", "same-cpu-crypt", "submit-from-crypt-cpus",
    "tpm2-measure-pcr", "tpm2-measure-bank"})      # the last two only measure the volume key into a PCR


def peer_paths(meta, where, unlock_record, binding=None):
    """Judge a volume that carries peer-path tokens (#67): (ok, why). unlock.judge_tokens decides whether
    the paths are well-formed, for this node, from the recorded peers, each with a keyslot of its own,
    with NO systemd-tpm2 token beside them; here the local share of each path must also be sealed to the
    TPM as the PIN credentials are RECORDED to be (`binding`: the same direct PCRs, signed PCRs and
    signing key, so the day the PINs get the signed PCR 11 policy the local share must have it too, with
    no second switch). With no recorded binding: PCR 7 exactly, with or without a signed PCR 11 policy.
    `unlock_record` is (this host's node ID, its unlock peers), from --node-id and --unlock-peer."""
    if unlock_record is None:
        return False, "%s carries %s tokens, and this run was not told which node this is: pass --node-id and one " \
            "--unlock-peer per peer (the tokens are judged against that record)" % (where, PEER_TOKEN)
    node, peers = unlock_record
    try:
        if os.path.dirname(os.path.dirname(HERE)) not in sys.path:
            sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
        from deploy.baremetal import unlock
    except Exception as error:      # noqa: BLE001  without the judge the shape cannot be accepted
        return False, "%s carries %s tokens, but deploy/baremetal/unlock.py cannot be loaded (%s: %s)" % (
            where, PEER_TOKEN, type(error).__name__, error)
    ok, why, _slots = unlock.judge_tokens(meta, node, list(peers))
    if not ok:
        return False, "%s: %s" % (where, why)
    for token_id, token in sorted(meta["tokens"].items()):
        if token.get("type") != PEER_TOKEN:
            continue
        try:
            direct, signed, _pkfp = local_share_binding(token.get("local"))
        except ValueError as error:
            return False, "%s: the local share of token %s is %s" % (where, token_id, error)
        if binding is not None:
            want = (list(binding[0]), list(binding[1]), binding[2])
            if (direct, signed, _pkfp) != want:
                return False, "%s: the local share of token %s is sealed to %s; the recorded binding is %s" % (
                    where, token_id, binding_text(direct, signed, _pkfp), binding_text(*want))
        elif direct != [7] or signed not in ([], [11]):
            return False, "%s: the local share of token %s is sealed to %s, not to PCR 7 exactly (with or without a signed " \
                "PCR 11 policy)" % (where, token_id, binding_text(direct, signed, _pkfp))
    return True, why


def root_unlock(host, unlock_record=None, binding=None):
    crypts, why = root_crypt_devices(host)
    if crypts is None:
        return False, why
    entries, key_files = {}, {}
    for line in (host.read("/etc/crypttab") or "").splitlines():
        f = line.split()
        if f and not f[0].startswith("#"):
            entries[f[0]] = f[3] if len(f) > 3 else ""
            key_files[f[0]] = f[2] if len(f) > 2 else ""
    how = []
    for name in crypts:
        dev, meta = luks_header(host, name)
        if dev is None:
            return False, meta
        tokens = meta["tokens"]
        opts = dict((o.split("=", 1) + [""])[:2] for o in entries.get(name, "").split(",") if o)
        # The peer-assisted shape (#67): the TPM AND a peer, never the TPM alone. There is no systemd-tpm2
        # token, and systemd-cryptsetup takes the volume key from the unlock client's socket and from nowhere
        # else: the crypttab entry names that socket as its key file and asks for no other way in.
        if any(t.get("type") == PEER_TOKEN for t in tokens.values()):
            if name not in entries:
                return False, "%s (%s) carries %s tokens, but it is not listed in /etc/crypttab: nothing asks the unlock " \
                    "client for its key at boot (key file %s)" % (name, dev, PEER_TOKEN, PEER_KEY_SOCKET)
            other = sorted(o for o in opts if o not in PEER_CRYPTTAB_OPTIONS)
            if other:
                return False, "%s (%s) carries %s tokens, but its crypttab entry has %s: not among the options known to leave " \
                    "what opens the volume, and where its key goes, alone (%s)" % (
                        name, dev, PEER_TOKEN, ", ".join("%s=%s" % (o, opts[o]) if opts[o] else o for o in other),
                        ", ".join(sorted(PEER_CRYPTTAB_OPTIONS)))
            # The root volume is opened in the INITRD, by the copy of crypttab the initrd was built with, or by
            # rd.luks.* on the kernel command line, never by this file. The second can be seen from here.
            cmdline = host.read("/proc/cmdline")
            if cmdline is None:
                return False, "%s (%s): cannot read /proc/cmdline to see whether the kernel command line configures the unlock" % (name, dev)
            on_cmdline = sorted({w.split("=", 1)[0] for w in cmdline.split() if w.startswith(("rd.luks", "luks."))})
            if on_cmdline:
                return False, "%s (%s) carries %s tokens, but the kernel command line configures LUKS (%s): the initrd did " \
                    "not open it as /etc/crypttab says" % (name, dev, PEER_TOKEN, ", ".join(on_cmdline))
            if key_files[name] != PEER_KEY_SOCKET:
                return False, "%s (%s) carries %s tokens, but its crypttab key file is %r, not the unlock client's socket %s" % (
                    name, dev, PEER_TOKEN, key_files[name] or "none", PEER_KEY_SOCKET)
            ok, why = peer_paths(meta, "%s (%s)" % (name, dev), unlock_record, binding)
            if not ok:
                return False, why
            how.append("%s unlocks with the TPM and a peer (%s)" % (name, why))
            continue
        # The record says this host's root disk is opened with its peers: a disk without peer paths is not
        # the disk the record describes, however well it is enrolled otherwise.
        if unlock_record is not None and unlock_record[1]:
            return False, "%s (%s) carries no %s token, but the unlock record names the peers %s: the root disk is not " \
                "enrolled as recorded" % (name, dev, PEER_TOKEN, ", ".join(unlock_record[1]))
        if name not in entries:
            return False, "%s (under the root filesystem) is not listed in /etc/crypttab" % name
        if not opts.get("tpm2-device"):
            return False, "%s is in crypttab but not TPM-unlocked (options: %s)" % (name, entries[name] or "none")
        # crypttab only ASKS for the TPM; the LUKS2 header must actually carry a TPM2 token (what
        # systemd-cryptenroll --tpm2-device writes), or a passphrase-only volume would pass here.
        tpm = [t for t in tokens.values() if t.get("type") == "systemd-tpm2" and token_keyslots(t, meta)]
        if not tpm:
            return False, "%s (%s) has no systemd-tpm2 token in its LUKS2 header: enrol it with " \
                "systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7" % (name, dev)
        # The commissioning policy binds the disk to PCR 7 exactly (README, section 3): a token with no
        # PCRs, or other ones, would release the disk key whatever the Secure Boot state. The one other
        # shape is an NV-backed token (tpm2_pcrlock): it lists no PCRs, they are in the policy the NV
        # index holds, so that policy must be shown to cover PCR 7. Whether a token can RETIRE an image
        # is root_disk_unlock_revocable's.
        wrong = [t.get("tpm2-pcrs") for t in tpm if not nv_backed(t) and t.get("tpm2-pcrs") != [7]]
        if wrong:
            return False, "%s (%s) has a TPM2 token bound to PCRs %s, not exactly [7] and not NV-backed: re-enrol with " \
                "systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7" % (name, dev, wrong)
        if any(nv_backed(t) for t in tpm):
            pcrs, why = pcrlock_pcrs(host)
            if pcrs is None or 7 not in pcrs:
                return False, "%s (%s) has an NV-backed TPM2 token, but %s: nothing shows that its policy binds PCR 7" % (
                    name, dev, why or "%s does not cover PCR 7 (it covers %s)" % (PCRLOCK_POLICY, sorted(pcrs)))
        how.append("%s unlocks with the TPM (%s; systemd-tpm2 token in the LUKS2 header)" % (name, entries[name]))
    return True, "; ".join(how)


def nv_backed(token):
    """A systemd-tpm2 token whose policy lives in a TPM NV index (systemd-cryptenroll --tpm2-pcrlock):
    exactly `"tpm2_pcrlock": true`, and no PCR list of its own."""
    return token.get("tpm2_pcrlock") is True and not token.get("tpm2-pcrs")


PCRLOCK_POLICY = "/var/lib/systemd/pcrlock.json"
# The PCRs that differ between two boot images: 11 (systemd-stub measures the UKI's sections into it) and 4
# (the firmware measures each EFI binary it starts: the boot loader, and the kernel WHEN it is started as an
# EFI image, as a UKI is; a kernel that GRUB loads itself is not in PCR 4). Not 12 (the command line and
# credentials), nor 9: the same image boots with either.
IMAGE_PCRS = frozenset({4, 11})


def pcrlock_pcrs(host):
    """The PCRs BOUND by the policy systemd keeps for its NV index (systemd-pcrlock make-policy writes
    it): (set of PCR numbers whose accepted values are all measured ones, never the all-zero value of a
    PCR nothing was extended into, ""), or (None, why). make-policy LEAVES OUT a PCR whose measurements it
    cannot match to components, and says so only in its log, so an NV-backed token says nothing by
    itself about WHICH PCRs bind the disk. The file is not authenticated here: whether the NV index
    holds this policy is not measured."""
    text = host.read(PCRLOCK_POLICY)
    if text is None:
        return None, "there is no %s (systemd-pcrlock make-policy writes it)" % PCRLOCK_POLICY
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    values = doc.get("pcrValues") if isinstance(doc, dict) else None
    if not isinstance(values, list) or not values or doc.get("pcrBank") != "sha256":
        return None, "%s is not a SHA-256 pcrlock policy with PCR values" % PCRLOCK_POLICY
    pcrs, listed = set(), set()
    for entry in values:
        good = isinstance(entry, dict) and type(entry.get("pcr")) is int and 0 <= entry["pcr"] <= 23 \
            and isinstance(entry.get("values"), list) and entry["values"] \
            and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in entry["values"])
        if not good:
            return None, "%s has a PCR entry that is not {pcr, values: [64 hex, ...]}" % PCRLOCK_POLICY
        # A PCR nothing was measured into is all zeros, on every boot of every image: accepting that value
        # binds nothing. PCR 11 is extended only by systemd-stub (a UKI boot); on a GRUB + initramfs host it
        # stays zero, and a policy "covering" it is satisfied by every old kernel.
        # one entry per PCR: with two, a second one accepting zeros would hide behind a first that does not
        if entry["pcr"] in listed:
            return None, "%s lists PCR %d twice" % (PCRLOCK_POLICY, entry["pcr"])
        listed.add(entry["pcr"])
        if "0" * 64 not in entry["values"]:
            pcrs.add(entry["pcr"])
    return pcrs, ""


# Where this host's secrets are: the root filesystem, systemd's host key (the other half of every PIN
# credential) and the credentials themselves. A separate /var, or a second device of the root
# filesystem, is a volume an old image can open like any other.
# NOT resolved: a filesystem that spans devices without naming them as its source (an f2fs with several
# devices, an ext4 or xfs with an external journal) is judged as its one named device. Swap is not judged.
SECRET_PATHS = ("/", HOST_KEY, CREDSTORE)


def secret_volumes(host):
    """The dm-crypt names under every filesystem that holds a secret: {name: [the paths it is under]},
    or (None, why). A multi-device btrfs is resolved to ALL its members (findmnt names one)."""
    volumes = {}
    for path in SECRET_PATHS:
        rc, out = host.run(["findmnt", "-n", "-o", "SOURCE,FSTYPE,UUID", "-T", path])
        fields = out.split()
        if rc != 0 or len(fields) < 2:
            return None, "cannot find the filesystem that holds %s (findmnt)" % path
        sources, fstype = [re.sub(r"\[.*\]$", "", fields[0])], fields[1]
        if fstype == "btrfs":
            rc, listing = host.run(["lsblk", "-n", "-r", "-o", "PATH,UUID"])
            members = [f[0] for f in (line.split() for line in listing.splitlines()) if len(f) == 2 and len(fields) == 3 and f[1] == fields[2]]
            if rc != 0 or not members:
                return None, "cannot list the devices of the btrfs filesystem that holds %s (lsblk)" % path
            sources = members
        for src in sources:
            rc, out = host.run(["lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", src])
            crypts = [f[0] for f in (line.split() for line in out.splitlines()) if len(f) == 2 and f[1] == "crypt"]
            if rc != 0 or not crypts:
                return None, "%s is on %s, which is not on dm-crypt" % (path, src)
            for name in crypts:
                volumes.setdefault(name, [])
                if path not in volumes[name]:
                    volumes[name].append(path)
    return volumes, ""


NOT_REVOCABLE = (
    "%s (%s) is unlocked by the local TPM alone, under a policy that cannot retire a boot image (%s). An old signed "
    "kernel image unlocks this disk, reads the host key and opens the HSM PIN. BLOCKING FOR PRODUCTION (#135). "
    "What clears it: a peer's contribution to the unlock (#67: deploy/baremetal/unlock.py), or an NV-backed policy "
    "(systemd-cryptenroll --tpm2-pcrlock; measured on a software TPM only, e2e/pcrlock-luks-swtpm.sh). "
    "There is no option to skip this check")


def unlock_revocable(host, unlock_record=None, binding=None):
    volumes, why = secret_volumes(host)
    if volumes is None:
        return False, why
    any_nv, by_peer = False, []
    for name, paths in volumes.items():
        dev, meta = luks_header(host, name)
        if dev is None:
            return False, meta
        where = "%s (%s, under %s)" % (name, dev, ", ".join(paths)) if paths != ["/"] and set(paths) != set(SECRET_PATHS) else "%s (%s)" % (name, dev)
        # as root_unlock: a root volume recorded as opened with peers, and carrying no peer path, is not the
        # recorded disk, whatever else would release it
        if "/" in paths and unlock_record is not None and unlock_record[1] \
                and not any(t.get("type") == PEER_TOKEN for t in meta["tokens"].values()):
            return False, "%s carries no %s token, but the unlock record names the peers %s: the root disk is not enrolled " \
                "as recorded. BLOCKING FOR PRODUCTION (#135)" % (where, PEER_TOKEN, ", ".join(unlock_record[1]))
        nv, fixed, named, recovery = 0, [], {}, 0
        for token_id, token in sorted(meta["tokens"].items()):
            if token.get("keyslots") and token_keyslots(token, meta) is None:
                return False, "%s: token %s (%s) names keyslots %r, which are not all keyslots of this header: a stale or " \
                    "damaged token. BLOCKING FOR PRODUCTION (#135): what unlocks this volume cannot be judged" % (
                        where, token_id, token.get("type"), token.get("keyslots"))
            for slot in token.get("keyslots") or []:
                named.setdefault(slot, []).append(token_id)
        # A keyslot that no token names is opened by something this check cannot see: a passphrase, a key file
        # (on the ESP, say), or a TPM-sealed key from a tool that writes no token. On the root volume
        # root_disk_recovery_keyslot says the same; here it holds for EVERY volume with a secret on it.
        stray = sorted(set(meta["keyslots"]) - set(named), key=lambda slot: (len(slot), slot))
        if stray:
            return False, "%s: keyslot %s is named by no token: a passphrase, a key file or a sealed key this check cannot " \
                "judge. BLOCKING FOR PRODUCTION (#135): wipe it, or enrol what opens it as a token" % (where, ", ".join(stray))
        shared = sorted(slot for slot, ids in named.items() if len(ids) > 1)
        if shared:
            return False, "%s: keyslot %s is named by more than one token (%s): what releases it cannot be judged. BLOCKING FOR " \
                "PRODUCTION (#135)" % (where, ", ".join(shared), ", ".join("token " + i for i in named[shared[0]]))
        # The peer-assisted shape (#67): every TPM-held share needs a peer's contribution, and a peer gives it
        # only to an image its manifest accepts now. unlock.judge_tokens refuses it if ANY systemd-tpm2 token
        # sits beside the paths, NV-backed or not: a keyslot the local TPM opens by itself bypasses the peers.
        peer_shape = any(t.get("type") == PEER_TOKEN for t in meta["tokens"].values())
        if peer_shape:
            # The unlock client opens ONE volume per boot, the root one, and a peer keeps its contribution
            # per node, not per volume (unlock.py, v1). Peer paths on any other volume open at no boot.
            if "/" not in paths:
                return False, "%s carries %s tokens, but it is not the root volume: the unlock client opens the root volume " \
                    "only, so nothing can open this one through its peer paths. BLOCKING FOR PRODUCTION (#135)" % (where, PEER_TOKEN)
            ok, why = peer_paths(meta, where, unlock_record, binding)
            if not ok:
                return False, "%s. BLOCKING FOR PRODUCTION (#135)" % why
            by_peer.append("%s: %s" % (name, why))
        for token_id, token in sorted(meta["tokens"].items()):
            if not token.get("keyslots"):
                continue                       # a token that names no keyslot releases nothing
            kind = token.get("type")
            if peer_shape and kind == PEER_TOKEN:
                continue                       # judged above, with its local share
            if kind == "systemd-recovery":
                recovery += 1                  # the recovery key: root_disk_recovery_keyslot judges the root volume's
                continue
            if kind != "systemd-tpm2":
                return False, "%s: token %s of type %r names keyslot %s. This check knows what releases a systemd-tpm2 " \
                    "keyslot and the recovery key's, and nothing else: an unknown token may be a TPM-sealed key that no " \
                    "update retires. BLOCKING FOR PRODUCTION (#135)" % (where, token_id, kind, ", ".join(token["keyslots"]))
            if nv_backed(token):
                nv += 1
                continue
            how = "PCRs %s" % (token.get("tpm2-pcrs") or "none")
            if token.get("tpm2_pubkey") or token.get("tpm2_pubkey_pcrs"):
                how += ", and a signed policy on PCRs %s (every image its key ever signed)" % (token.get("tpm2_pubkey_pcrs") or "?")
            fixed.append(how)
        if fixed:
            return False, NOT_REVOCABLE % (name, dev, "; ".join(fixed))
        if recovery > 1:
            return False, "%s has %d systemd-recovery tokens: one volume has one recovery key (a second is a second secret " \
                "that opens it). BLOCKING FOR PRODUCTION (#135)" % (where, recovery)
        any_nv = any_nv or bool(nv)
        if not nv and not peer_shape:
            return False, "%s has no systemd-tpm2 token that names a keyslot: nothing to judge (root_disk_tpm_unlocked says " \
                "what is missing on the root volume; a volume opened by a key file cannot be judged here). BLOCKING FOR " \
                "PRODUCTION (#135)" % where
    said = []
    if any_nv:
        pcrs, why = pcrlock_pcrs(host)
        if pcrs is None:
            return False, "the TPM tokens are NV-backed, but %s: nothing shows what their policy binds. BLOCKING FOR PRODUCTION (#135)" % why
        if 7 not in pcrs or not pcrs & IMAGE_PCRS:
            return False, "the TPM tokens are NV-backed, but %s binds PCRs %s (with measured values): it must bind PCR 7 and a PCR " \
                "that tells boot images apart (11, or 4). systemd-pcrlock leaves out a PCR it cannot predict, a PCR nothing was " \
                "measured into is all zeros for every image, and a policy without the image is satisfied by every old one. " \
                "BLOCKING FOR PRODUCTION (#135)" % (PCRLOCK_POLICY, sorted(pcrs))
        said.append("NV-backed (tpm2_pcrlock) tokens, and %s covers PCRs %s. NOT measured: that the NV index holds this policy"
                    % (PCRLOCK_POLICY, ", ".join(str(n) for n in sorted(pcrs))))
    if by_peer:
        said.append("peer-assisted unlock (%s). NOT measured: that the peers refuse a retired image (they judge by the "
                    "manifest and measurements they hold)" % "; ".join(by_peer))
    return True, "%s: every token that names a keyslot is the recovery key or needs more than a fixed TPM policy: %s; nor that a " \
        "retired image is refused on this host" % (", ".join(volumes), "; ".join(said))


def recovery_keyslots(meta):
    """Judge one LUKS2 header (the JSON of cryptsetup luksDump --dump-json-metadata) for the recovery
    keyslot. Pure: it is given metadata, which holds no key, and returns (ok, why)."""
    keyslots = set(meta.get("keyslots") or {})
    tokens = [t for t in (meta.get("tokens") or {}).values() if isinstance(t, dict)]
    named = {}
    for token in tokens:
        for slot in token.get("keyslots") or []:
            named.setdefault(str(slot), []).append(token.get("type"))
    # A recovery token that names no keyslot is not a recovery key: cryptsetup unassigns a token when
    # its keyslot is destroyed and leaves the empty token behind. It opens nothing, so it is not
    # counted (recovery-key.sh --status reports it, and --enrol / --replace remove it).
    recovery = [t for t in tokens if t.get("type") == "systemd-recovery" and t.get("keyslots")]
    if not recovery:
        return False, "no recovery keyslot (no systemd-recovery token): enrol the host's recovery key with " \
            "deploy/baremetal/recovery-key.sh --enrol"
    if len(recovery) != 1 or len(recovery[0].get("keyslots") or []) != 1:
        return False, "%d systemd-recovery tokens naming %s keyslots: one host has ONE recovery key in one keyslot " \
            "(a second is a second secret to keep, and an old one that still opens the disk)" % (
                len(recovery), [len(t.get("keyslots") or []) for t in recovery])
    slot = str(recovery[0]["keyslots"][0])
    if slot not in keyslots:
        return False, "the systemd-recovery token names keyslot %s, which does not exist" % slot
    # A keyslot whose priority is "ignore" (0) is skipped whenever no keyslot is named, which is how a
    # boot prompt tries a passphrase: the key would pass --check by keyslot and fail at the console.
    if (meta.get("keyslots") or {}).get(slot, {}).get("priority") == 0:
        return False, "recovery keyslot %s has priority 'ignore': a boot prompt would not try it " \
            "(cryptsetup config --priority normal --key-slot %s)" % (slot, slot)
    # Its OWN keyslot: one that the TPM token (or any other) also names would be opened by that
    # credential too, and wiping either would take the other with it.
    if len(named[slot]) != 1:
        return False, "keyslot %s is named by %s: the recovery key must have a keyslot of its own" % (
            slot, " and ".join(sorted(str(t) for t in named[slot])))
    # A keyslot that no token names is a plain passphrase: the installer's, typically. Left in place it
    # is the weakest way into the disk, beside a TPM policy and a 256-bit recovery key.
    stray = sorted(keyslots - set(named), key=lambda s: (len(s), s))
    if stray:
        return False, "keyslot %s is named by no token (a leftover passphrase?): once the TPM and the recovery " \
            "key are proven, wipe it with systemd-cryptenroll --wipe-slot=password" % ", ".join(stray)
    return True, "recovery keyslot %s (systemd-recovery token), separate from %s" % (
        slot, ", ".join(sorted("%s in keyslot %s" % (kinds[0], s) for s, kinds in named.items() if s != slot)) or "nothing else")


def recovery_keyslot(host):
    crypts, why = root_crypt_devices(host)
    if crypts is None:
        return False, why
    found = []
    for name in crypts:
        dev, meta = luks_header(host, name)
        if dev is None:
            return False, meta
        ok, why = recovery_keyslots(meta)
        if not ok:
            return False, "%s (%s): %s" % (name, dev, why)
        found.append("%s (%s): %s" % (name, dev, why))
    return True, "; ".join(found)


def ima(host):
    policy = host.read("/sys/kernel/security/ima/policy")
    if policy is None:
        return False, "no IMA policy readable (securityfs, or IMA disabled)"
    exec_rules = []
    for line in policy.splitlines():
        f = line.split()
        if not f or f[0] != "measure":
            continue
        opts = dict(o.split("=", 1) for o in f[1:] if "=" in o)
        # BPRM_CHECK measures executables only with no mask or MAY_EXEC; MMAP_CHECK only with MAY_EXEC.
        executable = (opts.get("func") == "BPRM_CHECK" and opts.get("mask", "MAY_EXEC").lstrip("^") == "MAY_EXEC") \
            or (opts.get("func") == "MMAP_CHECK" and opts.get("mask", "").lstrip("^") == "MAY_EXEC")
        if executable and opts.get("pcr", "10") == "10":
            # PCR 10: the PCR that attestation quotes (README, section 3); a rule extending another PCR
            # would leave the quoted one silent about the binary.
            exec_rules.append("%s, PCR 10" % opts["func"])
    if not exec_rules:
        return False, "the IMA policy has no executable-measurement rule into PCR 10 (measure func=BPRM_CHECK)"
    # ascii_runtime_measurements: PCR, template hash, template (ima-ng / ima-sig / ima-ngv2), file
    # digest "[ima:]alg:hex", path. IMA appends a new entry when changed bytes are executed, so the
    # NEWEST entry for the path is the one that must match the file as it is now.
    newest = None
    for line in (host.read(IMA_LOG) or "").splitlines():
        f = line.split()
        if len(f) >= 5 and f[0] == "10" and f[2] in ("ima-ng", "ima-sig", "ima-ngv2", "ima-sigv2") and f[4] == KMS_BINARY:
            newest = f[3].split(":")
    if not newest:
        return False, "the IMA policy measures executables (%s) but %s is not in the measurement log: " \
            "start regalia-kms, then re-run" % (exec_rules[0], KMS_BINARY)
    alg, logged = newest[-2], newest[-1]
    current = host.read_bytes(KMS_BINARY)
    if current is None or alg not in hashlib.algorithms_available:
        return False, "cannot hash %s (%s) to compare with its IMA entry" % (KMS_BINARY, alg)
    now = hashlib.new(alg, current).hexdigest()
    if now != logged:
        return False, "the newest IMA entry for %s (%s:%s…) is not the binary there now (%s…): it was " \
            "replaced after it last ran; restart regalia-kms, then re-run" % (KMS_BINARY, alg, logged[:12], now[:12])
    return True, "executables measured (%s); the running %s is in the IMA log (%s:%s…)" % (
        exec_rules[0], KMS_BINARY, alg, now[:12])


def lockout_policy(host):
    if not host.which("tpm2_getcap"):
        return False, "tpm2_getcap is not installed"
    rc, out = host.run(["tpm2_getcap", "properties-variable"])
    if rc != 0:
        return False, "cannot read the TPM's variable properties (tpm2_getcap properties-variable)"
    found = {}
    for line in out.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep and value.strip():
            try:
                found[key] = int(value.strip(), 0)
            except ValueError:
                pass
    names = ("lockoutAuthSet", "inLockout", "TPM2_PT_LOCKOUT_COUNTER") + tuple(LOCKOUT_POLICY)
    missing = [n for n in names if n not in found]
    if missing:
        return False, "tpm2_getcap did not report %s" % ", ".join(missing)
    drift = ["%s is %d, not %d" % (n, found[n], want) for n, want in LOCKOUT_POLICY.items() if found[n] != want]
    if drift:
        return False, "the TPM's dictionary-attack settings are not the commissioned ones: %s (deploy/baremetal/tpm-lockout.sh --set)" % "; ".join(drift)
    if found["lockoutAuthSet"] != 1:
        return False, "the TPM's lockout hierarchy has no authorization value: anyone on this host can change the " \
            "dictionary-attack settings or clear the counter (deploy/baremetal/tpm-lockout.sh --set)"
    if found["inLockout"] != 0:
        return False, "the TPM is in dictionary-attack lockout (%d failed tries of %d): it releases no PIN until a try " \
            "heals or the counter is cleared" % (found["TPM2_PT_LOCKOUT_COUNTER"], found["TPM2_PT_MAX_AUTH_FAIL"])
    return True, "lockout after %d failed tries, one forgiven every %d s, lockout-hierarchy recovery %d s; lockout " \
        "authorization set; %d failed tries counted now" % (
            found["TPM2_PT_MAX_AUTH_FAIL"], found["TPM2_PT_LOCKOUT_INTERVAL"], found["TPM2_PT_LOCKOUT_RECOVERY"],
            found["TPM2_PT_LOCKOUT_COUNTER"])


def import_key(host, expected=None):
    if not host.which("tpm2_readpublic"):
        return False, "tpm2_readpublic is not installed"
    rc, yaml = host.run(["tpm2_readpublic", "-c", IMPORT_HANDLE])
    if rc != 0:
        return False, "no key at %s: run seal-hsm-pin.sh --init-import-key" % IMPORT_HANDLE
    attrs = set((re.search(r"^attributes:\s*\n\s+value:\s*(\S+)", yaml, re.M) or [None, ""])[1].split("|")) - {""}
    kind = (re.search(r"^type:\s*\n\s+value:\s*(\S+)", yaml, re.M) or [None, "?"])[1]
    bits = (re.search(r"^bits:\s*(\d+)", yaml, re.M) or [None, "?"])[1]
    if kind != "rsa" or bits != "3072" or attrs != IMPORT_KEY_ATTRS:
        return False, "the key at %s is not the import key's template (%s-%s, %s)" % (IMPORT_HANDLE, kind, bits, "|".join(sorted(attrs)))
    rc, pem = host.run(["tpm2_readpublic", "-Q", "-c", IMPORT_HANDLE, "-f", "pem", "-o", "/dev/stdout"])
    body = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    try:
        fp = hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest() if rc == 0 and body else None
    except ValueError:
        fp = None
    if not fp:
        return False, "cannot export the public key at %s" % IMPORT_HANDLE
    want = re.sub(r"[\s:]", "", (expected or "")).lower()
    if not re.fullmatch(r"[0-9a-f]{16,64}", want):
        return False, "no recorded fingerprint to compare (pass --import-key-sha256, at least 16 hex): " \
            "the key at %s has sha256 %s" % (IMPORT_HANDLE, fp)
    if not fp.startswith(want):
        return False, "the key at %s (sha256 %s) is NOT the recorded import key (%s)" % (IMPORT_HANDLE, fp, want)
    return True, "the recorded import key is at %s (sha256 %s)" % (IMPORT_HANDLE, fp)


def der_item(data, at):
    """One DER TLV at offset `at`: (tag, content, offset after it). ValueError on anything malformed."""
    if at + 2 > len(data):
        raise ValueError("truncated DER")
    tag, length, at = data[at], data[at + 1], at + 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4 or at + n > len(data):
            raise ValueError("bad DER length")
        length, at = int.from_bytes(data[at:at + n], "big"), at + n
    if at + length > len(data):
        raise ValueError("truncated DER")
    return tag, data[at:at + length], at + length


def rsa_pkfp(pem):
    """systemd's "pkfp" for an RSA public key in PEM (SubjectPublicKeyInfo): the SHA-256 of the PKCS#1
    RSAPublicKey DER inside it. This is the fingerprint seal-hsm-pin.sh prints and every PCR signature
    file carries. ValueError if it is not such a key."""
    text = pem.decode("ascii", "strict") if isinstance(pem, bytes) else pem
    body = re.fullmatch(r"\s*-----BEGIN PUBLIC KEY-----\s(.*?)-----END PUBLIC KEY-----\s*", text, re.S)
    if not body:
        raise ValueError("not a PEM public key")
    spki = base64.b64decode("".join(body.group(1).split()), validate=True)
    tag, seq, end = der_item(spki, 0)
    if tag != 0x30 or end != len(spki):
        raise ValueError("not a SubjectPublicKeyInfo")
    tag, algorithm, at = der_item(seq, 0)
    if seq[:at] != RSA_ALGORITHM:
        raise ValueError("not an RSA key")
    tag, bits, end = der_item(seq, at)
    if tag != 0x03 or end != len(seq) or bits[:1] != b"\x00":
        raise ValueError("not a SubjectPublicKeyInfo")
    return hashlib.sha256(bits[1:]).hexdigest()


def pcr_list(mask):
    return [i for i in range(64) if mask >> i & 1]


def _sealed_binding(raw, signed):
    """The binding in a systemd encrypted credential's header (the bytes after base64): (PCRs bound
    directly, PCRs bound through a signed policy, the signing key's pkfp or ""). `signed` says whether the
    key type carries a signed-policy header. ValueError with the reason.

    Layout (little-endian; measured on systemd 257): id[16], key size, block size, IV size, tag size
    (u32 each), the IV; then, aligned to 8: PCR mask u64, PCR bank u16, primary algorithm u16, blob
    size u32, policy hash size u32, the blob and the policy hash; then, for a signed policy, aligned
    to 8: PCR mask u64, key size u32, the PCR-signing public key as the PEM it was given."""
    try:
        tag_size = struct.unpack_from("<I", raw, 28)[0]
        at = (32 + struct.unpack_from("<I", raw, 24)[0] + 7) & ~7
        mask, bank, _alg, blob, policy = struct.unpack_from("<QHHII", raw, at)
        at = (at + 20 + blob + policy + 7) & ~7
        signed_mask, key = 0, b""
        if signed:
            signed_mask, size = struct.unpack_from("<QI", raw, at)
            key = raw[at + 12:at + 12 + size]
            if len(key) != size:
                raise ValueError("truncated")
            at = (at + 12 + size + 7) & ~7
    except struct.error:
        raise ValueError("truncated")
    # After the headers: the encrypted metadata (timestamp, not-after, name size: 20 bytes), the
    # secret, and the authentication tag. Less than that cannot be a whole credential; whether what
    # is there authenticates is for systemd to say (pin_credentials opens each blob).
    if len(raw) - at < 20 + tag_size:
        raise ValueError("truncated")
    # The PCRs named are PCRs of ONE bank. A blob bound to the SHA-1 bank's PCR 7 is not the recorded
    # binding, whatever its mask says: tpm_sha256_bank measures the bank the record means.
    if bank != TPM2_ALG_SHA256:
        raise ValueError("bound to PCR bank 0x%04x, not SHA-256 (0x000b)" % bank)
    if not signed:
        return pcr_list(mask), [], ""
    try:
        return pcr_list(mask), pcr_list(signed_mask), rsa_pkfp(key)
    except ValueError as error:
        raise ValueError("its PCR-signing key is unreadable (%s)" % error)


def _credential_bytes(text):
    try:
        raw = base64.b64decode("".join((text or "").split()), validate=True)
    except (ValueError, AttributeError):
        raise ValueError("not base64")
    if len(raw) < 32:
        raise ValueError("too short to be an encrypted credential")
    return raw


def credential_header(text):
    """What a PIN credential is sealed to, read from its header: (PCRs bound directly, PCRs bound through
    a signed policy, the signing key's pkfp or ""). ValueError, with the reason, for anything that is not
    sealed to the host key and the TPM together."""
    raw = _credential_bytes(text)
    kind = raw[:16].hex()
    if kind in CRED_REFUSED:
        raise ValueError("sealed with %s" % CRED_REFUSED[kind])
    if kind not in (CRED_HOST_TPM2, CRED_HOST_TPM2_PK):
        raise ValueError("an unknown credential type (id %s)" % kind)
    return _sealed_binding(raw, kind == CRED_HOST_TPM2_PK)


# The local share of a peer-assisted disk unlock (deploy/baremetal/unlock.py, #67) is the ONE credential
# sealed to the TPM alone: the host key is on the disk it helps to open. It opens nothing by itself (the
# keyslot needs the peer's contribution as well), which is why what credential_header refuses for a PIN
# is required here. This function is for that share and nothing else.
LOCAL_SHARE_TPM2, LOCAL_SHARE_TPM2_PK = "0c7cc07b117645919c4b0bea08bc20fe", "faf7eb9341e3412ca1a436f95a29362f"


def local_share_binding(text):
    """What a peer path's local share is sealed to: (PCRs bound directly, signed PCRs, pkfp or "").
    ValueError unless it is a credential sealed to the TPM alone."""
    raw = _credential_bytes(text)
    kind = raw[:16].hex()
    if kind not in (LOCAL_SHARE_TPM2, LOCAL_SHARE_TPM2_PK):
        raise ValueError("not sealed to the TPM alone (credential type id %s): it could not open before the root disk does" % kind)
    return _sealed_binding(raw, kind == LOCAL_SHARE_TPM2_PK)


def binding_text(direct, signed, pkfp):
    out = "PCRs %s" % ("+".join(map(str, direct)) or "none")
    return out + (", signed PCRs %s by key pkfp %s" % ("+".join(map(str, signed)), pkfp) if signed or pkfp else ", no signed policy")


def host_key_protected(host):
    """The other half of every PIN credential: systemd's host key. It must be root's alone and on a
    filesystem with a dm-crypt device beneath it. On a clear disk it is one more file an old image can
    read, and the credential is then worth no more than the TPM half alone."""
    # %f is the raw st_mode in hex: 8100 is a regular file (0100000) with mode 0400. Not %F, the file
    # type in words, which coreutils translates to the operator's language.
    rc, out = host.run(["stat", "-c", "%f|%u", HOST_KEY])
    if rc != 0:
        return False, "the host key %s cannot be read (stat): seal-hsm-pin.sh creates it" % HOST_KEY
    if out.strip() != "8100|0":
        return False, "the host key %s must be a regular file, root's, mode 0400 (stat says mode 0x%s, owner %s)" % (
            (HOST_KEY,) + tuple((out.strip().split("|") + ["?", "?"])[:2]))
    rc, out = host.run(["findmnt", "-n", "-o", "SOURCE", "-T", HOST_KEY])
    src = re.sub(r"\[.*\]$", "", out.strip())
    if rc != 0 or not src:
        return False, "cannot find the filesystem holding the host key %s" % HOST_KEY
    rc, out = host.run(["lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", src])
    crypts = [f[0] for f in (line.split() for line in out.splitlines()) if len(f) == 2 and f[1] == "crypt"]
    if rc != 0 or not crypts:
        return False, "the host key %s is on %s, which is not on dm-crypt: an image that boots without unlocking " \
            "the root disk can read it, and the PIN is then guarded by the TPM alone" % (HOST_KEY, src)
    return True, "the host key is root's, 0400, on %s" % ", ".join(crypts)


def pin_credentials(host, expected=None):
    """expected: (direct PCRs, signed PCRs, pkfp) as evidence.credential_binding returns it, or None."""
    names = sorted(n for n in host.listdir(CREDSTORE) if PIN_CREDENTIAL.fullmatch(n))
    if not names:
        return False, "no PIN credential (regalia-kms-<id>.pin) in %s: run seal-hsm-pin.sh" % CREDSTORE
    found = {}
    for name in names:
        try:
            found[name] = credential_header(host.read("%s/%s" % (CREDSTORE, name)))
        except ValueError as error:
            return False, "%s/%s is %s" % (CREDSTORE, name, error)
    if expected is None:
        return False, "no recorded binding to compare (pass --credential-pcrs, and --credential-signed-pcrs with " \
            "--credential-pcr-key-pkfp for a signed policy): " + "; ".join(
                "%s is sealed to %s" % (n, binding_text(*b)) for n, b in found.items())
    expected = (list(expected[0]), list(expected[1]), expected[2])
    wrong = ["%s is sealed to %s" % (n, binding_text(*b)) for n, b in found.items() if tuple(b) != expected]
    if wrong:
        return False, "%s; the record says %s" % ("; ".join(wrong), binding_text(*expected))
    # The header says what a blob is bound to, not that the blob is whole or that this boot can open it.
    # systemd says that: it authenticates and decrypts each one, as the service start will, under the
    # name the unit loads it by (<id>.pin; a blob named otherwise dies with 243/CREDENTIALS). The
    # secret goes to /dev/null and never enters this process.
    for name in names:
        rc, _ = host.run(["systemd-creds", "decrypt", "--name=" + name[len("regalia-kms-"):],
                          "%s/%s" % (CREDSTORE, name), "/dev/null"])
        if rc != 0:
            return False, "%s/%s is sealed as recorded but does NOT open on this boot (systemd-creds decrypt): it is cut or " \
                "altered, sealed by another TPM or under another name, or this boot's PCRs or PCR signature do " \
                "not satisfy its policy. regalia-kms cannot load it" % (CREDSTORE, name)
    ok, detail = host_key_protected(host)
    if not ok:
        return False, detail
    return True, "%d PIN credential(s) open on this boot, sealed to the host key and the TPM under %s, as recorded (%s); %s" % (
        len(names), binding_text(*expected), ", ".join(names), detail)


def hsm_ports(host):
    """The sysfs USB paths of every Nitrokey HSM 2 on the bus."""
    base = "/sys/bus/usb/devices"
    return sorted(d for d in host.listdir(base)
                  if ((host.read("%s/%s/idVendor" % (base, d)) or "").strip(),
                      (host.read("%s/%s/idProduct" % (base, d)) or "").strip()) == NITROKEY_HSM)


def hsm_token(host):
    ports = hsm_ports(host)
    if not ports:
        return False, "no Nitrokey HSM (USB %s:%s) on the bus" % NITROKEY_HSM
    return True, "Nitrokey HSM attached at USB %s" % ", ".join(ports)


def token_clients_root_only(host):
    loose = []
    # Every copy, not only the first on PATH: a root-only wrapper must not hide a runnable one.
    for path in (p for tool in os_probe.TOKEN_CLIENTS for p in host.which_all(tool)):
        st = host.stat(path)
        if st is None:
            loose.append("%s (cannot stat)" % path)
        elif st[0] != 0 or st[1] != 0 or st[2] & 0o077:
            # no group or other bit at all: a writable root-owned client is code root runs later
            loose.append("%s (uid %d, gid %d, mode %o)" % (path, st[0], st[1], st[2] & 0o7777))
    if loose:
        return False, "token client tools others can run or change: %s (chown root:root, chmod 0700)" % ", ".join(loose)
    ok, why = os_probe.pcscd_clients(host)
    return ok, ("token client tools root-only; %s" % why if ok else why)


def firewall(host):
    rc, out = host.run(["nft", "-j", "list", "table", "inet", "regalia_kms"])
    if rc != 0:
        return False, "the table inet regalia_kms is not loaded (nft -f the firewall.py output)"
    try:
        items = json.loads(out).get("nftables", [])
        chains = {c["chain"].get("hook"): c["chain"] for c in items if "chain" in c}
        flags = [t["table"].get("flags") for t in items if "table" in t]
    except (ValueError, AttributeError):
        return False, "cannot parse nft -j output"
    # A dormant table still lists its chains, but they are detached from the hooks and filter nothing.
    if any(f and "dormant" in (f if isinstance(f, list) else [f]) for f in flags):
        return False, "inet regalia_kms is loaded but DORMANT: its chains filter nothing (nft add table inet regalia_kms '{ flags ; }')"
    bad = [h for h in ("input", "output", "forward") if (chains.get(h) or {}).get("policy") != "drop"]
    if bad:
        return False, "inet regalia_kms is loaded, but %s %s not on policy drop" % (", ".join(bad), "is" if len(bad) == 1 else "are")
    return True, "inet regalia_kms loaded; input, output and forward default to drop"


PROBES = dict(os_probe.PROBES, uefi_boot=uefi_boot, secure_boot_enabled=secure_boot,
              tpm2_present=tpm2, tpm_sha256_bank=sha256_bank, tpm_lockout_policy=lockout_policy, root_disk_tpm_unlocked=root_unlock,
              root_disk_unlock_revocable=unlock_revocable, root_disk_recovery_keyslot=recovery_keyslot, ima_policy_loaded=ima,
              pin_import_key_present=import_key, pin_credentials_sealed_as_recorded=pin_credentials,
              hsm_token_attached=hsm_token, token_clients_root_only=token_clients_root_only, firewall_default_deny=firewall)


def measure(host, import_key_sha256=None, credential_binding=None, unlock_record=None):
    def run(name):
        if name == "pin_import_key_present":
            return import_key(host, import_key_sha256)
        if name == "pin_credentials_sealed_as_recorded":
            return pin_credentials(host, credential_binding)
        if name in ("root_disk_tpm_unlocked", "root_disk_unlock_revocable"):
            return PROBES[name](host, unlock_record, credential_binding)
        return PROBES[name](host)

    def judged(name):
        try:
            return run(name)
        except Exception as error:      # noqa: BLE001  a probe that cannot run has not measured its control
            return False, "the probe raised %s: %s (not measured: counted as failing)" % (type(error).__name__, error)
    return {name: dict(zip(("value", "why"), judged(name))) for name in MEASURED}


def compare(measured, host, ports=()):
    """Every measured control the evidence records must agree with the host, both ways; and the token
    must be on the USB port the evidence pins (the INTERNAL one)."""
    out = ["evidence records %s=%s, the host measures %s: %s" % (n, host.get(n), measured[n]["value"], measured[n]["why"])
           for n in MEASURED if host.get(n) is not measured[n]["value"]]
    if host.get("hsm_usb_path") not in ports:
        out.append("evidence pins the Nitrokey HSM to USB %s, the host has it at %s" % (
            host.get("hsm_usb_path"), ", ".join(ports) or "no port"))
    return out


def main(argv=None, host=None, run=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", help="the signed commissioning evidence (deploy/baremetal/evidence.py)")
    ap.add_argument("--signature", help="its detached signature (openssl dgst -sha256 -sign)")
    ap.add_argument("--evidence-key", help="the commissioning evidence public key (P-256 PEM)")
    ap.add_argument("--evidence-key-sha256", help="that key's recorded SHA-256 (DER), from the commissioning record")
    ap.add_argument("--import-key-sha256", help="without evidence: the import key fingerprint written down at "
                    "--init-import-key (at least 16 hex)")
    ap.add_argument("--credential-pcrs", help="without evidence: the PCRs the PIN credentials are bound to directly, "
                    "as given to seal-hsm-pin.sh --pcrs (e.g. 7)")
    ap.add_argument("--credential-signed-pcrs", default="", help="without evidence: 11 if the PINs were sealed with "
                    "--tpm2-public-key-pcrs 11")
    ap.add_argument("--credential-pcr-key-pkfp", default="", help="without evidence: the PCR-signing key's pkfp, "
                    "from seal-hsm-pin.sh's record")
    ap.add_argument("--node-id", help="without evidence: this host's node ID in the membership manifest, needed to judge "
                    "a root disk enrolled for peer-assisted unlock (deploy/baremetal/unlock.py); with evidence it comes "
                    "from host.node_id, and an argument must agree with it")
    ap.add_argument("--unlock-peer", action="append", default=[], metavar="NODE_ID",
                    help="a peer that holds an unlock path for this host; repeat for each. With --node-id")
    args = ap.parse_args(argv)
    host = host or Host()
    report = {"attested_not_measured": list(UNMEASURED)}
    problems, want, binding = [], args.import_key_sha256, None
    if args.unlock_peer and not args.node_id:
        ap.error("--unlock-peer needs --node-id")
    unlock_record = None
    if args.node_id:
        try:
            unlock_record = evidence_mod.unlock_record(args.node_id, list(args.unlock_peer), label="--")
        except evidence_mod.InvalidEvidence as error:
            ap.error(str(error))
    if args.credential_pcrs is not None and not args.evidence:
        try:
            binding = evidence_mod.credential_binding(args.credential_pcrs, args.credential_signed_pcrs,
                                                      args.credential_pcr_key_pkfp, label="--")
        except evidence_mod.InvalidEvidence as error:
            ap.error(str(error))
    if args.evidence:
        if not (args.signature and args.evidence_key and args.evidence_key_sha256):
            ap.error("--evidence needs --signature, --evidence-key and --evidence-key-sha256")
        try:
            # One snapshot of all three inputs: the bytes validated are the bytes verified.
            with evidence_mod.Snapshot(evidence=args.evidence, signature=args.signature, key=args.evidence_key) as snap:
                ev_host = evidence_mod.validate(evidence_mod.load(snap.data["evidence"]), MEASURED)
                evidence_mod.verify_signature(snap.paths["evidence"], snap.paths["signature"], snap.paths["key"],
                                              args.evidence_key_sha256, **({"run": run} if run else {}))
            want = ev_host["pin_import_key_sha256"]
            binding = evidence_mod.credential_binding(ev_host["credential_tpm2_pcrs"], ev_host["credential_tpm2_signed_pcrs"],
                                                      ev_host["credential_tpm2_pcr_key_pkfp"])
            # The root disk is judged against the SIGNED record of which node this is and who its peers are
            # (the signature was verified just above). Arguments may repeat it; they never replace it. When
            # the evidence is refused, the disk is judged against the arguments, and the run still fails on
            # "evidence REFUSED": the disk controls in the report may pass while the run does not.
            recorded = evidence_mod.unlock_record(ev_host["node_id"], ev_host["unlock_peers"])
            if unlock_record is not None and (unlock_record[0], sorted(unlock_record[1])) != (recorded[0], sorted(recorded[1])):
                problems.append("the arguments say node %s with unlock peers %s, the evidence node %s with %s: they disagree, "
                                "and the root disk is judged against the evidence" % (
                                    unlock_record[0], ", ".join(unlock_record[1]) or "none", recorded[0], ", ".join(recorded[1]) or "none"))
            unlock_record = recorded
        except (OSError, evidence_mod.InvalidEvidence) as error:
            problems.append("evidence REFUSED: %s" % error)
            ev_host = None
    measured = measure(host, want, binding, unlock_record)
    report["measured"] = measured
    if args.evidence:
        if ev_host is not None:
            problems += compare(measured, ev_host, hsm_ports(host))
        report["evidence_problems"] = problems
    print(json.dumps(report, indent=2))
    # Evidence never lowers the bar: every measured control must be true, AND, when given, the evidence
    # must be well-formed, signed by the recorded key, attest every firmware setting, and agree.
    ok = all(v["value"] for v in measured.values()) and not problems
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
