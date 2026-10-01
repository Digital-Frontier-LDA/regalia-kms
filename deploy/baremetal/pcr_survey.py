#!/usr/bin/env python3
"""Survey a KMS host's PCRs across boots and classify them (#65, PoC 5.2 and 5.3), so the PCR policy the
disk, the PIN and the WG-BOOT key are sealed to is chosen from real DL360 evidence, not assumed.

    sudo python3 deploy/baremetal/pcr_survey.py snapshot --label same      --out survey/   # once per boot
    sudo python3 deploy/baremetal/pcr_survey.py snapshot --label kernel    --out survey/   # after changing only the kernel
    python3 deploy/baremetal/pcr_survey.py classify survey/                                # the table

Labels say what changed since the PREVIOUS boot: `same` (nothing; a plain reboot), `kernel`,
`initramfs`, `cmdline`, `bootloader`, `firmware`, `secureboot` (keys or state). The first snapshot
must be `same` (the baseline). `classify` then reports, per SHA-256 PCR:
  stable        identical across every `same` reboot (a candidate for direct binding)
  volatile      differs across plain reboots (never bind it)
  moved by X    changed when only X changed (what a policy over that PCR protects, and what an update
                of X would strand)
and refuses a survey whose labels it cannot interpret (two changes between snapshots, or none
recorded).

Each snapshot records the boot ID, the kernel release and command line, Secure Boot state, the system
firmware version (DMI), the sha256 of the running kernel image, the initramfs and the bootloader
configuration, and the sha256 of the TPM event log. Nothing secret is read.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import sys

PCR_DIR = "/sys/class/tpm/tpm0/pcr-sha256"
EVENT_LOG = "/sys/kernel/security/tpm0/binary_bios_measurements"
SECURE_BOOT = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
LABELS = ("same", "kernel", "initramfs", "cmdline", "bootloader", "firmware", "secureboot")
BOOT_FILES = {"kernel": ("/boot/vmlinuz-%s",), "initramfs": ("/boot/initrd.img-%s",),
              "bootloader": ("/boot/grub/grub.cfg", "/boot/efi/EFI/debian/grub.cfg")}


def _read(path, binary=False):
    try:
        with open(path, "rb" if binary else "r") as f:
            return f.read()
    except OSError:
        return None


def _sha(path):
    data = _read(path, binary=True)
    return hashlib.sha256(data).hexdigest() if data is not None else None


def snapshot(label, root="/"):
    def p(path):
        return os.path.join(root, path.lstrip("/"))
    pcrs = {}
    for n in range(24):
        v = _read(p("%s/%d" % (PCR_DIR, n)))
        if v is not None:
            pcrs[str(n)] = v.strip().lower()
    if not pcrs:
        raise SystemExit("no SHA-256 PCRs readable at %s: is this a TPM 2.0 host with the SHA-256 bank?" % PCR_DIR)
    release = platform.release() if root == "/" else (_read(p("/proc/sys/kernel/osrelease")) or "").strip()
    sb = _read(p(SECURE_BOOT), binary=True)
    files = {}
    for name, candidates in BOOT_FILES.items():
        for c in candidates:
            h = _sha(p(c % release if "%s" in c else c))
            if h:
                files[name] = h
                break
    return {
        "schema": "regalia.pcr-survey/v1", "label": label,
        "taken_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "boot_id": (_read(p("/proc/sys/kernel/random/boot_id")) or "").strip(),
        "kernel_release": release, "cmdline": (_read(p("/proc/cmdline")) or "").strip(),
        "secure_boot": None if not sb else bool(sb[-1]),
        "firmware_version": (_read(p("/sys/class/dmi/id/bios_version")) or "").strip(),
        "boot_files_sha256": files, "event_log_sha256": _sha(p(EVENT_LOG)), "pcrs": pcrs,
    }


def classify(snaps):
    """snaps: ordered list of snapshots. Returns {pcr: classification} and refuses an uninterpretable survey."""
    if not snaps or snaps[0]["label"] != "same":
        raise ValueError("the first snapshot must be labelled 'same' (the baseline boot)")
    boots = [s["boot_id"] for s in snaps]
    if len(set(boots)) != len(boots):
        raise ValueError("two snapshots share a boot ID: take exactly one snapshot per boot")
    for s in snaps:
        if s["label"] not in LABELS:
            raise ValueError("unknown label %r" % s["label"])
    pcr_ids = sorted(set().union(*(s["pcrs"] for s in snaps)), key=int)
    result = {}
    for n in pcr_ids:
        volatile = any(snaps[i]["label"] == "same" and snaps[i]["pcrs"].get(n) != snaps[i - 1]["pcrs"].get(n)
                       for i in range(1, len(snaps)))
        moved = sorted({snaps[i]["label"] for i in range(1, len(snaps))
                        if snaps[i]["label"] != "same" and snaps[i]["pcrs"].get(n) != snaps[i - 1]["pcrs"].get(n)})
        same_boots = sum(1 for s in snaps[1:] if s["label"] == "same")
        result[n] = {"volatile": volatile, "moved_by": moved,
                     "class": "volatile" if volatile else ("stable" if same_boots else "unproven (no plain reboot yet)")}
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--label", required=True, choices=LABELS)
    s.add_argument("--out", required=True, help="the survey directory")
    c = sub.add_parser("classify")
    c.add_argument("dir")
    a = ap.parse_args(argv)
    if a.cmd == "snapshot":
        snap = snapshot(a.label)
        os.makedirs(a.out, exist_ok=True)
        n = len([f for f in os.listdir(a.out) if f.endswith(".json")])
        path = os.path.join(a.out, "%03d-%s.json" % (n, a.label))
        with open(path, "x", encoding="utf-8") as f:
            json.dump(snap, f, indent=1, sort_keys=True)
        print(path)
        return 0
    files = sorted(f for f in os.listdir(a.dir) if f.endswith(".json"))
    snaps = []
    for f in files:
        with open(os.path.join(a.dir, f), encoding="utf-8") as fh:
            snaps.append(json.load(fh))
    try:
        table = classify(snaps)
    except ValueError as error:
        print("REFUSED: %s" % error, file=sys.stderr)
        return 2
    print("PCR  class       moved by")
    for n, r in table.items():
        print("%-4s %-11s %s" % (n, r["class"], ", ".join(r["moved_by"]) or "-"))
    print("\n%d snapshots: %s" % (len(snaps), " ".join(s["label"] for s in snaps)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
