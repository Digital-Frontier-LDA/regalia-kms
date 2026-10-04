#!/usr/bin/env python3
"""The firmware's boot entries, for a rolling image update's trial boot (#75, Phase 15).

The hosts boot the signed UKI straight from the firmware (no boot loader: nothing between the firmware and
systemd-stub is measured into PCR 4 but the image, as every recorded measurement set assumes). So the trial
boot of a new image is the firmware's own one-shot, as UEFI defines it:

  * the new image is installed as its OWN Boot#### entry, beside the current one, on the same ESP;
  * BootNext names it: the firmware boots it ONCE, deleting BootNext as it does, and every later boot
    (a reset at the recovery prompt, a panic with `panic=` set, a power cut) follows BootOrder, which
    still starts with the current image. That is the fallback: nothing has to work on the new image for
    the old one to come back, and the old image is still approved (CURRENT and NEXT both are);
  * only once the host is seen up on the new image does BootOrder put it first (promote).

What resets a trial boot that HANGS (at the recovery prompt, waiting for peers that refuse it) is not the
firmware: the operator does, through the iLO's power reset, after the deadline `rollout apply` prints. A
hardware watchdog would do it unattended, but none is armed across the reboot here: that is a rehearsal
item for the DL360s (#65), not something this module claims.

state(run)            the entries, BootCurrent, BootNext and BootOrder, as efibootmgr reports them, parsed
                      strictly (anything it cannot read is a refusal, never a guess)
trial(entry, esp, accepted, run)
                      THE way a trial boot is set: the entry's image is read from the booted ESP and must
                      measure the accepted set (NEXT) before BootNext := entry is written, then read back;
                      nothing writes BootNext otherwise
promote(entry, run)   BootOrder := entry first, the rest in their order, then read back
remove(entry, run)    delete an entry that is not the one booted, nor first in BootOrder, nor BootNext
image(esp, entry)     the file an entry boots, on the ESP this host booted from: the entry's GPT partition
                      must be BootCurrent's, and `esp` must BE that partition (a vfat mount whose device is
                      /dev/disk/by-partuuid/<GUID>, the partition systemd-stub names in LoaderDevicePartUUID);
                      every component opened relative to its directory, never through a link
measures(data, set)   whether that image measures into PCR 11, in each phase, what an accepted set says

Every efibootmgr call is `run` (subprocess.run or a fake), by absolute path, with a clean environment.
"""
import os
import re
import stat
import subprocess

from deploy.baremetal import attest, membership, uki

Refused, require = membership.Refused, membership.require

EFIBOOTMGR = "/usr/bin/efibootmgr"
ENTRY = re.compile(r"[0-9A-F]{4}")
# \EFI\<dir>\<name>.efi as the firmware stores it (case-insensitive FAT), with nothing that climbs
LOADER = re.compile(r"\\EFI(\\[A-Za-z0-9][A-Za-z0-9._-]{0,63})+\.EFI", re.IGNORECASE)
GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
LINE = re.compile(r"Boot([0-9A-F]{4})(\*?) ([^\t]*)\t?(.*)")
# the file node as efivar formats it: File(\EFI\…) (efibootmgr 17) or the bare path (efibootmgr 18, efivar 38)
DEVICE = re.compile(r"HD\([0-9]+,GPT,(" + GUID + r"),[^)]*\)/(?:File\(([^)\s]*)\)|(\\[^\s]*))")


def _efibootmgr(run, *argv):
    done = run([EFIBOOTMGR, "-v", *argv], capture_output=True, text=True, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
    require(done.returncode == 0, "efibootmgr %s failed (exit %s): %s" % (" ".join(argv) or "-v", done.returncode,
                                                                          (done.stderr or "").strip()[:300]))
    return done.stdout


def parse(text):
    """efibootmgr -v's report as {"current", "next" (None if unset), "order": [...], "entries": {id: {"label",
    "active", "partition" (GPT partition GUID, lower case, or None), "path" (or None)}}}."""
    require(isinstance(text, str), "efibootmgr printed nothing")
    found, seen = {"current": None, "next": None, "order": None, "entries": {}}, set()
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line[:1].isspace():           # efibootmgr 18's -v continuation lines (dp: …, data: …): the hex of what is above
            continue
        header = next((k for k, name in (("current", "BootCurrent: "), ("next", "BootNext: "), ("order", "BootOrder: "))
                       if line.startswith(name)), None)
        if header is not None:
            require(header not in seen, "efibootmgr reports %s twice" % line.split(":")[0])
            seen.add(header)
            value = line.split(": ", 1)[1].strip()
            found[header] = (value.split(",") if value else []) if header == "order" else value
        elif re.match(r"Boot[0-9A-F]{4}", line):
            match = LINE.fullmatch(line)
            require(match is not None, "an efibootmgr entry line cannot be read: %r" % line[:120])
            number, star, label, rest = match.groups()
            require(number not in found["entries"], "efibootmgr lists Boot%s twice" % number)
            device = DEVICE.search(rest)
            found["entries"][number] = {"label": label.strip(), "active": star == "*",
                                        "partition": device.group(1).lower() if device else None,
                                        "path": (device.group(2) or device.group(3)) if device else None}
    require(found["current"] is not None and ENTRY.fullmatch(found["current"]), "efibootmgr reports no BootCurrent: was this host "
            "booted by UEFI firmware?")
    require(found["current"] in found["entries"], "BootCurrent %s is not among the entries" % found["current"])
    require(found["order"] is not None and all(ENTRY.fullmatch(e) for e in found["order"]), "efibootmgr reports no readable BootOrder")
    require(found["next"] is None or (ENTRY.fullmatch(found["next"]) and found["next"] in found["entries"]),
            "BootNext %s is not among the entries" % found["next"])
    return found


def state(run=subprocess.run):
    return parse(_efibootmgr(run))


def _entry(value):
    require(isinstance(value, str) and ENTRY.fullmatch(value), "a boot entry is four upper-case hex digits (e.g. 0003), not %r" % (value,))
    return value


def trial(entry, esp, accepted, run=subprocess.run, **where):
    """Set the trial boot of Boot`entry`: its image, read from the ESP this host booted from (image), must
    measure `accepted` (NEXT's set, measures) BEFORE BootNext is written. The only caller of _set_next, so no
    image is ever tried unchecked. Returns {"state": after, "measured": {phase: PCR 11}}."""
    entry = _entry(entry)
    measured_now = measures(image(esp, entry, state(run), **where), accepted)
    return {"state": _set_next(entry, run), "measured": measured_now}


def _set_next(entry, run=subprocess.run):
    """BootNext := `entry` (an active entry other than the one booted), then read back. Returns the state."""
    entry, before = _entry(entry), state(run)
    require(entry in before["entries"], "there is no Boot%s" % entry)
    require(before["entries"][entry]["active"], "Boot%s is not active: the firmware would skip it" % entry)
    require(entry != before["current"], "Boot%s is the entry this host booted: a trial boot is of another image" % entry)
    _efibootmgr(run, "--bootnext", entry)
    after = state(run)
    require(after["next"] == entry, "BootNext reads %s after setting it to %s: nothing is rebooted on that" % (after["next"], entry))
    return after


def promote(entry, run=subprocess.run):
    """BootOrder := `entry` first, the others in their order. Only the entry this host booted: a host
    promotes the image it is running, never one it has not come up on. Returns the state."""
    entry, before = _entry(entry), state(run)
    require(entry == before["current"], "Boot%s is not the entry this host booted (Boot%s): only the running image is promoted"
            % (entry, before["current"]))
    order = [entry] + [e for e in before["order"] if e != entry]
    if order != before["order"]:
        _efibootmgr(run, "--bootorder", ",".join(order))
    after = state(run)
    require(after["order"][:1] == [entry], "BootOrder reads %s after putting %s first" % (",".join(after["order"]), entry))
    return after


def remove(entry, run=subprocess.run):
    """Delete Boot`entry`: the retired image's, after the retire. Never the one booted, the first in
    BootOrder or BootNext. Returns the state."""
    entry, before = _entry(entry), state(run)
    require(entry in before["entries"], "there is no Boot%s" % entry)
    require(entry != before["current"], "Boot%s is the entry this host booted" % entry)
    require(before["order"][:1] != [entry], "Boot%s is first in BootOrder: promote the running image first" % entry)
    require(before["next"] != entry, "Boot%s is BootNext" % entry)
    _efibootmgr(run, "--bootnum", entry, "--delete-bootnum")
    after = state(run)
    require(entry not in after["entries"], "Boot%s is still listed after deleting it" % entry)
    return after


MOUNTINFO = "/proc/self/mountinfo"
EFIVARS = "/sys/firmware/efi/efivars"
LOADER_VENDOR = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"         # systemd's loader vendor GUID (LoaderDevicePartUUID)


def _mount(path, mountinfo=MOUNTINFO):
    """(device number, filesystem type) of the mount AT `path` (it must be a mount point), from mountinfo."""
    target = os.path.realpath(path)
    with open(mountinfo, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read(4 << 20).splitlines()
    found = None
    for line in lines:
        before, sep, after = line.partition(" - ")
        fields = before.split()
        if sep and len(fields) >= 5 and fields[4].replace("\\040", " ") == target:
            major, minor = (int(x) for x in fields[2].split(":"))
            # the last mount at the point is the visible one; field 4 is the root of the mount within its file
            # system: a subdirectory of the ESP bound here would resolve \EFI\… one level down
            found = (os.makedev(major, minor), after.split()[0], fields[3])
    require(found is not None, "%s is not a mount point: the ESP must be mounted there" % path)
    require(found[2] == "/", "%s mounts %s of its file system, not the whole ESP: \\EFI\\… would not resolve as the firmware "
            "resolves it" % (path, found[2]))
    return found[:2]


def _partition_device(guid, by_partuuid="/dev/disk/by-partuuid"):
    return os.stat(os.path.join(by_partuuid, guid.lower())).st_rdev


def _loader_partition(efivars=EFIVARS):
    """LoaderDevicePartUUID, which systemd-stub sets to the GPT partition it was loaded from (lower case), or
    None if the variable is absent."""
    try:
        with open(os.path.join(efivars, "LoaderDevicePartUUID-" + LOADER_VENDOR), "rb") as f:
            raw = f.read(4096)
    except FileNotFoundError:
        return None
    text = raw[4:].decode("utf-16-le", "replace").rstrip("\0").strip()       # 4 bytes of attributes, then UTF-16
    require(re.fullmatch(GUID, text) is not None, "LoaderDevicePartUUID is not a GUID: %r" % text[:60])
    return text.lower()


def image(esp, entry, boot, mount=_mount, partition_device=_partition_device, loader_partition=_loader_partition):
    """The bytes of the image Boot`entry` loads, from the ESP mounted at `esp`, given `boot` (state()). The
    entry must name a file on the GPT partition BootCurrent's entry is on, and `esp` must BE that partition:
    a vfat mount whose device is that partition's, the one systemd-stub says it was loaded from. Only then is
    the file read here the one the firmware will load (another disk's ESP, mounted where this one usually is,
    would not be)."""
    entry = _entry(entry)
    require(entry in boot["entries"], "there is no Boot%s" % entry)
    this, here = boot["entries"][entry], boot["entries"][boot["current"]]
    require(this["path"] is not None and LOADER.fullmatch(this["path"]), "Boot%s does not load a file \\EFI\\…\\*.efi on a GPT "
            "partition (it loads %r)" % (entry, this["path"]))
    require(here["partition"] is not None, "BootCurrent %s names no GPT partition: the ESP cannot be told apart" % boot["current"])
    require(this["partition"] == here["partition"], "Boot%s is on partition %s, not on the ESP this host booted from (%s)"
            % (entry, this["partition"], here["partition"]))
    require(isinstance(esp, str) and os.path.isabs(esp), "the ESP mount point must be an absolute path")
    device, fstype = mount(esp)
    require(fstype == "vfat", "%s is a %s file system, not the ESP's vfat" % (esp, fstype))
    require(device == partition_device(here["partition"]), "%s is not the partition this host booted from (%s): another ESP is "
            "mounted there, and its files are not the ones the firmware loads" % (esp, here["partition"]))
    stub = loader_partition()
    require(stub is not None, "LoaderDevicePartUUID is not set: this host was not booted through systemd-stub, so the ESP "
            "it booted from cannot be confirmed")
    require(stub == here["partition"], "systemd-stub says this host booted from partition %s, but BootCurrent's entry is on %s"
            % (stub, here["partition"]))
    # every component opened relative to the directory before it, none through a link; FAT is case-insensitive
    # and the firmware's path may differ in case from the directory listing
    parts = this["path"].split("\\")[1:]
    fd = os.open(esp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for k, part in enumerate(parts):
            names = {n.lower(): n for n in os.listdir(fd)}
            require(part.lower() in names, "%s has no %s (Boot%s loads %s)" % (esp, part, entry, this["path"]))
            last = k == len(parts) - 1
            nfd = os.open(names[part.lower()], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (0 if last else os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = nfd
        require(stat.S_ISREG(os.fstat(fd).st_mode), "Boot%s's %s is not a regular file" % (entry, this["path"]))
        data = bytearray()
        while len(data) <= uki.MAX_IMAGE:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    require(len(data) <= uki.MAX_IMAGE, "Boot%s's image is larger than %d bytes" % (entry, uki.MAX_IMAGE))
    return bytes(data)


def measured(data):
    """{phase: PCR 11 hex} an image will measure: systemd-stub's sections, then systemd's boot phases."""
    parts = uki.measured(data)
    return {phase: uki.pcr11(parts, uki.PHASE_PATHS[phase]) for phase in attest.PHASES}


def measures(data, accepted):
    """Refuses unless the image measures, in each boot phase, the PCR 11 the accepted set records (a UKI
    host's set has per-phase values: measurements.py)."""
    require(isinstance(accepted, dict) and isinstance(accepted.get("phases"), dict),
            "the set %r has no per-phase PCR 11: it is not a UKI host's set" % (accepted.get("label") if isinstance(accepted, dict) else None))
    got = measured(data)
    for phase in attest.PHASES:
        want = accepted["phases"].get(phase, {}).get("11")
        require(want == got[phase], "the image measures PCR 11 %s in its %s phase; %s records %s: it is not that image"
                % (got[phase], phase, accepted.get("label"), want))
    return got
